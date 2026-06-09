use bytes::{Buf, Bytes};
use std::fmt;
use std::path::Path;
use tracing::info;
use zpr::policy::v1 as policy_capnp;

use crate::logging::targets::PIO;
use crate::policy::{Policy, PolicyError};

/// (Major, Minor, Patch)
#[derive(Debug)]
pub struct Version(pub u32, pub u32, pub u32);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// Returns the contained policy from the Cap'n Proto `PolicyContainer` struct.
///
/// `policy_container_bytes` - bytes of the Cap'n Proto `PolicyContainer` struct.
/// `min_version` - minimum compiler version accepted. Note that the container includes the compiler version used to create it.
pub fn load_policy_from_container(
    policy_container_bytes: &[u8],
    min_version: &Version,
) -> Result<Policy, PolicyError> {
    let container_reader = capnp::serialize::read_message(
        policy_container_bytes.reader(),
        capnp::message::ReaderOptions::new(),
    )?;

    let container = container_reader.get_root::<policy_capnp::policy_container::Reader>()?;

    // Version check: container compiler major version must be >= min_version.major

    let comp_version = Version(
        container.get_zplc_ver_major(),
        container.get_zplc_ver_minor(),
        container.get_zplc_ver_patch(),
    );

    check_version(&comp_version, &min_version)?;

    if !container.has_policy() {
        return Err(PolicyError::PolicyFileError(
            "policy container missing policy data".to_string(),
        ));
    }

    let policy_bytes = container.get_policy().unwrap();
    let p = Policy::new_from_policy_bytes(Bytes::copy_from_slice(policy_bytes))?;
    info!(target: PIO, "loaded policy created by compiler version {comp_version}");
    Ok(p)
}

/// Load policy from file. Checks the version of the compiler against the passed
/// minimum version.  This will not allow loading policies if the major version
/// is not the same as specified in the minimum version.
///
/// `fpath` - path to policy container (bin2) file.
pub fn load_policy(fpath: &Path, min_version: &Version) -> Result<Policy, PolicyError> {
    let encoded = std::fs::read(fpath)?;
    let encoded_container_bytes = Bytes::from(encoded);
    load_policy_from_container(&encoded_container_bytes, min_version)
}

/// Returns an error if the `found_version` is not compatible with the `min_version`.
fn check_version(found_version: &Version, min_version: &Version) -> Result<(), PolicyError> {
    if found_version.0 != min_version.0 {
        return Err(PolicyError::PolicyVersionError(format!(
            "policy file major version {found_version} is not compatible with the expected version {min_version}",
        )));
    }
    // Majors match, so check minor & patch.
    if found_version.1 < min_version.1 {
        return Err(PolicyError::PolicyVersionError(format!(
            "policy file minor version {found_version} is less than required minimum {min_version}",
        )));
    } else if found_version.1 == min_version.1 {
        if found_version.2 < min_version.2 {
            return Err(PolicyError::PolicyVersionError(format!(
                "policy file patch version {found_version} is less than required minimum {min_version}",
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_check_version() {
        let min = Version(5, 6, 7);

        let found_ok = vec![
            Version(5, 6, 7),
            Version(5, 6, 8),
            Version(5, 7, 0),
            Version(5, 8, 9),
        ];
        for v in found_ok {
            assert!(
                check_version(&v, &min).is_ok(),
                "version {} should be ok against min {}",
                v,
                min
            );
        }

        let found_nogood = vec![
            Version(4, 9, 9),
            Version(6, 0, 0),
            Version(5, 5, 9),
            Version(5, 6, 6),
        ];
        for v in found_nogood {
            assert!(
                check_version(&v, &min).is_err(),
                "version {} should NOT be ok against min {}",
                v,
                min
            );
        }
    }
}
