//! A simple command-line tool to manage API keys for the VS API.

use clap::{Parser, Subcommand};
use openssl::rand::rand_bytes;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use vs::admin_apikeys::{ApiKeyRecord, KeyStatus, KeysFile, Permission};
use vs::apikey::ApiKey;

const DEFAULT_KEYS_FILE: &str = "vs_keys.toml";

/// Read and deserialize a TOML keys file from disk.
fn read_keys_file(path: &Path) -> Result<KeysFile, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    toml::from_str(&content).map_err(|e| format!("failed to parse {}: {}", path.display(), e))
}

/// Serialize and write a keys file atomically (write to a temp file, then rename).
fn write_keys_file(path: &Path, kf: &KeysFile) -> Result<(), String> {
    let content =
        toml::to_string_pretty(kf).map_err(|e| format!("failed to serialize keys file: {e}"))?;
    let tmp_path = path.with_extension("toml.tmp");
    let mut tmp = fs::File::create(&tmp_path)
        .map_err(|e| format!("failed to create temp file {}: {}", tmp_path.display(), e))?;
    tmp.write_all(content.as_bytes())
        .map_err(|e| format!("failed to write temp file: {e}"))?;
    fs::rename(&tmp_path, path)
        .map_err(|e| format!("failed to rename temp file to {}: {}", path.display(), e))
}

/// Generate a random u32 key ID not already present in `keys`.
fn pick_new_id(keys: &HashMap<String, ApiKeyRecord>) -> Result<u32, String> {
    loop {
        let mut buf = [0u8; 4];
        rand_bytes(&mut buf).map_err(|e| format!("random id generation failed: {e}"))?;
        let id = u32::from_be_bytes(buf);
        if !keys.contains_key(&format!("{:08x}", id)) {
            return Ok(id);
        }
    }
}

/// Parse a permission level given on the command line. Lowercase only, and the
/// rejection message names all four accepted levels.
fn parse_permission(perms: &str) -> Result<Permission, String> {
    match perms {
        "resolve" => Ok(Permission::Resolve),
        "read" => Ok(Permission::Read),
        "readwrite" => Ok(Permission::ReadWrite),
        "notify" => Ok(Permission::Notify),
        other => Err(format!(
            "invalid permission '{other}': must be resolve, read, readwrite or notify"
        )),
    }
}

/// Enforce the --service/permission pairing (zipline#79): a notify key must
/// be bound to exactly one trusted-service id, and --service on any other
/// level is rejected as a probable mistake rather than silently ignored.
fn validate_service_binding(permission: &Permission, service: Option<&str>) -> Result<(), String> {
    match (permission, service) {
        (Permission::Notify, None) => {
            Err("a notify key must be bound to a service: pass --service <id>".to_string())
        }
        (Permission::Notify, Some(_)) => Ok(()),
        (_, Some(_)) => Err(
            "--service only applies to notify keys; remove it or use permission 'notify'"
                .to_string(),
        ),
        (_, None) => Ok(()),
    }
}

#[derive(Parser)]
#[command(name = "vsapikey", version = build_info::BUILD_VERSION, about = "Manage VS API keys")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new API key
    Create {
        /// Permission level: resolve, read or readwrite
        perms: String,
        /// Owner identifier
        owner: String,
        /// Path to the key file (default: vs_keys.toml)
        path: Option<PathBuf>,
        /// Initialize a new key file (error if file exists)
        #[arg(long)]
        init: bool,
        /// Description for the key
        #[arg(long)]
        desc: Option<String>,
        /// Status: active or revoked (default: active)
        #[arg(long)]
        status: Option<String>,
        /// Created date YYYY-MM-DD (default: today)
        #[arg(long)]
        created: Option<String>,
        /// Trusted-service id to bind a notify key to (required for notify,
        /// rejected otherwise)
        #[arg(long)]
        service: Option<String>,
    },
    /// Revoke an existing API key
    Revoke {
        /// Key ID (hex-encoded 32-bit value)
        keyid: String,
        /// Path to the key file (default: vs_keys.toml)
        path: Option<PathBuf>,
    },
}

fn cmd_create(
    perms: &str,
    owner: &str,
    path: &Path,
    init: bool,
    desc: Option<&str>,
    status: Option<&str>,
    created: Option<&str>,
    service: Option<&str>,
) -> Result<(), String> {
    let permission = parse_permission(perms)?;
    validate_service_binding(&permission, service)?;

    let key_status = match status.unwrap_or("active") {
        "active" => KeyStatus::Active,
        "revoked" => KeyStatus::Revoked,
        other => {
            return Err(format!(
                "invalid status '{other}': must be active or revoked"
            ));
        }
    };

    let created_date = match created {
        Some(d) => d.to_string(),
        None => chrono::Local::now().format("%Y-%m-%d").to_string(),
    };

    let mut kf = if init {
        if path.exists() {
            return Err(format!("key file already exists: {}", path.display()));
        }
        KeysFile::empty()
    } else {
        if !path.exists() {
            return Err(format!(
                "key file not found: {} (use --init to create a new file)",
                path.display()
            ));
        }
        read_keys_file(path)?
    };

    let key_id = pick_new_id(&kf.keys)?;
    let apikey =
        ApiKey::new_generate(key_id).map_err(|e| format!("failed to generate API key: {e}"))?;
    let secret_hash = apikey
        .secret_hash()
        .map_err(|e| format!("failed to compute secret hash: {e}"))?;

    let record = ApiKeyRecord {
        owner: owner.to_string(),
        permission,
        status: key_status,
        created: created_date,
        secret_hash,
        description: desc.unwrap_or("").to_string(),
        service: service.map(str::to_string),
    };

    kf.keys.insert(apikey.key_id_hex(), record);
    write_keys_file(path, &kf)?;

    println!("{}", apikey.to_key_string());
    Ok(())
}

fn cmd_revoke(keyid: &str, path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("key file not found: {}", path.display()));
    }
    let mut kf = read_keys_file(path)?;

    match kf.keys.get(keyid) {
        None => {
            eprintln!("key not found");
            std::process::exit(1);
        }
        Some(record) => {
            if matches!(record.status, KeyStatus::Revoked) {
                println!("already revoked");
                return Ok(());
            }
        }
    }

    if let Some(record) = kf.keys.get_mut(keyid) {
        record.status = KeyStatus::Revoked;
    }
    write_keys_file(path, &kf)
}

fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Create {
            perms,
            owner,
            path,
            init,
            desc,
            status,
            created,
            service,
        } => {
            let p = path
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_KEYS_FILE));
            cmd_create(
                perms,
                owner,
                &p,
                *init,
                desc.as_deref(),
                status.as_deref(),
                created.as_deref(),
                service.as_deref(),
            )
        }
        Commands::Revoke { keyid, path } => {
            let p = path
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_KEYS_FILE));
            cmd_revoke(keyid, &p)
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The permission parser accepts all four levels, lowercase
    /// (zipline#36, zipline#79).
    #[test]
    fn test_parse_permission_accepts_all_four_levels() {
        assert_eq!(parse_permission("resolve").unwrap(), Permission::Resolve);
        assert_eq!(parse_permission("read").unwrap(), Permission::Read);
        assert_eq!(
            parse_permission("readwrite").unwrap(),
            Permission::ReadWrite
        );
        assert_eq!(parse_permission("notify").unwrap(), Permission::Notify);
    }

    /// The rejection message for an invalid value names all four levels
    /// (zipline#36, zipline#79), so users learn about `resolve` and `notify`
    /// from the error itself.
    #[test]
    fn test_parse_permission_rejects_invalid_naming_all_levels() {
        let err = parse_permission("bogus").unwrap_err();
        assert_eq!(
            err,
            "invalid permission 'bogus': must be resolve, read, readwrite or notify"
        );
    }

    /// A notify key requires --service at mint time (zipline#79): the
    /// file-load side rejects an unbound notify key, and the CLI catches the
    /// mistake before writing anything.
    #[test]
    fn test_validate_service_binding_notify_requires_service() {
        let err = validate_service_binding(&Permission::Notify, None).unwrap_err();
        assert!(
            err.contains("--service"),
            "error should name the missing flag, got: {err}"
        );
        assert!(validate_service_binding(&Permission::Notify, Some("hr")).is_ok());
    }

    /// --service with a non-notify permission is rejected as an error rather
    /// than silently ignored (zipline#79 plan Q1): the load side ignores the
    /// field, but the CLI catching the mistake is cheap.
    #[test]
    fn test_validate_service_binding_rejected_for_non_notify() {
        for perm in [Permission::Resolve, Permission::Read, Permission::ReadWrite] {
            let err = validate_service_binding(&perm, Some("hr")).unwrap_err();
            assert!(
                err.contains("notify"),
                "error should say --service is notify-only, got: {err}"
            );
            assert!(validate_service_binding(&perm, None).is_ok());
        }
    }

    /// Minting a notify key writes the service binding into the record, and
    /// it round-trips through the TOML file (zipline#79).
    #[test]
    fn test_create_notify_key_round_trips_service() {
        let path = std::env::temp_dir().join("vsapikey-test-notify-roundtrip.toml");
        let _ = fs::remove_file(&path);
        cmd_create(
            "notify",
            "hr-connector",
            &path,
            true,
            Some("notify key for hr"),
            None,
            None,
            Some("hr"),
        )
        .unwrap();
        let kf = read_keys_file(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(kf.keys.len(), 1);
        let record = kf.keys.values().next().unwrap();
        assert_eq!(record.permission, Permission::Notify);
        assert_eq!(record.service, Some("hr".to_string()));
    }

    /// Minting a read key leaves the binding absent — no stray `service`
    /// key in the written TOML.
    #[test]
    fn test_create_read_key_has_no_service() {
        let path = std::env::temp_dir().join("vsapikey-test-read-noservice.toml");
        let _ = fs::remove_file(&path);
        cmd_create("read", "reader", &path, true, None, None, None, None).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let kf = read_keys_file(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(kf.keys.values().next().unwrap().service, None);
        assert!(
            !content.contains("service"),
            "read key TOML must not carry a service key:\n{content}"
        );
    }
}
