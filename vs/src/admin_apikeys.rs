use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

use crate::apikey::{ApiKey, sha256_hex};
use crate::error::ServiceError;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Revoked,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Resolve,
    Read,
    #[serde(rename = "readwrite")]
    ReadWrite,
    /// Change-notification only (zipline#79): may POST
    /// /admin/services/{id}/changed for the one service the key is bound to
    /// (ApiKeyRecord::service), and nothing else.
    Notify,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiKeyRecord {
    pub owner: String,
    pub permission: Permission,
    pub status: KeyStatus,
    pub created: String,
    pub secret_hash: String,
    pub description: String,
    /// The trusted-service id a notify key is bound to (zipline#79).
    /// REQUIRED when `permission` is `notify` — the load rejects an unbound
    /// notify key — and ignored for every other level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeysFile {
    pub keys: HashMap<String, ApiKeyRecord>,
}

pub struct ReloadableApiKeys {
    keys_file_path: std::path::PathBuf,
    keys_file: RwLock<KeysFile>,
}

impl KeysFile {
    pub fn empty() -> Self {
        KeysFile {
            keys: HashMap::new(),
        }
    }

    /// Structural validation beyond what serde enforces (zipline#79): a
    /// notify key must carry the service binding it is scoped to. Applied on
    /// every load and reload, so an unbound notify key never becomes live.
    fn validate(&self) -> Result<(), ServiceError> {
        for (id, record) in &self.keys {
            if record.permission == Permission::Notify && record.service.is_none() {
                return Err(ServiceError::AdminKey(format!(
                    "key {id}: a notify key requires a service binding (`service = \"<id>\"`)"
                )));
            }
        }
        Ok(())
    }
}

impl Permission {
    /// GET /admin/services and GET /admin/services/{name}: any active key
    /// except notify (which reaches only the notification endpoint).
    pub fn can_resolve(&self) -> bool {
        !matches!(self, Permission::Notify)
    }

    /// Every other GET. Resolve and notify keys are excluded on purpose.
    pub fn can_read(&self) -> bool {
        matches!(self, Permission::Read | Permission::ReadWrite)
    }

    pub fn can_write(&self) -> bool {
        matches!(self, Permission::ReadWrite)
    }

    /// POST /admin/services/{id}/changed (zipline#79): the dedicated notify
    /// level and readwrite. A notify key is additionally bound to one service
    /// id (ApiKeyRecord::service); that check lives at the endpoint, where
    /// the requested id is known.
    pub fn can_notify(&self) -> bool {
        matches!(self, Permission::Notify | Permission::ReadWrite)
    }
}

impl ReloadableApiKeys {
    /// Create a new ReloadableApiKeys by loading from the given file path.
    /// If allow_missing is true, then if the file does not exist, an empty
    /// keys file will be used instead (but it will not be created on disk
    /// until you save or add a key). If allow_missing is false, then the file
    /// must exist and be valid or an error will be returned.
    pub fn new_from_file(
        path: std::path::PathBuf,
        allow_missing: bool,
    ) -> Result<Self, ServiceError> {
        let keys_file: KeysFile = if path.exists() {
            match toml::from_str(&std::fs::read_to_string(&path)?) {
                Ok(kf) => kf,
                Err(e) => {
                    return Err(ServiceError::AdminKey(format!(
                        "failed to parse keys file: {e}"
                    )));
                }
            }
        } else if allow_missing {
            KeysFile::empty()
        } else {
            return Err(ServiceError::AdminKey(format!(
                "keys file not found: {}",
                path.display()
            )));
        };
        keys_file.validate()?;
        Ok(ReloadableApiKeys {
            keys_file_path: path,
            keys_file: RwLock::new(keys_file),
        })
    }

    /// Reload the keys file from disk. If errors occur, they are returned and you will end up
    /// with no keys (i.e. all API access will be denied) until the file is fixed and this
    /// is called again.
    pub fn reload(&self) -> Result<(), ServiceError> {
        match std::fs::read_to_string(&self.keys_file_path) {
            Ok(contents) => match toml::from_str::<KeysFile>(&contents) {
                Ok(kf) => {
                    kf.validate()?;
                    let mut keys_file = self.keys_file.write().unwrap();
                    *keys_file = kf;
                    Ok(())
                }
                Err(e) => Err(ServiceError::AdminKey(format!(
                    "failed to parse keys file: {e}"
                ))),
            },
            Err(e) => Err(ServiceError::AdminKey(format!(
                "failed to read keys file: {e}"
            ))),
        }
    }

    /// Check the key given by ID is present and active, and then confirm that
    /// the passed secret matches the stored hash. If all that is good, return
    /// the permission associated with the key and its service binding
    /// (zipline#79: `Some(id)` for a notify key, `None` otherwise) so the
    /// notification endpoint can enforce that a notify key only names its
    /// bound service. If not, return None (ie, no permission).
    pub fn lookup_permission_and_service(
        &self,
        apikey: &ApiKey,
    ) -> Result<Option<(Permission, Option<String>)>, ServiceError> {
        let keys_file = self.keys_file.read().unwrap();
        if let Some(record) = keys_file.keys.get(&apikey.key_id_hex()) {
            if record.status == KeyStatus::Active {
                let secret_hash = sha256_hex(apikey.secret_bytes())
                    .map_err(|e| ServiceError::AdminKey(format!("failed to hash key: {e}")))?;
                if secret_hash == record.secret_hash {
                    Ok(Some((record.permission.clone(), record.service.clone())))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Get the number of active keys in the keys file.
    pub fn size_active(&self) -> usize {
        let keys_file = self.keys_file.read().unwrap();
        keys_file
            .keys
            .values()
            .filter(|record| record.status == KeyStatus::Active)
            .count()
    }

    /// Returns TRUE if there are no ACTIVE keys in the keys file.
    pub fn is_empty(&self) -> bool {
        return self.size_active() == 0;
    }

    /// The path from which keys are loaded.
    pub fn get_path(&self) -> &std::path::Path {
        &self.keys_file_path
    }

    /// Insert a key record directly. Only available in test builds.
    #[cfg(test)]
    pub fn insert_for_test(&self, id: String, record: ApiKeyRecord) {
        let mut keys_file = self.keys_file.write().unwrap();
        keys_file.keys.insert(id, record);
    }
}

impl Default for ReloadableApiKeys {
    fn default() -> Self {
        ReloadableApiKeys {
            keys_file_path: std::path::PathBuf::new(),
            keys_file: RwLock::new(KeysFile::empty()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A keys-file entry with permission = "resolve" deserializes to
    /// Permission::Resolve (zipline#36): the new least-privilege level
    /// round-trips through the vsapikey TOML format.
    #[test]
    fn test_keys_file_resolve_permission_parses() {
        let toml_src = r#"
            [keys.00000001]
            owner = "test"
            permission = "resolve"
            status = "active"
            created = "2026-09-15"
            secret_hash = "abc123"
            description = "resolve key"
        "#;
        let kf: KeysFile = toml::from_str(toml_src).unwrap();
        let record = &kf.keys["00000001"];
        assert_eq!(record.permission, Permission::Resolve);
        assert_eq!(record.status, KeyStatus::Active);
    }

    /// An existing-style entry with permission = "read" still parses
    /// unchanged: adding the Resolve variant is backward compatible.
    #[test]
    fn test_keys_file_read_permission_still_parses() {
        let toml_src = r#"
            [keys.00000002]
            owner = "test"
            permission = "read"
            status = "active"
            created = "2026-01-01"
            secret_hash = "def456"
            description = "read key"
        "#;
        let kf: KeysFile = toml::from_str(toml_src).unwrap();
        let record = &kf.keys["00000002"];
        assert_eq!(record.permission, Permission::Read);
        // No `service` key in the file: the optional binding is absent.
        assert_eq!(record.service, None);
    }

    /// A keys-file entry with permission = "notify" and a service binding
    /// deserializes to Permission::Notify with the binding attached
    /// (zipline#79): the change-notification key level round-trips through
    /// the vsapikey TOML format.
    #[test]
    fn test_keys_file_notify_permission_parses_with_service() {
        let toml_src = r#"
            [keys.00000003]
            owner = "hr-connector"
            permission = "notify"
            status = "active"
            created = "2026-09-22"
            secret_hash = "abc789"
            description = "notify key for hr"
            service = "hr"
        "#;
        let kf: KeysFile = toml::from_str(toml_src).unwrap();
        let record = &kf.keys["00000003"];
        assert_eq!(record.permission, Permission::Notify);
        assert_eq!(record.service, Some("hr".to_string()));
    }

    /// can_notify() gates POST /admin/services/{id}/changed: true for the
    /// dedicated notify level and for readwrite, false for the read-side
    /// levels (zipline#79).
    #[test]
    fn test_can_notify_true_for_notify_and_readwrite_only() {
        assert!(Permission::Notify.can_notify());
        assert!(Permission::ReadWrite.can_notify());
        assert!(!Permission::Read.can_notify());
        assert!(!Permission::Resolve.can_notify());
    }

    /// A notify key reaches ONLY the notification endpoint: every existing
    /// surface predicate returns false for it (zipline#79) — least privilege,
    /// same shape as the resolve level before it.
    #[test]
    fn test_existing_predicates_false_for_notify() {
        assert!(!Permission::Notify.can_resolve());
        assert!(!Permission::Notify.can_read());
        assert!(!Permission::Notify.can_write());
        // The other levels keep their resolve access unchanged.
        assert!(Permission::Resolve.can_resolve());
        assert!(Permission::Read.can_resolve());
        assert!(Permission::ReadWrite.can_resolve());
    }

    /// Loading a keys file that carries a notify key WITHOUT a service
    /// binding is rejected (zipline#79): an unbound notify key could post
    /// change notifications for any service, which defeats the level's
    /// purpose.
    #[test]
    fn test_load_rejects_notify_key_without_service() {
        let toml_src = r#"
            [keys.00000004]
            owner = "test"
            permission = "notify"
            status = "active"
            created = "2026-09-22"
            secret_hash = "abc123"
            description = "unbound notify key"
        "#;
        let path = std::env::temp_dir().join("vs-test-notify-unbound-keys.toml");
        std::fs::write(&path, toml_src).unwrap();
        let result = ReloadableApiKeys::new_from_file(path.clone(), false);
        std::fs::remove_file(&path).unwrap();
        let err = result.err().expect("load must reject unbound notify key");
        assert!(
            err.to_string().contains("notify"),
            "error should name the notify requirement, got: {err}"
        );
    }

    /// Reload applies the same validation as the initial load: a keys file
    /// edited to hold an unbound notify key is rejected on reload too.
    #[test]
    fn test_reload_rejects_notify_key_without_service() {
        let good = r#"
            [keys.00000005]
            owner = "test"
            permission = "notify"
            status = "active"
            created = "2026-09-22"
            secret_hash = "abc123"
            description = "bound notify key"
            service = "hr"
        "#;
        let bad = r#"
            [keys.00000005]
            owner = "test"
            permission = "notify"
            status = "active"
            created = "2026-09-22"
            secret_hash = "abc123"
            description = "unbound notify key"
        "#;
        let path = std::env::temp_dir().join("vs-test-notify-reload-keys.toml");
        std::fs::write(&path, good).unwrap();
        let keys = ReloadableApiKeys::new_from_file(path.clone(), false).unwrap();
        std::fs::write(&path, bad).unwrap();
        let result = keys.reload();
        std::fs::remove_file(&path).unwrap();
        assert!(result.is_err(), "reload must reject unbound notify key");
    }

    /// `service` on a non-notify key is ignored at load time (zipline#79):
    /// the field is meaningful only for notify keys, and its presence
    /// elsewhere must not break loading.
    #[test]
    fn test_service_field_on_read_key_is_ignored() {
        let toml_src = r#"
            [keys.00000006]
            owner = "test"
            permission = "read"
            status = "active"
            created = "2026-09-22"
            secret_hash = "abc123"
            description = "read key with stray service"
            service = "hr"
        "#;
        let path = std::env::temp_dir().join("vs-test-read-service-keys.toml");
        std::fs::write(&path, toml_src).unwrap();
        let result = ReloadableApiKeys::new_from_file(path.clone(), false);
        std::fs::remove_file(&path).unwrap();
        assert!(
            result.is_ok(),
            "stray service on a read key must not fail the load"
        );
    }
}
