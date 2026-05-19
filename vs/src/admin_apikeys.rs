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
    Read,
    #[serde(rename = "readwrite")]
    ReadWrite,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiKeyRecord {
    pub owner: String,
    pub permission: Permission,
    pub status: KeyStatus,
    pub created: String,
    pub secret_hash: String,
    pub description: String,
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
}

impl Permission {
    pub fn can_read(&self) -> bool {
        matches!(self, Permission::Read | Permission::ReadWrite)
    }

    #[allow(dead_code)]
    pub fn can_write(&self) -> bool {
        matches!(self, Permission::ReadWrite)
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
        let keys_file = if path.exists() {
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
            Ok(contents) => match toml::from_str(&contents) {
                Ok(kf) => {
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

    /// Check the key given by ID is present and active, and then confirm that the passed
    /// secret matches the stored hash. If all that is good, return the permission associated with the key.
    /// If not, return None (ie, no permission).
    pub fn lookup_permission(&self, apikey: &ApiKey) -> Result<Option<Permission>, ServiceError> {
        let keys_file = self.keys_file.read().unwrap();
        if let Some(record) = keys_file.keys.get(&apikey.key_id_hex()) {
            if record.status == KeyStatus::Active {
                let secret_hash = sha256_hex(apikey.secret_bytes())
                    .map_err(|e| ServiceError::AdminKey(format!("failed to hash key: {e}")))?;
                if secret_hash == record.secret_hash {
                    Ok(Some(record.permission.clone()))
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
