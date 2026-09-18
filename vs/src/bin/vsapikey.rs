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
/// rejection message names all three accepted levels.
fn parse_permission(perms: &str) -> Result<Permission, String> {
    match perms {
        "resolve" => Ok(Permission::Resolve),
        "read" => Ok(Permission::Read),
        "readwrite" => Ok(Permission::ReadWrite),
        other => Err(format!(
            "invalid permission '{other}': must be resolve, read or readwrite"
        )),
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
) -> Result<(), String> {
    let permission = parse_permission(perms)?;

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

    /// The permission parser accepts all three levels, lowercase (zipline#36).
    #[test]
    fn test_parse_permission_accepts_all_three_levels() {
        assert_eq!(parse_permission("resolve").unwrap(), Permission::Resolve);
        assert_eq!(parse_permission("read").unwrap(), Permission::Read);
        assert_eq!(
            parse_permission("readwrite").unwrap(),
            Permission::ReadWrite
        );
    }

    /// The rejection message for an invalid value names all three levels
    /// (zipline#36), so users learn about `resolve` from the error itself.
    #[test]
    fn test_parse_permission_rejects_invalid_naming_all_levels() {
        let err = parse_permission("bogus").unwrap_err();
        assert_eq!(
            err,
            "invalid permission 'bogus': must be resolve, read or readwrite"
        );
    }
}
