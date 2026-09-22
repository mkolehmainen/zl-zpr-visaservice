//! The file-backed data set a reference server serves.
//!
//! The on-disk format is **exactly the visa service `file` store's JSON**
//! (`zl-zpr-visaservice/vs/src/trusted_services/file_attribute_store.rs`):
//! identity attribute key -> identity value -> attribute name -> values —
//! so one fixture file drives both a `file` store and this server — plus two
//! server-only extensions:
//!
//! - an optional top-level `_schema` key holding the SCIM 2.0 attribute
//!   definitions `GET /schema` returns (derived from the data when absent);
//! - an attribute's values may be spelled as an object
//!   `{"values": [...], "expires_at": "<RFC 3339>"}` instead of a bare
//!   array, when the entry should carry an `expires_at` in the `/query`
//!   response. A bare array (the `file` store's native spelling) never
//!   emits one — the spec requires `expires_at` only when the entry
//!   carries it.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;

/// The reserved top-level key holding SCIM attribute definitions.
pub const SCHEMA_KEY: &str = "_schema";

/// Why a data file could not be loaded.
#[derive(Debug, Error)]
pub enum DataError {
    /// The file could not be read.
    #[error("failed to read data file: {0}")]
    Io(#[from] std::io::Error),
    /// The file is not JSON, or not the file-store shape.
    #[error("data file does not parse as file-store JSON: {0}")]
    Parse(#[from] serde_json::Error),
    /// The top level is not a JSON object keyed by identity key.
    #[error("data file must be a JSON object keyed by identity attribute key")]
    NotAnObject,
    /// `_schema` is present but is not an array of SCIM definitions.
    #[error("'_schema' must be an array of SCIM attribute definitions")]
    SchemaNotAnArray,
}

/// Two matched identities disagree on an attribute's values. The server
/// must not pick a winner (spec status table: `409`).
#[derive(Debug)]
pub struct Conflict {
    /// The service-side attribute name the records disagree on.
    pub name: String,
}

/// One stored attribute entry: the `file` store's bare value array, or the
/// extended object form carrying an `expires_at` to pass through.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum StoredEntry {
    /// The `file` store's native spelling: `["red"]`.
    Bare(Vec<String>),
    /// The extended spelling: `{"values": ["red"], "expires_at": "..."}`.
    WithExpiry {
        /// The attribute's values.
        values: Vec<String>,
        /// Emitted verbatim in the `/query` response when present. The
        /// server never clamps or validates it — expiry policy is the visa
        /// service's side of the contract.
        #[serde(default)]
        expires_at: Option<String>,
    },
}

impl StoredEntry {
    /// The attribute's values, whichever spelling stored them.
    pub fn values(&self) -> &[String] {
        match self {
            StoredEntry::Bare(values) => values,
            StoredEntry::WithExpiry { values, .. } => values,
        }
    }

    /// The entry's `expires_at`, if the extended spelling carries one.
    pub fn expires_at(&self) -> Option<&str> {
        match self {
            StoredEntry::Bare(_) => None,
            StoredEntry::WithExpiry { expires_at, .. } => expires_at.as_deref(),
        }
    }
}

/// One actor entry's attributes: service-side name -> stored entry.
type AttrMap = BTreeMap<String, StoredEntry>;

/// The loaded data set: the file-store map plus the optional `_schema`.
#[derive(Debug, Clone)]
pub struct AttrData {
    /// identity key -> identity value -> attribute name -> entry.
    entries: BTreeMap<String, BTreeMap<String, AttrMap>>,
    /// SCIM definitions from `_schema`, verbatim, when present.
    schema: Option<serde_json::Value>,
}

impl AttrData {
    /// Load and decode a data file from disk.
    pub fn load(path: &Path) -> Result<Self, DataError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_json_str(&contents)
    }

    /// Decode a data set from its JSON text.
    pub fn from_json_str(contents: &str) -> Result<Self, DataError> {
        // Stub (zipline#80 step 1): parses nothing, serves nothing. The
        // contract tests define the behavior; step 2 implements it.
        let _ = contents;
        Ok(AttrData {
            entries: BTreeMap::new(),
            schema: None,
        })
    }

    /// Look up every identity pair and return the UNION of the matched
    /// entries' attributes, keyed by service-side name. Two matched entries
    /// disagreeing on an attribute's values is a [Conflict] — the same
    /// fail-closed rule as the visa service `file` store, moved to the side
    /// that can see the records. An unknown identity matches nothing and is
    /// not an error.
    pub fn lookup(&self, identities: &BTreeMap<String, String>) -> Result<AttrMap, Conflict> {
        let _ = identities;
        Ok(BTreeMap::new())
    }

    /// The `GET /schema` response body: `identityKeys` from the data's
    /// top-level identity keys, and the SCIM definitions from `_schema` —
    /// or, when absent, definitions derived from the data (`string`,
    /// `multiValued` when any entry has more than one value), sorted by
    /// name.
    pub fn schema_response(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
}
