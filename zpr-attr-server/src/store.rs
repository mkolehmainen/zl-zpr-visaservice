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

use chrono::DateTime;
use serde::Deserialize;
use serde_json::{Value, json};
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
#[derive(Debug, Clone, PartialEq, Deserialize)]
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
pub type AttrMap = BTreeMap<String, StoredEntry>;

/// Whether `challenger` carries the strictly earlier — more conservative —
/// expiry than `held`, for merging entries that agree on values. `None`
/// when the two stamps differ but cannot both be parsed as RFC 3339, so no
/// conservative choice exists (the caller conflicts). A stated expiry is
/// always more conservative than an absent one: absent means the policy
/// default, which a stamp can only shorten (spec, `expires_at`).
fn earlier_expiry(held: &StoredEntry, challenger: &StoredEntry) -> Option<bool> {
    match (held.expires_at(), challenger.expires_at()) {
        (_, None) => Some(false),      // nothing stated: held is no less strict
        (None, Some(_)) => Some(true), // stated beats absent
        (Some(held_at), Some(challenger_at)) => {
            if held_at == challenger_at {
                return Some(false); // identical stamps: nothing to choose
            }
            let held_time = DateTime::parse_from_rfc3339(held_at).ok()?;
            let challenger_time = DateTime::parse_from_rfc3339(challenger_at).ok()?;
            Some(challenger_time < held_time)
        }
    }
}

/// The loaded data set: the file-store map plus the optional `_schema`.
#[derive(Debug, Clone)]
pub struct AttrData {
    /// identity key -> identity value -> attribute name -> entry.
    entries: BTreeMap<String, BTreeMap<String, AttrMap>>,
    /// SCIM definitions from `_schema`, verbatim, when present.
    schema: Option<Value>,
}

impl AttrData {
    /// Load and decode a data file from disk.
    pub fn load(path: &Path) -> Result<Self, DataError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_json_str(&contents)
    }

    /// Decode a data set from its JSON text: split off the reserved
    /// `_schema` key, then decode the rest as the file-store map.
    pub fn from_json_str(contents: &str) -> Result<Self, DataError> {
        let parsed: Value = serde_json::from_str(contents)?;
        let Value::Object(mut top) = parsed else {
            return Err(DataError::NotAnObject);
        };
        let schema = match top.remove(SCHEMA_KEY) {
            None => None,
            Some(defs @ Value::Array(_)) => Some(defs),
            Some(_) => return Err(DataError::SchemaNotAnArray),
        };
        let entries: BTreeMap<String, BTreeMap<String, AttrMap>> =
            serde_json::from_value(Value::Object(top))?;
        Ok(AttrData { entries, schema })
    }

    /// Look up every identity pair and return the UNION of the matched
    /// entries' attributes, keyed by service-side name. Two matched entries
    /// disagreeing on an attribute's values is a [Conflict] — the same
    /// fail-closed rule as the visa service `file` store, moved to the side
    /// that can see the records. An unknown identity matches nothing and is
    /// not an error. Entries agreeing on values but differing on
    /// `expires_at` merge conservatively: the earliest expiry survives, and
    /// a stated expiry beats an absent one (absent means the policy
    /// default, which a stamp can only shorten — spec, `expires_at`).
    /// Differing stamps that cannot both be parsed cannot be ordered, so
    /// they conflict rather than letting iteration order pick.
    pub fn lookup(&self, identities: &BTreeMap<String, String>) -> Result<AttrMap, Conflict> {
        let mut merged: AttrMap = BTreeMap::new();
        for (ident_key, ident_value) in identities {
            let Some(attributes) = self
                .entries
                .get(ident_key)
                .and_then(|by_value| by_value.get(ident_value))
            else {
                continue; // unknown identity: matches nothing, not an error
            };
            for (name, entry) in attributes {
                match merged.get(name) {
                    None => {
                        merged.insert(name.clone(), entry.clone());
                    }
                    Some(first) if first.values() != entry.values() => {
                        return Err(Conflict { name: name.clone() });
                    }
                    Some(first) => {
                        // Same name, same values: one answer, carrying the
                        // most conservative expiry of the two.
                        if earlier_expiry(first, entry)
                            .ok_or_else(|| Conflict { name: name.clone() })?
                        {
                            merged.insert(name.clone(), entry.clone());
                        }
                    }
                }
            }
        }
        Ok(merged)
    }

    /// The `GET /schema` response body: `identityKeys` from the data's
    /// top-level identity keys (sorted — a BTreeMap's order — and never the
    /// reserved `_schema` key), and the SCIM definitions from `_schema`
    /// verbatim — or, when absent, definitions derived from the data:
    /// every attribute name seen anywhere in the file, `type: string`,
    /// `multiValued: true` exactly when some entry holds more than one
    /// value, sorted by name.
    pub fn schema_response(&self) -> Value {
        let identity_keys: Vec<&String> = self.entries.keys().collect();
        let attributes = match &self.schema {
            Some(defs) => defs.clone(),
            None => self.derived_definitions(),
        };
        json!({
            "identityKeys": identity_keys,
            "attributes": attributes,
        })
    }

    /// Definitions derived from the data when the file has no `_schema`:
    /// name -> multiValued (true when any entry holds more than one value),
    /// every type `string`. BTreeMap keeps the list sorted by name.
    fn derived_definitions(&self) -> Value {
        let mut multi_by_name: BTreeMap<&str, bool> = BTreeMap::new();
        for by_value in self.entries.values() {
            for attrs in by_value.values() {
                for (name, entry) in attrs {
                    let multi = multi_by_name.entry(name).or_insert(false);
                    *multi = *multi || entry.values().len() > 1;
                }
            }
        }
        Value::Array(
            multi_by_name
                .into_iter()
                .map(
                    |(name, multi)| json!({ "name": name, "type": "string", "multiValued": multi }),
                )
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both entry spellings decode, and expires_at surfaces only from the
    /// object spelling.
    #[test]
    fn test_entry_spellings() {
        let data = AttrData::from_json_str(
            r#"{"user.sub": {"s": {
                "plain": ["x"],
                "stamped": {"values": ["y"], "expires_at": "2027-01-01T00:00:00Z"}
            }}}"#,
        )
        .unwrap();
        let matched = data
            .lookup(&[("user.sub".to_string(), "s".to_string())].into())
            .unwrap();
        assert_eq!(matched["plain"].values(), ["x".to_string()]);
        assert_eq!(matched["plain"].expires_at(), None);
        assert_eq!(
            matched["stamped"].expires_at(),
            Some("2027-01-01T00:00:00Z")
        );
    }

    /// A non-object top level and a non-array `_schema` are load errors.
    #[test]
    fn test_bad_shapes_rejected() {
        assert!(matches!(
            AttrData::from_json_str("[1, 2]"),
            Err(DataError::NotAnObject)
        ));
        assert!(matches!(
            AttrData::from_json_str(r#"{"_schema": {"not": "an array"}}"#),
            Err(DataError::SchemaNotAnArray)
        ));
        assert!(matches!(
            AttrData::from_json_str("not json"),
            Err(DataError::Parse(_))
        ));
    }

    /// Two matched identities agreeing on values but not on `expires_at`
    /// merge conservatively: the earliest expiry survives, regardless of
    /// which identity was iterated first, and a stated expiry beats an
    /// absent one (absent means the policy default, which a stamp can only
    /// shorten — ATTRIBUTE_SERVICE.md, `expires_at`).
    #[test]
    fn test_agreeing_values_keep_earliest_expiry() {
        // "a.key" iterates before "b.key" (sorted-key order). The earlier
        // `role` expiry and the only `team` expiry both sit under "b.key",
        // so a first-encountered-wins merge would discard them.
        let data = AttrData::from_json_str(
            r#"{
                "a.key": {"v": {
                    "role": {"values": ["x"], "expires_at": "2027-06-01T00:00:00Z"},
                    "team": ["t"]
                }},
                "b.key": {"v": {
                    "role": {"values": ["x"], "expires_at": "2027-01-01T00:00:00Z"},
                    "team": {"values": ["t"], "expires_at": "2027-03-01T00:00:00Z"}
                }}
            }"#,
        )
        .unwrap();
        let matched = data
            .lookup(
                &[
                    ("a.key".to_string(), "v".to_string()),
                    ("b.key".to_string(), "v".to_string()),
                ]
                .into(),
            )
            .unwrap();
        assert_eq!(matched["role"].expires_at(), Some("2027-01-01T00:00:00Z"));
        assert_eq!(matched["team"].expires_at(), Some("2027-03-01T00:00:00Z"));
    }

    /// The earliest-expiry rule orders instants, not strings: two spellings
    /// of the same instant agree, and the first is kept.
    #[test]
    fn test_agreeing_values_same_instant_different_spelling() {
        let data = AttrData::from_json_str(
            r#"{
                "a.key": {"v": {"role": {"values": ["x"], "expires_at": "2027-01-01T00:00:00Z"}}},
                "b.key": {"v": {"role": {"values": ["x"], "expires_at": "2027-01-01T01:00:00+01:00"}}}
            }"#,
        )
        .unwrap();
        let matched = data
            .lookup(
                &[
                    ("a.key".to_string(), "v".to_string()),
                    ("b.key".to_string(), "v".to_string()),
                ]
                .into(),
            )
            .unwrap();
        assert_eq!(matched["role"].expires_at(), Some("2027-01-01T00:00:00Z"));
    }

    /// Two DIFFERING `expires_at` stamps that cannot both be parsed cannot
    /// be ordered, so the merge cannot pick the conservative one: that is a
    /// conflict (fail closed), not a coin flip.
    #[test]
    fn test_agreeing_values_unorderable_expiry_is_conflict() {
        let data = AttrData::from_json_str(
            r#"{
                "a.key": {"v": {"role": {"values": ["x"], "expires_at": "not a timestamp"}}},
                "b.key": {"v": {"role": {"values": ["x"], "expires_at": "2027-01-01T00:00:00Z"}}}
            }"#,
        )
        .unwrap();
        let result = data.lookup(
            &[
                ("a.key".to_string(), "v".to_string()),
                ("b.key".to_string(), "v".to_string()),
            ]
            .into(),
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().name, "role");
    }
}
