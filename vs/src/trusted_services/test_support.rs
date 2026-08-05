//! Shared fixtures for trusted-service unit tests.

use std::fs;
use std::path::PathBuf;

use zpr::policy_types::parse_attribute_mapping;

use super::attribute_mapper::AttributeMapper;

/// Build a mapper covering single-valued, multi-valued, and tag attributes.
pub(super) fn test_mapper() -> AttributeMapper {
    AttributeMapper {
        mappings: [
            "color -> user.color",
            "roles -> user.role{}",
            "lazy -> #user.lazy",
        ]
        .iter()
        .map(|mapping| parse_attribute_mapping(mapping).unwrap())
        .collect(),
    }
}

/// Write a named JSON fixture into the system temporary directory.
pub(super) fn write_fixture(name: &str, contents: &str) -> PathBuf {
    let fp = std::env::temp_dir().join(name);
    fs::write(&fp, contents).unwrap();
    fp
}
