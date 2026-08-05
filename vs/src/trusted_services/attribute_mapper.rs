//! Mapping between trusted-service attribute names and ZPR attribute names.

use zpr::policy_types::AttrMapping;

/// Maps attributes returned by a trusted service into their ZPR representation.
#[derive(Debug)]
pub(super) struct AttributeMapper {
    // Linear scan. A trusted service returns a handful of attributes; index it
    // by service_attr_key if that ever stops being true.
    pub(super) mappings: Vec<AttrMapping>,
}

/// Describes how a mapped attribute value must be emitted.
pub(super) enum AttrHint {
    /// Attribute is declared as single valued.
    SingleValued,

    /// Attribute is declared as multi valued.
    MultiValued,

    /// Attribute is declared as a tag.
    Tag(String),
}

impl AttributeMapper {
    /// Map a trusted-service attribute name into its ZPR name and value behavior.
    pub(super) fn map_attribute(&self, ts_key: &str) -> Option<(String, AttrHint)> {
        // `AttrMapping::attr` already carries the decoded RHS spec, so `zpl_key`/`zpl_value`
        // handle the tag class translation ("#user.lazy" -> "user.zpr.tag" + "user.lazy").
        let attr = &self
            .mappings
            .iter()
            .find(|m| m.service_attr_key == ts_key)?
            .attr;

        let hint = if attr.is_tag() {
            AttrHint::Tag(attr.zpl_value())
        } else if attr.is_multi_valued() {
            AttrHint::MultiValued
        } else {
            AttrHint::SingleValued
        };
        Some((attr.zpl_key(), hint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusted_services::test_support::test_mapper;

    /// Every mapping form produces the expected ZPR key and value behavior.
    #[test]
    fn test_map_attribute_covers_every_spec_form() {
        let mapper = test_mapper();

        let (key, hint) = mapper.map_attribute("color").unwrap();
        assert_eq!(key, "user.color");
        assert!(matches!(hint, AttrHint::SingleValued));

        let (key, hint) = mapper.map_attribute("roles").unwrap();
        assert_eq!(key, "user.role");
        assert!(matches!(hint, AttrHint::MultiValued));

        let (key, hint) = mapper.map_attribute("lazy").unwrap();
        assert_eq!(key, "user.zpr.tag");
        assert!(matches!(hint, AttrHint::Tag(t) if t == "user.lazy"));

        assert!(mapper.map_attribute("not_in_the_mapping").is_none());
    }
}
