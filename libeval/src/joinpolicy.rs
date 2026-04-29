//! Structs for managing the "join policy" records from ZPR policy.
//! Only as much as is needed for libeval to do its work.
use enumset::{EnumSet, EnumSetType};
use std::collections::HashMap;
use zpr::policy::v1;
use zpr::policy_types::{AttrExp, AttrOp};

use crate::attribute::Attribute;
use crate::policy::PolicyError;

/// JPolicy is a simplified join policy used for connection authentication.
#[derive(Debug)]
pub struct JPolicy {
    pub matches: Vec<AttrExp>,
    pub flags: EnumSet<JFlag>,
    pub services: Option<Vec<String>>, // only service ID
}

#[derive(Debug, EnumSetType)]
pub enum JFlag {
    IsNode,
    IsVs,
    IsVsDock,
}

// Extract a `JPolicy` from a Cap'n Proto `j_policy`.
impl TryFrom<v1::j_policy::Reader<'_>> for JPolicy {
    type Error = PolicyError;

    fn try_from(jp_rdr: v1::j_policy::Reader<'_>) -> Result<Self, Self::Error> {
        let mut matches: Vec<AttrExp> = Vec::new();
        if jp_rdr.has_match() {
            for attr_rdr in jp_rdr.get_match()?.iter() {
                let key = attr_rdr.get_key()?.to_string()?;
                let op = match attr_rdr.get_op()? {
                    v1::AttrOp::Eq => AttrOp::Eq,
                    v1::AttrOp::Ne => AttrOp::Ne,
                    v1::AttrOp::Has => AttrOp::Has,
                    v1::AttrOp::Excludes => AttrOp::Excludes,
                };
                let mut values: Vec<String> = Vec::new();
                for val in attr_rdr.get_value()?.iter() {
                    values.push(val?.to_string()?);
                }
                let attr_exp = AttrExp {
                    key,
                    op,
                    value: values,
                };
                matches.push(attr_exp);
            }
        }
        let services = if jp_rdr.has_provides() {
            let mut svc_ids: Vec<String> = Vec::new();
            for svc_rdr in jp_rdr.get_provides()?.iter() {
                svc_ids.push(svc_rdr.get_id()?.to_string()?);
            }
            Some(svc_ids)
        } else {
            None
        };
        let flags = if jp_rdr.has_flags() {
            let mut jflags: EnumSet<JFlag> = EnumSet::new();
            for flag_rdr in jp_rdr.get_flags()?.iter() {
                match flag_rdr? {
                    v1::JoinFlag::Node => jflags |= JFlag::IsNode,
                    v1::JoinFlag::Vs => jflags |= JFlag::IsVs,
                    v1::JoinFlag::Vsdock => jflags |= JFlag::IsVsDock,
                }
            }
            jflags
        } else {
            EnumSet::new()
        };
        Ok(JPolicy {
            matches,
            flags,
            services,
        })
    }
}

/// True if `vals` includes exactly the values from this AttrExp. Order not important.
/// If there are duplicates in `vals` there must also be duplicates in `attr_exp.value`
/// and vice versa.
///
/// Note that there should never normally be duplicates in `attr_exp.value`
/// since AttrExprs are created by the compiler and duplicates are not generated.
pub fn contains_exactly<S: AsRef<str>>(attr_exp: &AttrExp, vals: &[S]) -> bool {
    if vals.len() != attr_exp.value.len() {
        return false;
    }

    let mut m = HashMap::<String, usize>::new();
    for s in vals {
        *m.entry(s.as_ref().to_owned()).or_insert(0) += 1;
    }

    let mut n: HashMap<String, usize> = HashMap::<String, usize>::new();
    for s in &attr_exp.value {
        *n.entry(s.to_owned()).or_insert(0) += 1;
    }

    m == n
}

fn is_empty_value(attr_exp: &AttrExp) -> bool {
    attr_exp.value.is_empty() || attr_exp.value[0].is_empty()
}

impl JPolicy {
    /// The list of attributes matches this JPolicy only if all the JPolicy's AttrExps are satisfied.
    ///
    /// How attribute expressions match attributes here for reference (@cpacejo)
    /// - (key, has, v) or (key, has, (v0, v1, v2)) matches if "key" attribute is present and includes all of the specified values.
    /// - (key,excludes,v) or (key, excludes, (v0, v1,v2)) matches if "key" attribute is present and it has none of the specified values.
    /// - (key, eq, v) or (key, eq, (v0, v1, v2)) matches if "key" attribute is present and is exactly the specified values.
    /// - (key, ne, v) or (key, ne, (v0, v1, v2)) matches if "key" attribute is present and is not equal to the specified values.
    /// - In the case of multi value order is ignored.
    ///  - Special cases for HAS and EXCLUDES as (key, has, "") and (key, excludes, "").  These match having or not-having (respectively)
    ///    the attribute.  So (cn, has, "") will match if there is a CN attribute regardless of value.
    ///
    /// Duplicates should be dealt with before calling this. For example `(foo, eq, (a,b))` will not match `foo:(a,a,b)`.
    pub fn matches(&self, attrs: &[Attribute]) -> bool {
        for jp_exp in &self.matches {
            // continue so long as we keep matching the jp_exp's
            let mut found = false;

            for attr in attrs {
                if attr.get_key() == jp_exp.key {
                    // We assume the key appears only once in the incoming list.
                    found = true;

                    match jp_exp.op {
                        AttrOp::Eq => {
                            if !contains_exactly(jp_exp, &attr.get_value()) {
                                return false;
                            }
                        }
                        AttrOp::Ne => {
                            if contains_exactly(jp_exp, &attr.get_value()) {
                                return false;
                            }
                        }
                        AttrOp::Has => {
                            // HAS - the attribute must have all the values present in the attr exp.
                            // ALSO, if the AttrExp is (KEY, HAS, "") that is a match for any values on the attr.
                            if !is_empty_value(jp_exp) {
                                if !attr.value_has_all(&jp_exp.value) {
                                    return false;
                                }
                            }
                        }
                        AttrOp::Excludes => {
                            // EXCLUDES - the attribute must not have any of the values present in the AttrExp.
                            // ALSO, if the AttrExp is (KEY, EXCLUDES, "") that means we exclude the key, so it's a fail.
                            if is_empty_value(jp_exp) {
                                return false;
                            }
                            if attr.value_has_any(&jp_exp.value) {
                                return false;
                            }
                        }
                    }
                }
            }
            if !found {
                // EXCLUDES with an empty value matches not-having the attribute.
                if jp_exp.op == AttrOp::Excludes && is_empty_value(jp_exp) {
                    continue;
                }
                // Fail - all keys must be present.
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(key: &str, values: Vec<&str>) -> Attribute {
        Attribute::builder(key).values(values)
    }

    #[test]
    fn test_attrexp_contains_exactly() {
        let exp = AttrExp {
            key: "k".to_string(),
            op: AttrOp::Eq,
            value: vec!["a".to_string(), "b".to_string()],
        };
        let values = vec!["a".to_string()];
        assert!(!contains_exactly(&exp, &values));

        let values = vec!["a".to_string(), "b".to_string()];
        assert!(contains_exactly(&exp, &values));

        let values = vec!["b".to_string(), "a".to_string()];
        assert!(contains_exactly(&exp, &values));

        let values = vec!["a".to_string(), "b".to_string(), "b".to_string()];
        assert!(!contains_exactly(&exp, &values));
    }

    #[test]
    fn test_attrexp_contains_exactly_dupes() {
        // This is improbable since compiler does not create AttrExp with dupes,
        // but it should nevertheless work.
        let exp = AttrExp {
            key: "k".to_string(),
            op: AttrOp::Eq,
            value: vec!["a".to_string(), "b".to_string(), "a".to_string()],
        };

        // Any combo of two "a" and one "b" should work
        assert!(contains_exactly(&exp, &vec!["a", "b", "a"]));
        assert!(contains_exactly(&exp, &vec!["a", "a", "b"]));
        assert!(contains_exactly(&exp, &vec!["b", "a", "a"]));

        assert!(!contains_exactly(&exp, &vec!["b", "a", "a", "b", "a"]));
        assert!(!contains_exactly(&exp, &vec!["a", "b", "b"]));
        assert!(!contains_exactly(&exp, &vec!["a", "b"]));
    }

    #[test]
    fn test_attrexp_is_empty_value() {
        let empty = AttrExp {
            key: "k".to_string(),
            op: AttrOp::Eq,
            value: Vec::new(),
        };
        let empty_str = AttrExp {
            key: "k".to_string(),
            op: AttrOp::Eq,
            value: vec!["".to_string()],
        };
        let non_empty = AttrExp {
            key: "k".to_string(),
            op: AttrOp::Eq,
            value: vec!["a".to_string(), "".to_string()],
        };

        assert!(is_empty_value(&empty));
        assert!(is_empty_value(&empty_str));
        assert!(!is_empty_value(&non_empty));
    }

    #[test]
    fn test_jpolicy_matches_eq() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Eq,
                value: vec!["a".to_string(), "b".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };

        let attrs = vec![attr("k1", vec!["a", "b", "c"])];
        assert!(!policy.matches(&attrs));

        let attrs = vec![attr("k1", vec!["a", "b"])];
        assert!(policy.matches(&attrs));
    }

    #[test]
    fn test_jpolicy_matches_ne_rejects_full_match() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Ne,
                value: vec!["a".to_string(), "b".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };
        let attrs = vec![attr("k1", vec!["a", "b", "c"])];
        assert!(policy.matches(&attrs));
        let attrs = vec![attr("k1", vec!["a", "b"])];
        assert!(!policy.matches(&attrs));
        let attrs = vec![attr("k1", vec!["c"])];
        assert!(policy.matches(&attrs));
    }

    #[test]
    fn test_jpolicy_matches_has_empty_value() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Has,
                value: vec!["".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };
        let attrs = vec![attr("k1", vec!["a", "b"])];

        assert!(policy.matches(&attrs));
    }

    #[test]
    fn test_jpolicy_matches_has_empty_value_missing_key_fails() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Has,
                value: vec!["".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };

        assert!(!policy.matches(&[attr("k2", vec!["a"])]));
    }

    #[test]
    fn test_jpolicy_matches_excludes_value_present() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Excludes,
                value: vec!["b".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };
        let attrs = vec![attr("k1", vec!["a", "b"])];

        assert!(!policy.matches(&attrs));
    }

    #[test]
    fn test_jpolicy_matches_excludes_no_values_present() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Excludes,
                value: vec!["b".to_string(), "c".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };
        let attrs = vec![attr("k1", vec!["a"])];

        assert!(policy.matches(&attrs));
    }

    #[test]
    fn test_jpolicy_matches_missing_key_fails() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Eq,
                value: vec!["a".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };
        let attrs = vec![attr("k2", vec!["a"])];

        assert!(!policy.matches(&attrs));
    }

    #[test]
    fn test_jpolicy_matches_multiple_exact() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Eq,
                value: vec!["a".to_string(), "b".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };
        let attrs = vec![attr("k1", vec!["a", "b", "c"])];

        // Should not match since our attr also includes "c"
        assert!(!policy.matches(&attrs));
    }

    #[test]
    fn test_jpolicy_matches_ne_multiple_exact() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Ne,
                value: vec!["a".to_string(), "b".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };

        // (a,b) != (a,b,c)
        let attrs = vec![attr("k1", vec!["a", "b", "c"])];
        assert!(policy.matches(&attrs));

        // (a,b) == (b,a)
        let attrs = vec![attr("k1", vec!["b", "a"])];
        assert!(!policy.matches(&attrs));
    }

    #[test]
    fn test_jpolicy_matches_eq_order_ignored() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Eq,
                value: vec!["a".to_string(), "b".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };

        let attrs = vec![attr("k1", vec!["b", "a"])];
        assert!(policy.matches(&attrs));
    }

    #[test]
    fn test_jpolicy_matches_eq_dupes() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Eq,
                value: vec!["a".to_string(), "b".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };

        // Duplicates in attributes should cause Eq to fail
        let attrs = vec![attr("k1", vec!["b", "a", "a", "b"])];
        assert!(!policy.matches(&attrs));
    }

    #[test]
    fn test_jpolicy_matches_has_dupes() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Has,
                value: vec!["a".to_string(), "b".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };

        // Duplicates in attributes should not affect Has
        assert!(policy.matches(&[attr("k1", vec!["a", "b", "a", "b"])]));
        assert!(!policy.matches(&[attr("k1", vec!["a"])]));
    }

    #[test]
    fn test_jpolicy_matches_has_required_values() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Has,
                value: vec!["a".to_string(), "b".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };

        assert!(policy.matches(&[attr("k1", vec!["a", "b", "c"])]));
        assert!(!policy.matches(&[attr("k1", vec!["a"])]));
    }

    #[test]
    fn test_jpolicy_matches_excludes_empty_value_fails() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Excludes,
                value: vec!["".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };

        assert!(!policy.matches(&[attr("k1", vec!["a"])]));
    }

    #[test]
    fn test_jpolicy_matches_excludes_empty_value_missing_key_matches() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Excludes,
                value: vec!["".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };

        assert!(policy.matches(&[attr("k2", vec!["a"])]));
    }

    #[test]
    fn test_jpolicy_matches_ne_allows_partial_mismatch() {
        let policy = JPolicy {
            matches: vec![AttrExp {
                key: "k1".to_string(),
                op: AttrOp::Ne,
                value: vec!["a".to_string(), "b".to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        };
        let attrs = vec![attr("k1", vec!["a"])];

        assert!(policy.matches(&attrs));
    }
}
