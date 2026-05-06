use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

use thiserror::Error;

pub const ROLE_NODE: &str = "node";
pub const ROLE_ADAPTER: &str = "adapter";
const NEVER_EXPIRES: Duration = Duration::from_secs(60 * 60 * 60 * 24 * 365 * 100); // 100 years

pub mod key {

    /// used to be called EPID
    pub const ZPR_ADDR: &str = "zpr.addr";

    /// Dock ZPR address
    pub const CONNECT_VIA: &str = "zpr.connect_via";

    /// List of services provided.
    pub const SERVICES: &str = "zpr.services";

    pub const ACTOR_HASH: &str = "zpr.actor_hash";

    /// CN value
    pub const CN: &str = "endpoint.zpr.adapter.cn";

    /// "zpr.authority" attribute key
    pub const AUTHORITY: &str = "zpr.authority";

    /// "zpr.config_id"
    pub const CONFIG_ID: &str = "zpr.config_id";

    /// AAA network in CIDR notation
    pub const AAA_NET: &str = "endpoint.zpr.node.aaa_net";

    /// Substrate address is a SocketAddr.to_string()
    pub const SUBSTRATE_ADDR: &str = "zpr.substrate_addr";

    /// One of the ROLE_ constants.
    pub const ROLE: &str = "zpr.role";

    /// Policy install version when actor last authenticated/permitted.
    pub const VINST: &str = "zpr.vinst";
}

#[derive(Debug, Error)]
pub enum AttributeError {
    #[error("attribute is not single-valued: {0}")]
    NotSingleValue(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[allow(dead_code)]
pub struct Attribute {
    key: String,
    value: Vec<String>,
    expires_at: SystemTime,
}

/// TBD. Placeholder for that which is used to match link attributes based on policy.
/// For example, a ZPL constrainted attribute might be "location:spain" and in that
/// case the AttrMatch would indicates that we are looking for a "location"
/// key with a "spain" value.
#[derive(Debug, Clone, Serialize, Hash, Eq, PartialEq)]
pub struct AttrMatch {} // TODO

pub struct AttributeBuilder {
    key: String,
    expires_at: SystemTime,
}

/// Helper for building attributes.  Allows for addin an expiration time before setting value/values.
impl AttributeBuilder {
    /// Create a builder with the given attribute key and a default expiration
    /// in the far future.
    fn new(key: String) -> Self {
        AttributeBuilder {
            key,
            expires_at: SystemTime::now() + NEVER_EXPIRES,
        }
    }

    /// Add a expiration time.
    pub fn expires(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Add a duration until expiration from now.
    pub fn expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_at = SystemTime::now() + expires_in;
        self
    }

    /// Finishes the build and returns an attribute with given value.
    pub fn value<S>(self, value: S) -> Attribute
    where
        S: AsRef<str>,
    {
        Attribute::new(self.key, std::iter::once(value), self.expires_at)
    }

    /// Finishes the build and returns an attribute with the given set of values.
    pub fn values<I, S>(self, values: I) -> Attribute
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Attribute::new(self.key, values, self.expires_at)
    }
}

impl Attribute {
    fn collect_values<I, S>(values: I) -> Vec<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        values
            .into_iter()
            .map(|value| value.as_ref().to_string())
            .collect()
    }

    /// Create a handy attribute builder initialized with the given key.
    /// By default the attribute will expire in the far future unless you
    /// set an expiration using the builder.  To finish the build use
    /// [AttributeBuilder::value] or [AttributeBuilder::values] depending
    /// on whether you want to create a single or multi-valued attribute.
    pub fn builder<S: Into<String>>(key: S) -> AttributeBuilder {
        AttributeBuilder::new(key.into())
    }

    pub fn new<I, S>(key: String, values: I, expires_at: SystemTime) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Attribute {
            key,
            value: Self::collect_values(values),
            expires_at,
        }
    }

    pub fn get_key(&self) -> &str {
        &self.key
    }

    pub fn get_value(&self) -> &[String] {
        &self.value
    }

    /// If this is a single valued attribute, return a reference to the single value.
    /// Otherwise, throws an error.
    pub fn get_single_value(&self) -> Result<&str, AttributeError> {
        if self.value.len() != 1 {
            return Err(AttributeError::NotSingleValue(self.key.clone()));
        }
        Ok(&self.value[0])
    }

    /// Return true if this is a single valued attribute and the value matches.
    pub fn is_single_value(&self, value: &str) -> bool {
        self.value.len() == 1 && self.value[0] == value
    }

    /// Get a "human" formatted version of the value. When there is only one
    /// value you get a simple String. When there are multiple values they are
    /// joined with comma.
    pub fn get_value_as_string(&self) -> String {
        self.value.join(", ")
    }

    pub fn get_value_len(&self) -> usize {
        self.value.len()
    }

    pub fn get_expires(&self) -> SystemTime {
        self.expires_at
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    pub fn value_has(&self, v: &str) -> bool {
        self.value.iter().any(|s| s == v)
    }

    pub fn value_has_all(&self, vs: &[String]) -> bool {
        for v in vs {
            if !self.value_has(v) {
                return false;
            }
        }
        true
    }

    pub fn value_has_any(&self, vs: &[String]) -> bool {
        for v in vs {
            if self.value_has(v) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_has_all_true() {
        let attr = Attribute::builder("key").values(vec!["alpha", "beta", "gamma"]);
        let values = vec!["alpha".to_string(), "gamma".to_string()];

        assert!(attr.value_has_all(&values));
    }

    #[test]
    fn test_value_has_all_false() {
        let attr = Attribute::builder("key").values(vec!["alpha", "beta", "gamma"]);
        let values = vec!["alpha".to_string(), "delta".to_string()];

        assert!(!attr.value_has_all(&values));
    }

    #[test]
    fn test_value_has_any_true() {
        let attr = Attribute::builder("key").values(vec!["alpha", "beta", "gamma"]);
        let values = vec!["delta".to_string(), "beta".to_string()];

        assert!(attr.value_has_any(&values));
    }

    #[test]
    fn test_value_has_any_false() {
        let attr = Attribute::builder("key").values(vec!["alpha", "beta", "gamma"]);
        let values = vec!["delta".to_string(), "epsilon".to_string()];

        assert!(!attr.value_has_any(&values));
    }

    #[test]
    fn test_get_value_as_string() {
        let attr = Attribute::builder("key").values(vec!["alpha", "beta", "gamma"]);
        assert_eq!(attr.get_value_as_string(), "alpha, beta, gamma");
        let attr = Attribute::builder("key").value("");
        assert_eq!(attr.get_value_as_string(), "");
        let attr = Attribute::builder("key").value("foo");
        assert_eq!(attr.get_value_as_string(), "foo");
    }
}
