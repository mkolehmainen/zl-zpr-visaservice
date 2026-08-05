use serde::Serialize;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::SystemTime;
use thiserror::Error;

use crate::attribute::key;
use crate::attribute::{Attribute, ROLE_ADAPTER, ROLE_NODE};

#[derive(Debug, Error)]
pub enum AttributeError {
    #[error("attribute error: {0}")]
    AttributeError(String),
}

/// Role of the actor. Can be Adapter, Node. As a default
/// the actor starts as UNKNOWN.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Hash)]
pub enum Role {
    #[default]
    Unknown,
    Adapter,
    Node,
}

/// From the perspective of the evaluator, and actor is just a bunch of
/// attributes and provided services.  The provided services is stored
/// under the [Key::SERVICES] attribute key.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Actor {
    // Attributes associated with this actor, keyed by attribute key.
    attrs: HashMap<String, Attribute>,

    // Once authenticated, an actor will have one or more identity attributes.
    // The names are kept here in order.
    identity_keys: Vec<String>,

    // Cache zpr_addr since we parse it.
    zpr_addr: Option<IpAddr>,
}

/// Hand written because [HashMap] is not [Hash]. Attributes are hashed in key
/// order so the result does not depend on insertion or map iteration order.
impl Hash for Actor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut attrs: Vec<&Attribute> = self.attrs.values().collect();
        attrs.sort_by_key(|a| a.get_key());
        attrs.hash(state);
        self.identity_keys.hash(state);
        self.zpr_addr.hash(state);
    }
}

impl Actor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn attrs_iter(&self) -> impl Iterator<Item = &Attribute> {
        self.attrs.values()
    }

    pub fn identity_keys_iter(&self) -> impl Iterator<Item = &String> {
        self.identity_keys.iter()
    }

    /// Add the name of an identity attribute. The attribute must
    /// exist or an error is returned.  The `order` parameter is the
    /// priority of the key, 0 is highest.  Passing usize::MAX appends
    /// to the end.
    pub fn add_identity_key(&mut self, order: usize, key: &str) -> Result<(), AttributeError> {
        if !self.has_attribute_named(key) {
            return Err(AttributeError::AttributeError(format!(
                "cannot add identity key '{}', attribute not present",
                key
            )));
        }
        if order >= self.identity_keys.len() {
            self.identity_keys.push(key.to_string());
        } else {
            self.identity_keys.insert(order, key.to_string());
        }
        Ok(())
    }

    /// Adds or replaces the attribute with name `key`.  Assumes a single value attribute.
    /// Only used in tests.
    #[cfg(test)]
    pub fn add_attr_from_parts(
        &mut self,
        key: &str,
        value: &str,
        expires_in: std::time::Duration,
    ) -> Result<(), AttributeError> {
        self.add_attribute(Attribute::builder(key).expires_in(expires_in).value(value))
    }

    /// Adds or replaces the attribute on the actor.
    pub fn add_attribute(&mut self, attr: Attribute) -> Result<(), AttributeError> {
        let key = attr.get_key().to_string();
        let value = attr.get_value();
        match key.as_str() {
            key::ZPR_ADDR => {
                if let Ok(ip) = value[0].parse::<IpAddr>() {
                    self.zpr_addr = Some(ip);
                } else {
                    return Err(AttributeError::AttributeError(format!(
                        "Invalid IP address in zpr.addr attribute: '{}'",
                        value[0]
                    )));
                }
            }
            // Validated on the way in so the getters can trust what is in the map.
            key::ROLE => {
                if value[0] != ROLE_ADAPTER && value[0] != ROLE_NODE {
                    return Err(AttributeError::AttributeError(format!(
                        "role must be 'node' or 'adapter', not: '{}'",
                        value[0]
                    )));
                }
            }
            _ => (),
        }
        self.attrs.insert(key, attr);
        Ok(())
    }

    /// Removes the attribute named `key`, clearing the cached ZPR address if that is
    /// what went away, and dropping it from the identity keys. Returns the removed
    /// attribute, or None if the actor did not have one.
    pub fn remove_attribute(&mut self, key: &str) -> Option<Attribute> {
        let attr = self.attrs.remove(key)?;
        if key == key::ZPR_ADDR {
            self.zpr_addr = None;
        }
        self.identity_keys.retain(|k| k != key);
        Some(attr)
    }

    pub fn get_attribute(&self, key: &str) -> Option<&Attribute> {
        self.attrs.get(key)
    }

    /// First value of the attribute named `key`, if the actor has one.
    fn single(&self, key: &str) -> Option<&str> {
        self.attrs.get(key)?.get_value().first().map(|s| s.as_str())
    }

    /// If there are identity attributes, the values are copied and returned here
    /// in order.
    pub fn get_identity(&self) -> Option<Vec<String>> {
        if self.identity_keys.is_empty() {
            None
        } else {
            let mut identity_values: Vec<String> = Vec::new();
            for key in &self.identity_keys {
                if let Some(attr) = self.get_attribute(key) {
                    identity_values.push(attr.get_value()[0].clone());
                }
            }
            Some(identity_values)
        }
    }

    /// TODO: Figure out all the details of how we hold authentication data.
    ///
    /// Returns the minimum expiration time from:
    /// - [key::AUTHORITY] attribute, if present.
    /// - any `identity` attributes, if present.
    /// - ELSE: None.
    ///
    /// If there are no identity keys we assume there is no authentication and return None.
    pub fn get_authentication_expiration(&self) -> Option<SystemTime> {
        let authority_expiration = self
            .get_attribute(key::AUTHORITY)
            .map(|attr| attr.get_expires());
        let identity_expiration = self
            .identity_keys
            .iter()
            .filter_map(|key| self.get_attribute(key))
            .map(|attr| attr.get_expires())
            .min();

        match (authority_expiration, identity_expiration) {
            (Some(a), Some(i)) => Some(a.min(i)),
            (Some(a), None) => Some(a),
            (None, Some(i)) => Some(i),
            (None, None) => None,
        }
    }

    pub fn is_provider(&self) -> bool {
        self.single(key::SERVICES).is_some_and(|s| !s.is_empty())
    }

    pub fn is_node(&self) -> bool {
        self.single(key::ROLE) == Some(ROLE_NODE)
    }

    /// Role as recorded in the [key::ROLE] attribute. Unknown if there is none.
    pub fn get_role(&self) -> Role {
        match self.single(key::ROLE) {
            Some(ROLE_NODE) => Role::Node,
            Some(ROLE_ADAPTER) => Role::Adapter,
            _ => Role::Unknown,
        }
    }

    pub fn get_cn(&self) -> Option<&str> {
        self.single(key::CN)
    }

    pub fn get_zpr_addr(&self) -> Option<&IpAddr> {
        self.zpr_addr.as_ref()
    }

    pub fn provides(&self, service_id: &str) -> bool {
        self.attrs
            .get(key::SERVICES)
            .is_some_and(|a| a.value_has(service_id))
    }

    pub fn services_iter(&self) -> impl Iterator<Item = &str> {
        self.attrs
            .get(key::SERVICES)
            .into_iter()
            .flat_map(|attr| attr.get_value().iter().map(|s| s.as_str()))
    }

    pub(crate) fn has_attribute_named(&self, key: &str) -> bool {
        self.attrs.contains_key(key)
    }

    pub(crate) fn has_attribute_value(&self, key: &str, value: &str) -> bool {
        self.attrs
            .get(key)
            .is_some_and(|a| a.is_single_value(value))
    }

    /// TRUE if all attribute values are present.
    pub(crate) fn has_attribute_values(&self, key: &str, values: &[String]) -> bool {
        self.attrs.get(key).is_some_and(|a| a.value_has_all(values))
    }

    /// TRUE if any attribute value from `values` is present.
    pub(crate) fn has_any_attribute_values(&self, key: &str, values: &[String]) -> bool {
        self.attrs.get(key).is_some_and(|a| a.value_has_any(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_add_attribute_zpr_addr_ipv4() {
        let mut actor = Actor::new();
        let attr = Attribute::builder(key::ZPR_ADDR)
            .expires_in(Duration::from_secs(3600))
            .value("192.168.1.100");
        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert_eq!(
            actor.get_zpr_addr(),
            Some(&"192.168.1.100".parse().unwrap())
        );
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_add_attribute_zpr_addr_ipv6() {
        let mut actor = Actor::new();
        let attr = Attribute::builder(key::ZPR_ADDR)
            .expires_in(Duration::from_secs(3600))
            .value("::1");
        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert_eq!(actor.get_zpr_addr(), Some(&"::1".parse().unwrap()));
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_add_attribute_zpr_addr_invalid() {
        let mut actor = Actor::new();
        let attr = Attribute::builder(key::ZPR_ADDR)
            .expires_in(Duration::from_secs(3600))
            .value("not-an-ip-address");
        let result = actor.add_attribute(attr);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid IP address")
        );
        assert_eq!(actor.get_zpr_addr(), None); // Should remain None
        assert_eq!(actor.attrs.len(), 0); // Attribute should not be added on error
    }

    #[test]
    fn test_add_attribute_services_non_empty() {
        let mut actor = Actor::new();
        let attr = Attribute::builder(key::SERVICES)
            .expires_in(Duration::from_secs(3600))
            .values(&["auth", "database", "logging"]);
        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert!(actor.is_provider());
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_services_iter_handles_multi() {
        let mut actor = Actor::new();
        let attr = Attribute::builder(key::SERVICES)
            .expires_in(Duration::from_secs(3600))
            .values(&["auth", "database", "logging"]);
        let result = actor.add_attribute(attr);

        assert!(result.is_ok());

        let services: Vec<&str> = actor.services_iter().collect();
        assert_eq!(services, vec!["auth", "database", "logging"]);
    }

    #[test]
    fn test_add_attribute_services_empty() {
        let mut actor = Actor::new();
        let attr = Attribute::builder(key::SERVICES)
            .expires_in(Duration::from_secs(3600))
            .value("");

        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert!(!actor.is_provider());
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_add_attribute_cn() {
        let mut actor = Actor::new();
        let attr = Attribute::builder(key::CN)
            .expires_in(Duration::from_secs(3600))
            .value("my-test-node");

        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert_eq!(actor.get_cn(), Some("my-test-node"));
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_add_attribute_role_adapter() {
        let mut actor = Actor::new();
        let attr = Attribute::builder(key::ROLE)
            .expires_in(Duration::from_secs(3600))
            .value(ROLE_ADAPTER);

        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert_eq!(actor.get_role(), Role::Adapter);
        assert!(!actor.is_node());
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_add_attribute_role_node() {
        let mut actor = Actor::new();
        let attr = Attribute::builder(key::ROLE)
            .expires_in(Duration::from_secs(3600))
            .value(ROLE_NODE);
        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert_eq!(actor.get_role(), Role::Node);
        assert!(actor.is_node());
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_add_attribute_role_invalid() {
        let mut actor = Actor::new();
        let attr = Attribute::builder(key::ROLE)
            .expires_in(Duration::from_secs(3600))
            .value("invalid-role");
        let result = actor.add_attribute(attr);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("role must be"));
        assert_eq!(actor.get_role(), Role::Unknown); // Should remain unchanged
        assert_eq!(actor.attrs.len(), 0); // Attribute should not be added on error
    }

    #[test]
    fn test_add_attribute_non_special_key() {
        let mut actor = Actor::new();
        let attr = Attribute::builder("custom.attribute")
            .expires_in(Duration::from_secs(3600))
            .value("custom-value");

        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        // All internal fields should remain at their defaults
        assert_eq!(actor.get_zpr_addr(), None);
        assert!(!actor.is_provider());
        assert_eq!(actor.get_cn(), None);
        assert_eq!(actor.get_role(), Role::Unknown);
        // But the attribute should be added to the list
        assert_eq!(actor.attrs.len(), 1);
        assert!(actor.has_attribute_named("custom.attribute"));
        assert!(actor.has_attribute_value("custom.attribute", "custom-value"));
    }

    #[test]
    fn test_add_attribute_overwrites_internal_fields() {
        let mut actor = Actor::new();

        // Set initial values
        let initial_attr = Attribute::builder(key::ROLE)
            .expires_in(Duration::from_secs(3600))
            .value(ROLE_ADAPTER);
        assert!(actor.add_attribute(initial_attr).is_ok());
        assert_eq!(actor.get_role(), Role::Adapter);

        // Overwrite with new value
        let new_attr = Attribute::builder(key::ROLE)
            .expires_in(Duration::from_secs(3600))
            .value(ROLE_NODE);
        assert!(actor.add_attribute(new_attr).is_ok());

        // Should have the new value
        assert_eq!(actor.get_role(), Role::Node);
        assert!(actor.is_node());
        assert_eq!(actor.attrs.len(), 1); // Same key, so the second replaces the first
    }

    #[test]
    fn test_add_identity_key_success() {
        let mut actor = Actor::new();
        // First add an attribute that can be used as an identity
        let attr = Attribute::builder("user.email")
            .expires_in(Duration::from_secs(3600))
            .value("test@example.com");
        actor.add_attribute(attr).unwrap();

        // Now add it as an identity key
        let result = actor.add_identity_key(0, "user.email");

        assert!(result.is_ok());
        assert_eq!(actor.identity_keys.len(), 1);
        assert_eq!(actor.identity_keys[0], "user.email");
    }

    #[test]
    fn test_add_identity_key_missing_attribute() {
        let mut actor = Actor::new();

        // Try to add an identity key for an attribute that doesn't exist
        let result = actor.add_identity_key(0, "user.email");

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("attribute not present")
        );
        assert_eq!(actor.identity_keys.len(), 0);
    }

    #[test]
    fn test_add_identity_key_at_beginning() {
        let mut actor = Actor::new();
        // Add multiple attributes
        actor
            .add_attribute(
                Attribute::builder("user.email")
                    .expires_in(Duration::from_secs(3600))
                    .value("test@example.com"),
            )
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder("user.id")
                    .expires_in(Duration::from_secs(3600))
                    .value("12345"),
            )
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder("user.name")
                    .expires_in(Duration::from_secs(3600))
                    .value("John Doe"),
            )
            .unwrap();

        // Add identity keys in specific order
        actor.add_identity_key(0, "user.email").unwrap();
        actor.add_identity_key(0, "user.id").unwrap(); // Insert at beginning

        assert_eq!(actor.identity_keys.len(), 2);
        assert_eq!(actor.identity_keys[0], "user.id");
        assert_eq!(actor.identity_keys[1], "user.email");
    }

    #[test]
    fn test_add_identity_key_at_end() {
        let mut actor = Actor::new();
        // Add multiple attributes
        actor
            .add_attribute(
                Attribute::builder("user.email")
                    .expires_in(Duration::from_secs(3600))
                    .value("test@example.com"),
            )
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder("user.id")
                    .expires_in(Duration::from_secs(3600))
                    .value("12345"),
            )
            .unwrap();

        // Add identity keys
        actor.add_identity_key(0, "user.email").unwrap();
        actor.add_identity_key(usize::MAX, "user.id").unwrap(); // Append to end

        assert_eq!(actor.identity_keys.len(), 2);
        assert_eq!(actor.identity_keys[0], "user.email");
        assert_eq!(actor.identity_keys[1], "user.id");
    }

    #[test]
    fn test_add_identity_key_in_middle() {
        let mut actor = Actor::new();
        // Add multiple attributes
        actor
            .add_attribute(
                Attribute::builder("user.email")
                    .expires_in(Duration::from_secs(3600))
                    .value("test@example.com"),
            )
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder("user.id")
                    .expires_in(Duration::from_secs(3600))
                    .value("12345"),
            )
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder("user.name")
                    .expires_in(Duration::from_secs(3600))
                    .value("John Doe"),
            )
            .unwrap();

        // Add identity keys
        actor.add_identity_key(0, "user.email").unwrap();
        actor.add_identity_key(1, "user.name").unwrap();
        actor.add_identity_key(1, "user.id").unwrap(); // Insert in middle

        assert_eq!(actor.identity_keys.len(), 3);
        assert_eq!(actor.identity_keys[0], "user.email");
        assert_eq!(actor.identity_keys[1], "user.id");
        assert_eq!(actor.identity_keys[2], "user.name");
    }

    #[test]
    fn test_get_identity_empty() {
        let actor = Actor::new();

        let identity = actor.get_identity();

        assert!(identity.is_none());
    }

    #[test]
    fn test_get_identity_single_key() {
        let mut actor = Actor::new();
        actor
            .add_attribute(
                Attribute::builder("user.email")
                    .expires_in(Duration::from_secs(3600))
                    .value("test@example.com"),
            )
            .unwrap();
        actor.add_identity_key(0, "user.email").unwrap();

        let identity = actor.get_identity();

        assert!(identity.is_some());
        let identity = identity.unwrap();
        assert_eq!(identity.len(), 1);
        assert_eq!(identity[0], "test@example.com");
    }

    #[test]
    fn test_get_identity_multiple_keys() {
        let mut actor = Actor::new();
        actor
            .add_attribute(
                Attribute::builder("user.email")
                    .expires_in(Duration::from_secs(3600))
                    .value("test@example.com"),
            )
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder("user.id")
                    .expires_in(Duration::from_secs(3600))
                    .value("12345"),
            )
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder("user.name")
                    .expires_in(Duration::from_secs(3600))
                    .value("John Doe"),
            )
            .unwrap();

        actor.add_identity_key(0, "user.email").unwrap();
        actor.add_identity_key(1, "user.id").unwrap();
        actor.add_identity_key(2, "user.name").unwrap();

        let identity = actor.get_identity();

        assert!(identity.is_some());
        let identity = identity.unwrap();
        assert_eq!(identity.len(), 3);
        assert_eq!(identity[0], "test@example.com");
        assert_eq!(identity[1], "12345");
        assert_eq!(identity[2], "John Doe");
    }

    #[test]
    fn test_get_authentication_expiration_no_identity_keys() {
        let actor = Actor::new();
        assert!(actor.get_authentication_expiration().is_none());
    }

    #[test]
    fn test_get_authentication_expiration_single_key() {
        let mut actor = Actor::new();
        let attr = Attribute::builder("user.email")
            .expires_in(Duration::from_secs(3600))
            .value("test@example.com");
        let expected = attr.get_expires();
        actor.add_attribute(attr).unwrap();
        actor.add_identity_key(0, "user.email").unwrap();

        assert_eq!(actor.get_authentication_expiration(), Some(expected));
    }

    #[test]
    fn test_get_authentication_expiration_returns_soonest() {
        let mut actor = Actor::new();
        let soon = Attribute::builder("user.id")
            .expires_in(Duration::from_secs(60))
            .value("42");
        let later = Attribute::builder("user.email")
            .expires_in(Duration::from_secs(3600))
            .value("test@example.com");
        let soonest_expiry = soon.get_expires();
        actor.add_attribute(soon).unwrap();
        actor.add_attribute(later).unwrap();
        actor.add_identity_key(0, "user.email").unwrap();
        actor.add_identity_key(1, "user.id").unwrap();

        assert_eq!(actor.get_authentication_expiration(), Some(soonest_expiry));
    }

    #[test]
    fn test_get_authentication_expiration_non_identity_attrs_ignored() {
        let mut actor = Actor::new();
        // This attribute is NOT an identity key — should not affect the result
        actor
            .add_attribute(
                Attribute::builder("custom.attr")
                    .expires_in(Duration::from_secs(10))
                    .value("irrelevant"),
            )
            .unwrap();
        let attr = Attribute::builder("user.email")
            .expires_in(Duration::from_secs(3600))
            .value("test@example.com");
        let expected = attr.get_expires();
        actor.add_attribute(attr).unwrap();
        actor.add_identity_key(0, "user.email").unwrap();

        assert_eq!(actor.get_authentication_expiration(), Some(expected));
    }

    #[test]
    fn test_get_identity_preserves_order() {
        let mut actor = Actor::new();
        actor
            .add_attribute(
                Attribute::builder("attr.a")
                    .expires_in(Duration::from_secs(3600))
                    .value("value_a"),
            )
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder("attr.b")
                    .expires_in(Duration::from_secs(3600))
                    .value("value_b"),
            )
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder("attr.c")
                    .expires_in(Duration::from_secs(3600))
                    .value("value_c"),
            )
            .unwrap();

        // Add in specific order: b, c, a
        actor.add_identity_key(0, "attr.b").unwrap();
        actor.add_identity_key(1, "attr.c").unwrap();
        actor.add_identity_key(2, "attr.a").unwrap();

        let identity = actor.get_identity();

        assert!(identity.is_some());
        let identity = identity.unwrap();
        assert_eq!(identity.len(), 3);
        // Should return values in the order keys were added
        assert_eq!(identity[0], "value_b");
        assert_eq!(identity[1], "value_c");
        assert_eq!(identity[2], "value_a");
    }
}
