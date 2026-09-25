//! Offline OpenID Connect `id_token` validation (zipline#8).
//!
//! This module is deliberately self-contained: it knows nothing about policy
//! or the connect path. Callers (zipline#10/#11) build an [`IdpParams`] from the
//! policy-declared trusted-service configuration and hand over a JWKS; this
//! module only answers "is this token valid for that provider, and what do we
//! keep from it".

mod jwks;
mod store;
mod validate;

// The re-exports are the module's public surface; nothing consumes them until
// zipline#10/#11 wire validation into the connect path.
#[cfg(test)]
pub(crate) use jwks::test_support;
#[allow(unused_imports)]
pub use jwks::{KeySource, ProxyFuture, ProxyResolver, static_proxy};
#[allow(unused_imports)]
pub use store::OidcTrustedService;
#[allow(unused_imports)]
pub use validate::{IdpParams, NonceExpectation, OidcError, ValidatedToken, validate_id_token};

// The zipline#8 test-only token minter, shared with the connect-path tests (zipline#11).
#[cfg(test)]
pub(crate) use validate::mint;
