//! Offline OpenID Connect `id_token` validation (OIDC master plan C2).
//!
//! This module is deliberately self-contained: it knows nothing about policy
//! or the connect path. Callers (C4/C5) build an [`IdpParams`] from the
//! policy-declared trusted-service configuration and hand over a JWKS; this
//! module only answers "is this token valid for that provider, and what do we
//! keep from it".

mod jwks;
mod validate;

// The re-exports are the module's public surface; nothing consumes them until
// OIDC-C4/C5 wire validation into the connect path.
#[allow(unused_imports)]
pub use jwks::KeySource;
#[allow(unused_imports)]
pub use validate::{IdpParams, OidcError, ValidatedToken, validate_id_token};
