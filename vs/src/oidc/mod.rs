//! Offline OpenID Connect `id_token` validation (OIDC master plan C2).
//!
//! This module is deliberately self-contained: it knows nothing about policy
//! or the connect path. Callers (C4/C5) build an [`IdpParams`] from the
//! policy-declared trusted-service configuration and hand over a JWKS; this
//! module only answers "is this token valid for that provider, and what do we
//! keep from it".

mod validate;

// The re-export is the module's public surface; nothing consumes it until
// OIDC-C4/C5 wire validation into the connect path.
#[allow(unused_imports)]
pub use validate::{IdpParams, OidcError, ValidatedToken, validate_id_token};
