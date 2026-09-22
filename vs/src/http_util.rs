//! Shared HTTP plumbing for the visa service's outbound fetches.
//!
//! Everything the visa service fetches over HTTP — an OIDC provider's JWKS,
//! an attribute service's `/query` answer — is a response from a host that,
//! however trusted by policy, must not be able to balloon memory with an
//! unbounded body. This module owns the shared cap and the capped reader so
//! each client cannot drift its own copy (zipline#78, plan V1 step 3).

use crate::error::ServiceError;

/// Hard cap on an outbound fetch's response body. Real JWKS sets and
/// attribute answers are a few kilobytes; anything approaching this is
/// hostile or broken (docs/ATTRIBUTE_SERVICE.md caps bodies at 1 MiB).
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024; // 1 MiB

/// Read `resp`'s body under [`MAX_RESPONSE_BYTES`], chunk by chunk. A body
/// that exceeds the cap is an error naming `what` (e.g. "JWKS response"),
/// not a truncation — a partial body must never be parsed as a whole one.
/// The body content itself is never echoed into the error.
pub async fn read_body_capped(
    resp: &mut reqwest::Response,
    what: &str,
) -> Result<Vec<u8>, ServiceError> {
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ServiceError::Internal(format!("{what} read failed: {e}")))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(ServiceError::Internal(format!(
                "{what} too large (over {MAX_RESPONSE_BYTES} bytes)"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
