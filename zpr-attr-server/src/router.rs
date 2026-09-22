//! The axum router serving the two `zpr-attr/1` endpoints.
//!
//! `POST {url}/query` and `GET {url}/schema`, exactly per the spec's status
//! table (`docs/ATTRIBUTE_SERVICE.md`, "The wire protocol"): a missing or
//! unknown bearer token is `401` before anything else, a malformed request
//! is `400`, conflicting records are `409`, and an unknown actor is a
//! successful `{"attributes": {}}` — never an error. The two reserved paths
//! (`/stream`, `/satisfies`) answer `501` so nothing else squats on them.

use std::sync::Arc;

use axum::Router;

use crate::store::AttrData;

/// What the router needs to answer requests: the data set and the one
/// bearer token that may query it.
#[derive(Clone)]
pub struct AppState {
    /// The loaded attribute data.
    pub data: Arc<AttrData>,
    /// The expected bearer token, compared verbatim.
    pub token: String,
}

/// Build the `zpr-attr/1` router over one data set and one bearer token.
pub fn app(state: AppState) -> Router {
    // Stub (zipline#80 step 1): no routes yet; every request is a 404. The
    // contract tests define the endpoints; step 2 implements them.
    let _ = state;
    Router::new()
}
