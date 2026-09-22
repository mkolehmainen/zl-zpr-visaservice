//! The axum router serving the two `zpr-attr/1` endpoints.
//!
//! `POST {url}/query` and `GET {url}/schema`, exactly per the spec's status
//! table (`docs/ATTRIBUTE_SERVICE.md`, "The wire protocol"): a missing or
//! unknown bearer token is `401` before anything else, a malformed request
//! is `400`, conflicting records are `409`, and an unknown actor is a
//! successful `{"attributes": {}}` — never an error. The two reserved paths
//! (`/stream`, `/satisfies`) answer `501` so nothing else squats on them.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::debug;

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
/// The bearer check runs as middleware ahead of every route, so `401` wins
/// over `400`/`404`/`405` — the spec's "Bearer check → 401" comes first.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/query", post(query))
        .route("/schema", get(schema))
        .route("/stream", get(reserved))
        .route("/satisfies", post(reserved))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ))
        .with_state(state)
}

/// Middleware: require `Authorization: Bearer <token>` matching the
/// configured token exactly. Anything else — missing header, wrong scheme,
/// wrong or empty token — is `401` before any route logic runs. The token
/// value is never logged.
async fn require_bearer(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    match presented {
        Some(token) if !state.token.is_empty() && token == state.token => Ok(next.run(req).await),
        _ => {
            debug!("rejecting request with missing or unknown bearer token");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// The `POST /query` request body (spec: "The wire protocol"). Unknown
/// fields are rejected — the OpenAPI says `additionalProperties: false`,
/// and a smuggled field (say, a tenant name) silently ignored would
/// contradict the protocol's "no tenant parameter" rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryRequest {
    /// The actor's lookup-identity set as ZPR key names. Values are single
    /// strings — a multi-valued attribute can never name an identity.
    identities: BTreeMap<String, String>,
    /// The service-side names the caller will keep. A hint this server
    /// honours: names outside it are pruned from the answer (the visa
    /// service filters through its mapping regardless).
    attributes: Vec<String>,
}

/// `POST {url}/query` — attributes for one actor, named by its identity
/// set. Union-and-conflict over every matched entry (conflict → `409`,
/// never a coin flip); the `attributes` hint is honoured; `expires_at` is
/// emitted only when the stored entry carries one; an unknown actor is
/// `{"attributes": {}}`, a success.
async fn query(State(state): State<AppState>, body: axum::body::Bytes) -> Response {
    // Decode by hand so every malformed body — bad JSON, missing field,
    // unknown field, non-string identity value — is a plain 400, not
    // axum's default 415/422 rejection zoo.
    let request: QueryRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            debug!("malformed /query body: {error}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    // An empty identity set matches nothing it could mean (the OpenAPI
    // says minProperties: 1); reject it rather than guess.
    if request.identities.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let matched = match state.data.lookup(&request.identities) {
        Ok(matched) => matched,
        Err(conflict) => {
            debug!(
                "conflicting records for attribute '{}' -> 409",
                conflict.name
            );
            return StatusCode::CONFLICT.into_response();
        }
    };

    // Honour the hint: keep only the names the caller asked for. BTreeMap
    // iteration keeps the response keys sorted.
    let mut attributes = serde_json::Map::new();
    for (name, entry) in &matched {
        if !request.attributes.contains(name) {
            continue;
        }
        let mut answer = json!({ "values": entry.values() });
        if let Some(stamp) = entry.expires_at() {
            answer["expires_at"] = Value::String(stamp.to_string());
        }
        attributes.insert(name.clone(), answer);
    }
    Json(json!({ "attributes": attributes })).into_response()
}

/// `GET {url}/schema` — the attribute vocabulary this service can return:
/// the data file's `_schema` definitions verbatim (or definitions derived
/// from the data), with `identityKeys` from the file's top-level keys.
async fn schema(State(state): State<AppState>) -> Response {
    Json(state.data.schema_response()).into_response()
}

/// The reserved paths (`GET /stream`, `POST /satisfies`): named by the spec
/// so no implementer takes them for something else, specified by nothing,
/// answered with `501` per the OpenAPI rendering.
async fn reserved() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}
