//! Protocol contract tests for the `zpr-attr/1` reference server
//! (zipline#80, task V3).
//!
//! Every request/response example in the normative spec
//! (`zl-zpr-dev-context/docs/ATTRIBUTE_SERVICE.md`, "The wire protocol") is
//! driven against the router **in-process** (`tower::ServiceExt::oneshot`,
//! no network) and asserted byte-for-byte on the JSON shapes; each exchange
//! is additionally validated against the vendored OpenAPI rendering
//! (`tests/zpr-attr-v1.openapi.yaml`) with the lightweight structural
//! validator at the bottom of this file — path documented, method
//! documented, status documented, response body valid against the
//! referenced schema. These tests hold the reference server to the spec and
//! the OpenAPI file to the server, so the three cannot silently diverge.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use zpr_attr_server::router::{AppState, app};
use zpr_attr_server::store::AttrData;

/// The bearer token every authorized test request presents.
const TOKEN: &str = "test-token";

/// The data file behind the spec's examples: exactly the visa service
/// `file` store's JSON — identity key -> identity value -> name -> values —
/// plus the two server extensions: the `_schema` key (the spec's `/schema`
/// example, verbatim) and the object spelling of `roles` carrying the
/// `expires_at` the spec's `/query` example emits. The actor is the spec's
/// example actor; the `device.zpr.adapter.cn` entry is present but empty so
/// the schema's `identityKeys` example holds both keys.
const SPEC_DATA: &str = r#"{
    "_schema": [
        { "name": "dept", "type": "string", "multiValued": false,
          "description": "Cost centre", "canonicalValues": ["eng", "sales", "ops"] },
        { "name": "roles", "type": "string", "multiValued": true },
        { "name": "contractor", "type": "boolean", "description": "Not an employee" }
    ],
    "user.sub": {
        "10769150350006150715113082367": {
            "dept": ["eng"],
            "roles": { "values": ["a", "b"], "expires_at": "2026-09-22T15:00:00Z" },
            "contractor": []
        }
    },
    "device.zpr.adapter.cn": {
        "laptop.zpr.org": {}
    }
}"#;

/// The spec's `POST {url}/query` request example, verbatim.
fn spec_query_request() -> Value {
    json!({
        "identities": {
            "user.sub": "10769150350006150715113082367",
            "user.zpr.authority": "google",
            "device.zpr.adapter.cn": "laptop.zpr.org"
        },
        "attributes": ["dept", "roles", "contractor"]
    })
}

/// The spec's `POST {url}/query` response example, verbatim.
fn spec_query_response() -> Value {
    json!({
        "attributes": {
            "dept":       { "values": ["eng"] },
            "roles":      { "values": ["a", "b"], "expires_at": "2026-09-22T15:00:00Z" },
            "contractor": { "values": [] }
        }
    })
}

/// The spec's `GET {url}/schema` response example, verbatim.
fn spec_schema_response() -> Value {
    json!({
        "identityKeys": ["user.sub", "device.zpr.adapter.cn"],
        "attributes": [
            { "name": "dept", "type": "string", "multiValued": false,
              "description": "Cost centre", "canonicalValues": ["eng", "sales", "ops"] },
            { "name": "roles", "type": "string", "multiValued": true },
            { "name": "contractor", "type": "boolean", "description": "Not an employee" }
        ]
    })
}

/// A router over `data_json` guarded by [TOKEN].
fn router_over(data_json: &str) -> axum::Router {
    let data = AttrData::from_json_str(data_json).expect("test data must parse");
    app(AppState {
        data: Arc::new(data),
        token: TOKEN.to_string(),
    })
}

/// Drive one request through the router in-process and return the status
/// and the response body decoded as JSON (None when the body is empty).
async fn exchange(
    router: axum::Router,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Option<Value>) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed = if bytes.is_empty() {
        None
    } else {
        serde_json::from_slice(&bytes).ok()
    };
    (status, parsed)
}

/// Shorthand: an authorized POST /query with `body`.
async fn query(router: axum::Router, body: Value) -> (StatusCode, Option<Value>) {
    exchange(router, "POST", "/query", Some(TOKEN), Some(body)).await
}

// --- POST /query -----------------------------------------------------------

/// The spec's own request/response example, byte-for-byte: the JSON shapes
/// match exactly (`serde_json::Value` equality), and the exchange is
/// documented and schema-valid in the OpenAPI rendering.
#[tokio::test]
async fn test_query_spec_example_byte_for_byte() {
    let (status, body) = query(router_over(SPEC_DATA), spec_query_request()).await;
    assert_eq!(status, StatusCode::OK);
    let body = body.expect("a 200 must carry a JSON body");
    assert_eq!(body, spec_query_response());
    openapi::assert_exchange(&spec_query_request(), "/query", "post", 200, Some(&body));
}

/// The `attributes` hint is honoured: a stored attribute not named in the
/// hint is omitted from the response (the spec allows a server to use the
/// hint to prune; this server does, so the E1 fixture stays minimal).
#[tokio::test]
async fn test_query_attributes_hint_honoured() {
    let (status, body) = query(
        router_over(SPEC_DATA),
        json!({
            "identities": { "user.sub": "10769150350006150715113082367" },
            "attributes": ["dept"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let body = body.unwrap();
    assert_eq!(
        body,
        json!({ "attributes": { "dept": { "values": ["eng"] } } })
    );
    openapi::assert_exchange(&json!({}), "/query", "post", 200, Some(&body));
}

/// Multi-identity union, the `file` store's rule: every matched entry
/// contributes its attributes; entries agreeing on a name's values collapse
/// to one answer.
#[tokio::test]
async fn test_query_multi_identity_union() {
    let data = r#"{
        "device.zpr.adapter.cn": {
            "dev.zpr.org": { "color": ["red"], "dept": ["eng"] }
        },
        "user.sub": {
            "sub-123": { "roles": ["a", "b"], "dept": ["eng"] }
        }
    }"#;
    let (status, body) = query(
        router_over(data),
        json!({
            "identities": {
                "device.zpr.adapter.cn": "dev.zpr.org",
                "user.sub": "sub-123"
            },
            "attributes": ["color", "roles", "dept"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.unwrap(),
        json!({
            "attributes": {
                "color": { "values": ["red"] },
                "roles": { "values": ["a", "b"] },
                "dept":  { "values": ["eng"] }
            }
        })
    );
}

/// Conflict: two matched identities disagreeing on an attribute's values is
/// `409` — the server must not pick a winner (the fail-closed rule of the
/// store trait, moved to the side that can see the records).
#[tokio::test]
async fn test_query_conflict_is_409() {
    let data = r#"{
        "device.zpr.adapter.cn": {
            "dev.zpr.org": { "color": ["red"] }
        },
        "user.sub": {
            "sub-conflict": { "color": ["blue"] }
        }
    }"#;
    let (status, body) = query(
        router_over(data),
        json!({
            "identities": {
                "device.zpr.adapter.cn": "dev.zpr.org",
                "user.sub": "sub-conflict"
            },
            "attributes": ["color"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    openapi::assert_exchange(&json!({}), "/query", "post", 409, body.as_ref());
}

/// `expires_at` is emitted only when the JSON entry carries one: the bare
/// array spelling (the `file` store's native form) never grows the key, and
/// the object spelling passes its stamp through verbatim.
#[tokio::test]
async fn test_query_expires_at_only_when_entry_carries_one() {
    let data = r#"{
        "user.sub": {
            "sub-123": {
                "plain":   ["x"],
                "stamped": { "values": ["y"], "expires_at": "2027-01-01T00:00:00Z" }
            }
        }
    }"#;
    let (status, body) = query(
        router_over(data),
        json!({
            "identities": { "user.sub": "sub-123" },
            "attributes": ["plain", "stamped"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.unwrap(),
        json!({
            "attributes": {
                "plain":   { "values": ["x"] },
                "stamped": { "values": ["y"], "expires_at": "2027-01-01T00:00:00Z" }
            }
        })
    );
}

/// An unknown actor is a successful, EMPTY answer — `{"attributes": {}}`,
/// never an error, matching the file store (and the spec's explicit note
/// that a 404 means "wrong URL", never "unknown actor").
#[tokio::test]
async fn test_query_unknown_actor_is_ok_empty() {
    let (status, body) = query(
        router_over(SPEC_DATA),
        json!({
            "identities": { "user.sub": "nobody" },
            "attributes": ["dept"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let body = body.unwrap();
    assert_eq!(body, json!({ "attributes": {} }));
    openapi::assert_exchange(&json!({}), "/query", "post", 200, Some(&body));
}

/// Bearer check first: a missing, malformed, or unknown token is `401` on
/// both endpoints, before the body is looked at.
#[tokio::test]
async fn test_missing_or_wrong_bearer_is_401() {
    let cases: Vec<Option<&str>> = vec![None, Some("wrong-token"), Some("")];
    for bearer in cases {
        let (status, body) = exchange(
            router_over(SPEC_DATA),
            "POST",
            "/query",
            bearer,
            Some(spec_query_request()),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "bearer={bearer:?}");
        openapi::assert_exchange(&json!({}), "/query", "post", 401, body.as_ref());

        let (status, body) = exchange(router_over(SPEC_DATA), "GET", "/schema", bearer, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "bearer={bearer:?}");
        openapi::assert_exchange(&json!({}), "/schema", "get", 401, body.as_ref());
    }
}

/// Malformed requests are `400`: not JSON at all, a missing required field,
/// an unknown field (the OpenAPI says `additionalProperties: false`), an
/// empty `identities` object (`minProperties: 1`), and a non-string
/// identity value.
#[tokio::test]
async fn test_query_malformed_is_400() {
    let cases: Vec<Value> = vec![
        json!({ "attributes": ["dept"] }),             // no identities
        json!({ "identities": { "user.sub": "s" } }),  // no attributes
        json!({ "identities": {}, "attributes": [] }), // empty identities
        json!({ "identities": { "user.sub": ["not", "a", "string"] },
                "attributes": [] }), // non-string value
        json!({ "identities": { "user.sub": "s" }, "attributes": [],
                "tenant": "smuggled" }), // unknown field
    ];
    for body in cases {
        let (status, resp) = query(router_over(SPEC_DATA), body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body={body}");
        openapi::assert_exchange(&json!({}), "/query", "post", 400, resp.as_ref());
    }

    // Not JSON at all.
    let request = Request::builder()
        .method("POST")
        .uri("/query")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("not json"))
        .unwrap();
    let response = router_over(SPEC_DATA).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// --- GET /schema -----------------------------------------------------------

/// The spec's `/schema` example, byte-for-byte: with a `_schema` key in the
/// data file, the SCIM definitions are returned verbatim (order preserved)
/// and `identityKeys` holds the data's top-level identity keys. The
/// `identityKeys` array is compared as a set — the spec presents the keys
/// in prose order while the store iterates sorted, and the field means a
/// set of keys, not a sequence.
#[tokio::test]
async fn test_schema_spec_example_byte_for_byte() {
    let (status, body) =
        exchange(router_over(SPEC_DATA), "GET", "/schema", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::OK);
    let body = body.expect("a 200 must carry a JSON body");
    assert_eq!(
        canonicalize_identity_keys(&body),
        canonicalize_identity_keys(&spec_schema_response())
    );
    openapi::assert_exchange(&json!({}), "/schema", "get", 200, Some(&body));
}

/// Without a `_schema` key the definitions are derived from the data:
/// every attribute name seen anywhere in the file, `type: string`,
/// `multiValued: true` exactly when some entry holds more than one value.
#[tokio::test]
async fn test_schema_derived_from_data_when_no_schema_key() {
    let data = r#"{
        "user.sub": {
            "sub-1": { "dept": ["eng"], "roles": ["a", "b"] },
            "sub-2": { "dept": ["sales"] }
        }
    }"#;
    let (status, body) = exchange(router_over(data), "GET", "/schema", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::OK);
    let body = body.unwrap();
    assert_eq!(
        body,
        json!({
            "identityKeys": ["user.sub"],
            "attributes": [
                { "name": "dept",  "type": "string", "multiValued": false },
                { "name": "roles", "type": "string", "multiValued": true }
            ]
        })
    );
    openapi::assert_exchange(&json!({}), "/schema", "get", 200, Some(&body));
}

/// `identityKeys` comes from the data's top-level keys — all of them, and
/// never the reserved `_schema` key.
#[tokio::test]
async fn test_schema_identity_keys_from_top_level_keys() {
    let data = r#"{
        "_schema": [],
        "device.zpr.adapter.cn": { "dev": {} },
        "user.sub": { "s": {} },
        "user.upn": { "u": {} }
    }"#;
    let (status, body) = exchange(router_over(data), "GET", "/schema", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::OK);
    let keys: Vec<String> = body.unwrap()["identityKeys"]
        .as_array()
        .expect("identityKeys must be an array")
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        keys,
        vec!["device.zpr.adapter.cn", "user.sub", "user.upn"],
        "all top-level keys, sorted, and never _schema"
    );
}

// --- reserved paths --------------------------------------------------------

/// The two reserved paths answer `501`, exactly as the OpenAPI documents:
/// they are named so no implementer takes them for something else, and a
/// visa service running `zpr-attr/1` never calls them.
#[tokio::test]
async fn test_reserved_paths_are_501() {
    let (status, body) =
        exchange(router_over(SPEC_DATA), "GET", "/stream", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    openapi::assert_exchange(&json!({}), "/stream", "get", 501, body.as_ref());

    let (status, body) = exchange(
        router_over(SPEC_DATA),
        "POST",
        "/satisfies",
        Some(TOKEN),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    openapi::assert_exchange(&json!({}), "/satisfies", "post", 501, body.as_ref());
}

// --- helpers ---------------------------------------------------------------

/// A copy of `value` with any top-level `identityKeys` array sorted, so two
/// schema responses can be compared with the key set order-insensitive and
/// everything else byte-for-byte.
fn canonicalize_identity_keys(value: &Value) -> Value {
    let mut out = value.clone();
    if let Some(keys) = out
        .get_mut("identityKeys")
        .and_then(|keys| keys.as_array_mut())
    {
        keys.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    }
    out
}

/// Lightweight structural validation of an exchange against the vendored
/// OpenAPI file — the Q1-approved approach: parse the YAML with
/// `serde_yaml`, assert the path, method and status are documented, and
/// walk the response body against the referenced schema (required fields,
/// declared types, `additionalProperties`), resolving local `$ref`s. No
/// OpenAPI-validator dependency tree.
mod openapi {
    use super::*;
    use std::sync::OnceLock;

    /// The vendored OpenAPI document, parsed once. The vendored copy's
    /// source of truth is `zl-zpr-dev-context/docs/zpr-attr-v1.openapi.yaml`
    /// (see the header comment in the file).
    fn document() -> &'static Value {
        static DOC: OnceLock<Value> = OnceLock::new();
        DOC.get_or_init(|| {
            serde_yaml::from_str(include_str!("zpr-attr-v1.openapi.yaml"))
                .expect("vendored OpenAPI file must parse as YAML")
        })
    }

    /// Assert one exchange is documented: the path exists, the method
    /// exists on it, the status code is documented (exactly, or via a
    /// `5XX`-style range), and — when a JSON body came back on a 200 — the
    /// body validates against the response's schema.
    pub fn assert_exchange(
        _request: &Value,
        path: &str,
        method: &str,
        status: u16,
        body: Option<&Value>,
    ) {
        let doc = document();
        let operation = &doc["paths"][path][method];
        assert!(
            operation.is_object(),
            "OpenAPI documents no operation {method} {path}"
        );
        let responses = operation["responses"]
            .as_object()
            .unwrap_or_else(|| panic!("no responses documented for {method} {path}"));
        let exact = status.to_string();
        let range = format!("{}XX", status / 100);
        assert!(
            responses.contains_key(&exact) || responses.contains_key(&range),
            "status {status} is not documented for {method} {path}: {:?}",
            responses.keys().collect::<Vec<_>>()
        );

        if status == 200 {
            let schema = &responses[&exact]["content"]["application/json"]["schema"];
            assert!(
                schema.is_object(),
                "200 for {method} {path} documents no application/json schema"
            );
            let body = body.unwrap_or_else(|| panic!("200 from {method} {path} must carry JSON"));
            let errors = validate(doc, schema, body, path);
            assert!(
                errors.is_empty(),
                "response body of {method} {path} violates the OpenAPI schema:\n  {}",
                errors.join("\n  ")
            );
        }
    }

    /// Resolve a local `#/components/...` reference to its target.
    fn resolve<'doc>(doc: &'doc Value, schema: &'doc Value) -> &'doc Value {
        let Some(reference) = schema["$ref"].as_str() else {
            return schema;
        };
        let mut node = doc;
        for part in reference.trim_start_matches("#/").split('/') {
            node = &node[part];
        }
        node
    }

    /// Walk `value` against `schema`, collecting mismatches: missing
    /// required fields, wrong primitive types, values outside an `enum`,
    /// undeclared properties under `additionalProperties: false`, and the
    /// same recursively through `properties`, object-schema
    /// `additionalProperties`, and array `items`.
    fn validate(doc: &Value, schema: &Value, value: &Value, at: &str) -> Vec<String> {
        let schema = resolve(doc, schema);
        let mut errors = Vec::new();

        if let Some(expected) = schema["type"].as_str() {
            let ok = match expected {
                "object" => value.is_object(),
                "array" => value.is_array(),
                "string" => value.is_string(),
                "boolean" => value.is_boolean(),
                "integer" => value.is_i64() || value.is_u64(),
                "number" => value.is_number(),
                _ => true,
            };
            if !ok {
                errors.push(format!("{at}: expected {expected}, got {value}"));
                return errors;
            }
        }

        if let Some(allowed) = schema["enum"].as_array()
            && !allowed.contains(value)
        {
            errors.push(format!("{at}: {value} is not one of {allowed:?}"));
        }

        if let Some(object) = value.as_object() {
            for required in schema["required"].as_array().into_iter().flatten() {
                let name = required.as_str().unwrap_or_default();
                if !object.contains_key(name) {
                    errors.push(format!("{at}: missing required field '{name}'"));
                }
            }
            let declared = schema["properties"].as_object();
            for (name, entry) in object {
                let child_at = format!("{at}.{name}");
                if let Some(child) = declared.and_then(|props| props.get(name)) {
                    errors.extend(validate(doc, child, entry, &child_at));
                } else {
                    match &schema["additionalProperties"] {
                        Value::Bool(false) => {
                            errors.push(format!("{at}: undeclared field '{name}'"));
                        }
                        extra if extra.is_object() => {
                            errors.extend(validate(doc, extra, entry, &child_at));
                        }
                        _ => {}
                    }
                }
            }
        }

        if let (Some(items), Some(array)) = (schema.get("items"), value.as_array()) {
            for (index, entry) in array.iter().enumerate() {
                errors.extend(validate(doc, items, entry, &format!("{at}[{index}]")));
            }
        }

        errors
    }
}

// --- fixture sanity --------------------------------------------------------

/// The fixture drives both this server and a visa service `file` store, so
/// the file-store subset of SPEC_DATA (bare arrays) must decode under the
/// store loader too — guarded here by loading it through [AttrData], whose
/// entry spelling is a superset of the file store's.
#[test]
fn test_spec_data_parses() {
    let data = AttrData::from_json_str(SPEC_DATA).expect("SPEC_DATA must parse");
    let identities: BTreeMap<String, String> = [(
        "user.sub".to_string(),
        "10769150350006150715113082367".to_string(),
    )]
    .into();
    let matched = data.lookup(&identities).expect("no conflict in SPEC_DATA");
    assert_eq!(
        matched.len(),
        3,
        "the spec actor carries dept, roles, contractor"
    );
}
