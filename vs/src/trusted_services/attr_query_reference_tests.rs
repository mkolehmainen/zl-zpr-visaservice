//! V1 <-> V3 integration: the visa service's `AttrQueryStore` (zipline#78)
//! against the REAL `zpr-attr-server` (zipline#80) — router, hyper and
//! rustls included — running on an in-process loopback TLS listener. The
//! unit tests in `attr_query_store.rs` exercise the store against a
//! hand-rolled mock; this module proves the two shipped implementations of
//! `zpr-attr/1` actually interoperate: attributes served from a file-store
//! JSON come back mapped through the store trait, and a server-side
//! conflict (`409`) surfaces as the store's fail-closed error.

use std::sync::Arc;

use zpr::policy_types::{AttrQueryConfig, TrustedService, parse_attribute_mapping};
use zpr_attr_server::router::AppState;
use zpr_attr_server::serve::{serve_with_listener, tls_acceptor_from_pem};
use zpr_attr_server::store::AttrData;

use super::TrustedServiceInterface;
use super::attr_query_store::AttrQueryStore;

/// The reference server's data set: the spec's example actor plus a device
/// entry whose record conflicts with the user entry on `dept`.
const DATA: &str = r#"{
    "user.sub": {
        "sub-123": {
            "dept": ["eng"],
            "roles": ["a", "b"],
            "contractor": []
        }
    },
    "device.zpr.adapter.cn": {
        "conflicting.zpr.org": {
            "dept": ["sales"]
        }
    }
}"#;

/// Start the real `zpr-attr-server` on 127.0.0.1:0 with a fresh self-signed
/// certificate; return its base URL and the certificate PEM to pin.
async fn start_reference_server(data_json: &str, token: &str) -> (String, String) {
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let cert_pem = ck.cert.pem();
    let key_pem = ck.signing_key.serialize_pem();
    let acceptor = tls_acceptor_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())
        .expect("acceptor must build from rcgen PEM");
    let data = AttrData::from_json_str(data_json).expect("test data must parse");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState {
        data: Arc::new(data),
        token: token.to_string(),
    };
    tokio::spawn(serve_with_listener(listener, acceptor, state));
    (format!("https://127.0.0.1:{}", addr.port()), cert_pem)
}

/// An `api = "zpr-attr/1"` policy record pointing at `url`, pinned to
/// `ca_pem`, with the spec's three mapping spellings.
fn record(url: &str, ca_pem: &str) -> TrustedService {
    TrustedService {
        service_id: "attrs".to_string(),
        expiration_seconds: 3600,
        returns_attrs: [
            "dept -> user.dept",
            "roles -> user.role{}",
            "contractor -> #user.contractor",
        ]
        .iter()
        .map(|mapping| parse_attribute_mapping(mapping).unwrap())
        .collect(),
        identity_attrs: vec![],
        oidc: None,
        attr_query: Some(AttrQueryConfig {
            url: url.to_string(),
            ca_cert_pem: Some(ca_pem.to_string()),
            timeout_seconds: 5,
        }),
    }
}

/// An `AttrQueryStore` against the reference server: build the store from
/// a policy record and a secrets dir holding `attrs.token`.
fn store_against(url: &str, ca_pem: &str, token: &str) -> (tempfile::TempDir, AttrQueryStore) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("attrs.token"), token).unwrap();
    let store = AttrQueryStore::new(&record(url, ca_pem), dir.path()).unwrap();
    (dir, store)
}

/// Happy path across the wire: the file-store JSON served by the reference
/// server comes back through `get_attributes_for_actor` mapped to ZPR keys
/// — single-valued, multi-valued and tag — stamped with the store's id.
#[tokio::test]
async fn test_attr_query_store_against_reference_server() {
    let (url, ca_pem) = start_reference_server(DATA, "integration-token").await;
    let (_dir, store) = store_against(&url, &ca_pem, "integration-token");

    let attrs = store
        .get_attributes_for_actor(&[("user.sub".to_string(), "sub-123".to_string())])
        .await
        .expect("the two implementations must interoperate");

    let mut by_key: Vec<(&str, Vec<String>)> = attrs
        .iter()
        .map(|attr| (attr.get_key(), attr.get_value().to_vec()))
        .collect();
    by_key.sort();
    assert_eq!(
        by_key,
        vec![
            ("user.dept", vec!["eng".to_string()]),
            ("user.role", vec!["a".to_string(), "b".to_string()]),
            ("user.zpr.tag.contractor", Vec::<String>::new()),
        ]
    );
    for attr in &attrs {
        assert_eq!(attr.get_source(), "attrs");
    }

    // An unknown actor is a successful, empty answer end to end.
    let attrs = store
        .get_attributes_for_actor(&[("user.sub".to_string(), "nobody".to_string())])
        .await
        .unwrap();
    assert!(attrs.is_empty());
}

/// A server-side conflict (two matched identities disagreeing on `dept`)
/// is the server's `409`, and `409` is the store's fail-closed error: the
/// actor becomes indeterminate, never a coin flip.
#[tokio::test]
async fn test_conflict_fails_closed_across_the_wire() {
    let (url, ca_pem) = start_reference_server(DATA, "integration-token").await;
    let (_dir, store) = store_against(&url, &ca_pem, "integration-token");

    let result = store
        .get_attributes_for_actor(&[
            ("user.sub".to_string(), "sub-123".to_string()),
            (
                "device.zpr.adapter.cn".to_string(),
                "conflicting.zpr.org".to_string(),
            ),
        ])
        .await;
    assert!(
        result.is_err(),
        "a 409 from the reference server must fail closed in the store"
    );
}

/// The store's bearer token is checked by the real server: a wrong token
/// is the server's `401`, which is the store's fail-closed error.
#[tokio::test]
async fn test_wrong_token_fails_closed_across_the_wire() {
    let (url, ca_pem) = start_reference_server(DATA, "integration-token").await;
    let (_dir, store) = store_against(&url, &ca_pem, "wrong-token");

    let result = store
        .get_attributes_for_actor(&[("user.sub".to_string(), "sub-123".to_string())])
        .await;
    assert!(result.is_err(), "a 401 must fail closed in the store");
}
