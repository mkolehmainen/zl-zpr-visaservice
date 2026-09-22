//! Shared fixtures for trusted-service unit tests.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zpr::policy_types::parse_attribute_mapping;

use super::attribute_mapper::AttributeMapper;

/// Build a mapper covering single-valued, multi-valued, and tag attributes.
pub(super) fn test_mapper() -> AttributeMapper {
    AttributeMapper {
        mappings: [
            "color -> user.color",
            "roles -> user.role{}",
            "lazy -> #user.lazy",
        ]
        .iter()
        .map(|mapping| parse_attribute_mapping(mapping).unwrap())
        .collect(),
    }
}

/// Write a named JSON fixture into the system temporary directory.
pub(super) fn write_fixture(name: &str, contents: &str) -> PathBuf {
    let fp = std::env::temp_dir().join(name);
    fs::write(&fp, contents).unwrap();
    fp
}

/// One request the mock attribute server recorded, for on-the-wire
/// assertions: the method and path, the bearer token presented in the
/// `Authorization` header, and the raw request body.
#[derive(Debug, Clone)]
pub(crate) struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub bearer: Option<String>,
    pub body: String,
}

/// Chooses the mock server's answer to one request: `(status, JSON body)`.
pub(crate) type AttrResponder = Arc<dyn Fn(&RecordedRequest) -> (u16, String) + Send + Sync>;

/// A running in-process TLS `zpr-attr/1` mock (the `spawn_tls_jwks_server`
/// pattern): its base `url`, the self-signed certificate PEM a client must
/// pin to reach it, and every request it has served, in order.
pub(crate) struct AttrMockServer {
    pub url: String,
    pub cert_pem: String,
    pub requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

/// Spawn a TLS server for `zpr-attr/1` store tests. Every request is parsed
/// (method, path, bearer, body), recorded, optionally delayed by
/// `delay_secs` (to exercise the client timeout), and answered by
/// `respond`. The task ends with the test runtime.
pub(crate) async fn spawn_tls_attr_server(
    respond: AttrResponder,
    delay_secs: Option<u64>,
) -> AttrMockServer {
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let cert_pem = ck.cert.pem();
    let chain = vec![ck.cert.der().clone()];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        ck.signing_key.serialize_der(),
    ));
    let tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));

    let recorded = requests.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let respond = respond.clone();
            let recorded = recorded.clone();
            tokio::spawn(async move {
                // A client that rejects our certificate (the pin-mismatch
                // case) fails the handshake here; nothing to record.
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                // Read the request head, byte by byte, up to the blank line.
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match tls.read(&mut byte).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => head.push(byte[0]),
                    }
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let mut lines = head.split("\r\n");
                let request_line = lines.next().unwrap_or_default();
                let mut parts = request_line.split(' ');
                let method = parts.next().unwrap_or_default().to_string();
                let path = parts.next().unwrap_or_default().to_string();
                let mut bearer = None;
                let mut content_length = 0usize;
                for line in lines {
                    let Some((name, value)) = line.split_once(':') else {
                        continue;
                    };
                    let value = value.trim();
                    match name.to_ascii_lowercase().as_str() {
                        "authorization" => {
                            bearer = value.strip_prefix("Bearer ").map(str::to_string);
                        }
                        "content-length" => content_length = value.parse().unwrap_or(0),
                        _ => {}
                    }
                }
                let mut body = vec![0u8; content_length];
                if content_length > 0 && tls.read_exact(&mut body).await.is_err() {
                    return;
                }
                let request = RecordedRequest {
                    method,
                    path,
                    bearer,
                    body: String::from_utf8_lossy(&body).to_string(),
                };
                recorded.lock().unwrap().push(request.clone());
                if let Some(secs) = delay_secs {
                    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
                }
                let (status, response_body) = respond(&request);
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });

    AttrMockServer {
        url: format!("https://127.0.0.1:{}", addr.port()),
        cert_pem,
        requests,
    }
}
