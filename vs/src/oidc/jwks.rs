//! JWKS key source for OIDC trusted services (OIDC master plan C3).
//!
//! Cached signing keys for one provider: seeded from policy (`seed_jwks`),
//! refreshed periodically and on unknown `kid`, and never discarded on fetch
//! failure (stale tolerance). Refresh optionally tunnels through a
//! policy-designated CONNECT proxy so the visa service needs no direct
//! internet route.

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use jsonwebtoken::jwk::JwkSet;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use zpr::policy_types::OidcConfig;

    /// The C2 fixture JWKS (kid "k1").
    fn seed_jwks_json() -> &'static str {
        include_str!("../../tests/data/oidc-test-jwks.json")
    }

    /// The fixture key re-labelled kid "k2" — same key material, different
    /// id; enough to observe a refresh replacing the cached set.
    fn k2_jwks_json() -> String {
        let mut v: serde_json::Value = serde_json::from_str(seed_jwks_json()).unwrap();
        v["keys"][0]["kid"] = serde_json::json!("k2");
        v.to_string()
    }

    fn kids(set: &JwkSet) -> Vec<String> {
        set.keys
            .iter()
            .filter_map(|k| k.common.key_id.clone())
            .collect()
    }

    fn cfg(seed: &str, jwks_uri: &str, proxy_service: Option<&str>) -> OidcConfig {
        OidcConfig {
            issuer: "https://accounts.google.com".to_string(),
            jwks_uri: jwks_uri.to_string(),
            client_id: "test-client-id.apps.googleusercontent.com".to_string(),
            seed_jwks: seed.to_string(),
            jwks_proxy_service: proxy_service.map(|s| s.to_string()),
            ..OidcConfig::default()
        }
    }

    /// Plain-HTTP axum server answering `status`/`body` on `/jwks`.
    async fn spawn_jwks_server(status: StatusCode, body: String) -> SocketAddr {
        let app = axum::Router::new().route(
            "/jwks",
            axum::routing::get(move || {
                let body = body.clone();
                async move { (status, body) }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    /// TLS JWKS responder for the CONNECT test. reqwest tunnels TLS
    /// end-to-end through the proxy (that is the point of the assertion), so
    /// the upstream behind the tunnel must speak TLS; the returned
    /// certificate is handed to the client as an extra trust root.
    async fn spawn_tls_jwks_server(body: String) -> (SocketAddr, reqwest::Certificate) {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let client_cert = reqwest::Certificate::from_pem(ck.cert.pem().as_bytes()).unwrap();
        let chain = vec![ck.cert.der().clone()];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()),
        );
        let tls_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let body = body.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    // Read the request head (tiny GET; stop at the blank line).
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match tls.read(&mut byte).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => head.push(byte[0]),
                        }
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (addr, client_cert)
    }

    /// CONNECT-speaking stub proxy (written to be liftable for D5): records
    /// each connection's request line, answers `HTTP/1.1 200` to a CONNECT,
    /// then splices bytes to `upstream`. Anything that is not a CONNECT is
    /// recorded and dropped.
    async fn spawn_connect_stub(
        upstream: SocketAddr,
    ) -> (SocketAddr, mpsc::UnboundedReceiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    return;
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match client.read(&mut byte).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => head.push(byte[0]),
                        }
                    }
                    let head = String::from_utf8_lossy(&head);
                    let first = head.lines().next().unwrap_or_default().to_string();
                    let is_connect = first.starts_with("CONNECT ");
                    let _ = tx.send(first);
                    if !is_connect {
                        return;
                    }
                    let Ok(mut server) = TcpStream::connect(upstream).await else {
                        return;
                    };
                    if client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                });
            }
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn test_seed_serves_before_first_fetch() {
        // No server is started: the seed alone must serve.
        let c = cfg(seed_jwks_json(), "https://idp.invalid/jwks", None);
        let ks = KeySource::from_policy(&c, None).unwrap();
        assert_eq!(kids(&ks.current()), vec!["k1".to_string()]);
    }

    #[tokio::test]
    async fn test_refresh_replaces_keys() {
        let addr = spawn_jwks_server(StatusCode::OK, k2_jwks_json()).await;
        let c = cfg(seed_jwks_json(), &format!("http://{addr}/jwks"), None);
        let ks = KeySource::from_policy(&c, None).unwrap();
        ks.refresh().await.unwrap();
        let got = kids(&ks.current());
        assert!(got.contains(&"k2".to_string()), "{got:?}");
        assert!(
            !got.contains(&"k1".to_string()),
            "fetched set must replace the seed-only view: {got:?}"
        );
    }

    #[tokio::test]
    async fn test_refresh_failure_keeps_stale_keys() {
        let addr = spawn_jwks_server(StatusCode::INTERNAL_SERVER_ERROR, String::new()).await;
        let c = cfg(seed_jwks_json(), &format!("http://{addr}/jwks"), None);
        let ks = KeySource::from_policy(&c, None).unwrap();
        ks.refresh().await.unwrap_err();
        // Stale tolerance: the pre-failure keys keep serving.
        assert_eq!(kids(&ks.current()), vec!["k1".to_string()]);
    }

    #[tokio::test]
    async fn test_refresh_via_connect_proxy() {
        let (upstream, cert) = spawn_tls_jwks_server(k2_jwks_json()).await;
        let (proxy_addr, mut lines) = spawn_connect_stub(upstream).await;
        let c = cfg(
            seed_jwks_json(),
            &format!("https://127.0.0.1:{}/jwks", upstream.port()),
            Some("egress-proxy"),
        );
        let proxy_url = reqwest::Url::parse(&format!("http://{proxy_addr}")).unwrap();
        let mut ks = KeySource::from_policy(&c, Some(proxy_url)).unwrap();
        // Trust the test server's self-signed cert; production uses system roots.
        ks.extra_roots.push(cert);
        ks.refresh().await.unwrap();
        assert!(kids(&ks.current()).contains(&"k2".to_string()));

        let mut seen = Vec::new();
        while let Ok(l) = lines.try_recv() {
            seen.push(l);
        }
        assert_eq!(
            seen.len(),
            1,
            "proxy must see exactly one request: {seen:?}"
        );
        assert!(
            seen[0].starts_with(&format!("CONNECT 127.0.0.1:{} ", upstream.port())),
            "expected a CONNECT to the upstream, got: {:?}",
            seen[0]
        );
        assert!(
            !seen.iter().any(|l| l.starts_with("GET ")),
            "a plaintext GET through the proxy would expose the request: {seen:?}"
        );
    }

    #[tokio::test]
    async fn test_no_seed_no_route_is_nokeys() {
        // Policy demands a proxy, none is connected, and the seed is empty.
        let c = cfg("", "https://idp.invalid/jwks", Some("egress-proxy"));
        let err = KeySource::from_policy(&c, None).unwrap_err();
        assert!(matches!(err, OidcError::NoKeys), "{err}");
        // Likewise with no fetch route at all (empty jwks_uri, no proxy).
        let c2 = cfg("", "", None);
        let err2 = KeySource::from_policy(&c2, None).unwrap_err();
        assert!(matches!(err2, OidcError::NoKeys), "{err2}");
    }
}
