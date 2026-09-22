//! TLS serving of the `zpr-attr/1` router.
//!
//! In the library (not the binary) so the visa service's V1 integration
//! test can run the REAL server — router, hyper, rustls and all — on an
//! in-process loopback listener, exactly what the binary serves.

use std::sync::Arc;

use hyper::Request;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::PrivateKeyDer;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;
use tracing::{error, info, warn};

use crate::router::{AppState, app};

/// Build a TLS acceptor from PEM bytes: a certificate chain and a private
/// key — the same rustls construction the visa service's admin listener
/// uses.
pub fn tls_acceptor_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsAcceptor, String> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .map_err(|error| format!("failed to parse cert PEM: {error}"))?;
    let key: PrivateKeyDer = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|error| format!("failed to parse key PEM: {error}"))?
        .ok_or("no private key found in key PEM")?;
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| format!("failed to build TLS config: {error}"))?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Serve the `zpr-attr/1` router over TLS on an already-bound listener
/// until the task is dropped: accept, handshake, hand the connection to
/// hyper. Each failure is logged and the loop continues — a bad client
/// must not stop the server.
pub async fn serve_with_listener(listener: TcpListener, acceptor: TlsAcceptor, state: AppState) {
    let router = app(state);
    if let Ok(addr) = listener.local_addr() {
        info!("zpr-attr/1 reference server listening on {addr} (TLS)");
    }
    loop {
        let (cnx, addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                error!("accept failed: {error}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(cnx).await {
                Ok(stream) => stream,
                Err(error) => {
                    warn!("TLS handshake from {addr} failed: {error}");
                    return;
                }
            };
            let stream = TokioIo::new(stream);
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                // Clone per request: Router::call needs &mut self.
                router.clone().call(req)
            });
            if let Err(error) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(stream, service)
                .await
            {
                warn!("error serving connection from {addr}: {error}");
            }
        });
    }
}
