//! The `zpr-attr-server` binary: serve a file-store JSON over `zpr-attr/1`
//! (TLS), or post a `changed` notification to a visa service and exit. A
//! development and test tool, not a product binary —
//! `docs/ATTRIBUTE_SERVICE.md` is the only normative reference.
//!
//! Serve mode:
//!
//! ```text
//! zpr-attr-server --listen 127.0.0.1:8443 --cert server.pem --key server.key \
//!                 --token-file query.token --data attrs.json
//! ```
//!
//! Notify mode (the operator's and the e2e tier's way to simulate an
//! attribute change; spec: "Change notification"):
//!
//! ```text
//! zpr-attr-server --notify user.sub=sub-123 \
//!                 --vs-url https://vs:8021 --vs-service zipline \
//!                 --vs-api-key-file notify.key --vs-ca-cert vs-ca.pem
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use zpr_attr_server::router::AppState;
use zpr_attr_server::serve;
use zpr_attr_server::store::AttrData;

/// Reference implementation of the `zpr-attr/1` attribute-service protocol.
/// A development and test tool, not a product binary.
#[derive(Debug, Parser)]
#[command(name = "zpr-attr-server", version)]
struct Args {
    /// Address to serve `zpr-attr/1` on (serve mode).
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,

    /// PEM file with the server's TLS certificate chain (serve mode).
    #[arg(long, required_unless_present = "notify")]
    cert: Option<PathBuf>,

    /// PEM file with the server's TLS private key (serve mode).
    #[arg(long, required_unless_present = "notify")]
    key: Option<PathBuf>,

    /// File holding the one bearer token allowed to query, trimmed of
    /// surrounding whitespace (serve mode).
    #[arg(long, required_unless_present = "notify")]
    token_file: Option<PathBuf>,

    /// The attribute data: a visa service `file`-store JSON, plus the
    /// optional `_schema` key and the `{"values": ..., "expires_at": ...}`
    /// entry spelling (serve mode).
    #[arg(long, required_unless_present = "notify")]
    data: Option<PathBuf>,

    /// Notify mode: post a `changed` notification to a visa service and
    /// exit. Each value is one `<zpr key>=<value>` identity pair; with no
    /// pairs the body is `{}` ("everything changed").
    #[arg(long, num_args = 0.., value_name = "IDENTITY=VALUE")]
    notify: Option<Vec<String>>,

    /// Visa service admin base URL, e.g. `https://vs:8021` (notify mode).
    #[arg(long, requires = "notify")]
    vs_url: Option<String>,

    /// The trusted-service id this server is declared under — the `{id}` in
    /// `POST /admin/services/{id}/changed` (notify mode).
    #[arg(long, requires = "notify")]
    vs_service: Option<String>,

    /// File holding the visa service API key (a `notify`-level key bound to
    /// this service id), trimmed (notify mode).
    #[arg(long, requires = "notify")]
    vs_api_key_file: Option<PathBuf>,

    /// PEM file with the CA to trust for the visa service's TLS. Exclusive
    /// when set: system roots are disabled. Absent means system roots
    /// (notify mode).
    #[arg(long, requires = "notify")]
    vs_ca_cert: Option<PathBuf>,
}

/// Parse one `--notify` argument: `<zpr key>=<value>`, split on the FIRST
/// `=` so values may carry them.
fn parse_identity_pair(raw: &str) -> Result<(String, String), String> {
    match raw.split_once('=') {
        Some((key, value)) if !key.is_empty() && !value.is_empty() => {
            Ok((key.to_string(), value.to_string()))
        }
        _ => Err(format!("identity pair '{raw}' must be '<zpr key>=<value>'")),
    }
}

/// The `changed` request body (spec: "Change notification"): `{}` when
/// everything changed, `{"identities": [{key: value}, ...]}` targeted at
/// the actors carrying a listed pair — one single-pair object per entry.
fn notify_body(pairs: &[(String, String)]) -> Value {
    if pairs.is_empty() {
        return json!({});
    }
    let identities: Vec<Value> = pairs
        .iter()
        .map(|(key, value)| json!({ key: value }))
        .collect();
    json!({ "identities": identities })
}

/// The `changed` notification URL: `<base>/admin/services/<id>/changed`.
/// The admin API contract requires `{id}` to be URL-path encoded, and the
/// attr-query service-id validation only rejects `/` and `..` — so the id
/// is percent-encoded as one path segment here. The set is strict RFC 3986:
/// everything but unreserved characters (alphanumerics and `-._~`), which
/// keeps ordinary ids readable and makes reserved characters like `#`, `?`
/// and `%` inert.
fn notify_url(vs_url: &str, service: &str) -> String {
    /// Unreserved characters (RFC 3986 §2.3) pass through; everything else
    /// is encoded.
    const PATH_SEGMENT: &percent_encoding::AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    let encoded = utf8_percent_encode(service, PATH_SEGMENT);
    format!(
        "{}/admin/services/{encoded}/changed",
        vs_url.trim_end_matches('/')
    )
}

/// Read a secret file trimmed of surrounding whitespace; empty is an error.
fn read_secret(path: &Path, what: &str) -> Result<String, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("failed to read {what} file {path:?}: {error}"))?;
    let trimmed = contents.trim().to_string();
    if trimmed.is_empty() {
        return Err(format!("{what} file {path:?} is empty"));
    }
    Ok(trimmed)
}

/// Build the TLS acceptor from the PEM certificate chain and private key
/// files ([serve::tls_acceptor_from_pem] does the parsing).
fn tls_acceptor(cert_file: &Path, key_file: &Path) -> Result<TlsAcceptor, String> {
    let cert_pem = std::fs::read(cert_file)
        .map_err(|error| format!("failed to read cert file {cert_file:?}: {error}"))?;
    let key_pem = std::fs::read(key_file)
        .map_err(|error| format!("failed to read key file {key_file:?}: {error}"))?;
    serve::tls_acceptor_from_pem(&cert_pem, &key_pem)
}

/// Serve the router over TLS on `listen` until killed
/// ([serve::serve_with_listener] runs the accept loop).
async fn run_serve_loop(
    acceptor: TlsAcceptor,
    listen: SocketAddr,
    state: AppState,
) -> Result<(), String> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|error| format!("failed to bind {listen}: {error}"))?;
    serve::serve_with_listener(listener, acceptor, state).await;
    Ok(())
}

/// Notify mode: post `changed` to the visa service and report the status.
/// Success is the admin API's `202` and nothing else.
async fn notify(args: &Args, pairs: &[(String, String)]) -> Result<(), String> {
    let vs_url = args.vs_url.as_deref().ok_or("--notify requires --vs-url")?;
    let service = args
        .vs_service
        .as_deref()
        .ok_or("--notify requires --vs-service")?;
    let key_file = args
        .vs_api_key_file
        .as_deref()
        .ok_or("--notify requires --vs-api-key-file")?;
    let api_key = read_secret(key_file, "API key")?;

    let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    if let Some(ca_path) = &args.vs_ca_cert {
        let pem = std::fs::read(ca_path)
            .map_err(|error| format!("failed to read CA file {ca_path:?}: {error}"))?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|error| format!("CA file {ca_path:?} does not parse as PEM: {error}"))?;
        // Exclusive pin, matching the visa service's own client discipline.
        builder = builder.tls_certs_only(certs);
    }
    let client = builder
        .build()
        .map_err(|error| format!("failed to build HTTP client: {error}"))?;

    let url = notify_url(vs_url, service);
    let response = client
        .post(&url)
        .header("X-API-Key", api_key)
        .json(&notify_body(pairs))
        .send()
        .await
        .map_err(|error| format!("change notification failed: {error}"))?;
    let status = response.status();
    if status != reqwest::StatusCode::ACCEPTED {
        return Err(format!(
            "visa service answered {status} (expected 202 Accepted)"
        ));
    }
    info!("change notification accepted by {url}");
    Ok(())
}

/// Serve mode: load the data and token, build the TLS acceptor, serve.
async fn run_server(args: &Args) -> Result<(), String> {
    // clap's required_unless_present guarantees these in serve mode.
    let data_path = args.data.as_deref().expect("clap requires --data");
    let token_path = args
        .token_file
        .as_deref()
        .expect("clap requires --token-file");
    let cert_path = args.cert.as_deref().expect("clap requires --cert");
    let key_path = args.key.as_deref().expect("clap requires --key");

    let data = AttrData::load(data_path)
        .map_err(|error| format!("failed to load data file {data_path:?}: {error}"))?;
    let token = read_secret(token_path, "token")?;
    let acceptor = tls_acceptor(cert_path, key_path)?;
    run_serve_loop(
        acceptor,
        args.listen,
        AppState {
            data: Arc::new(data),
            token,
        },
    )
    .await
}

#[tokio::main]
async fn main() -> ExitCode {
    // Plain info-level logging to stderr; RUST_LOG is not consulted (a
    // development tool has no need for the env-filter feature tree).
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let args = Args::parse();

    let outcome = match &args.notify {
        Some(raw_pairs) => {
            let pairs: Result<Vec<_>, String> = raw_pairs
                .iter()
                .map(|raw| parse_identity_pair(raw))
                .collect();
            match pairs {
                Ok(pairs) => notify(&args, &pairs).await,
                Err(error) => Err(error),
            }
        }
        None => run_server(&args).await,
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            error!("{message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serve mode requires the four serve flags; notify mode does not.
    #[test]
    fn test_flag_parsing_modes() {
        // Serve mode: all four required flags present.
        let args = Args::try_parse_from([
            "zpr-attr-server",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--token-file",
            "t",
            "--data",
            "d.json",
        ])
        .unwrap();
        assert!(args.notify.is_none());
        assert_eq!(args.listen.port(), 8443);

        // Serve mode missing --data: rejected.
        assert!(
            Args::try_parse_from([
                "zpr-attr-server",
                "--cert",
                "c.pem",
                "--key",
                "k.pem",
                "--token-file",
                "t",
            ])
            .is_err()
        );

        // Notify mode: no serve flags needed; pairs are optional.
        let args = Args::try_parse_from([
            "zpr-attr-server",
            "--notify",
            "user.sub=sub-123",
            "device.zpr.adapter.cn=dev.zpr.org",
            "--vs-url",
            "https://vs:8021",
            "--vs-service",
            "zipline",
            "--vs-api-key-file",
            "notify.key",
        ])
        .unwrap();
        assert_eq!(
            args.notify.as_deref(),
            Some(
                &[
                    "user.sub=sub-123".to_string(),
                    "device.zpr.adapter.cn=dev.zpr.org".to_string()
                ][..]
            )
        );

        // Notify with no pairs: the "everything changed" form.
        let args = Args::try_parse_from([
            "zpr-attr-server",
            "--notify",
            "--vs-url",
            "https://vs:8021",
            "--vs-service",
            "zipline",
            "--vs-api-key-file",
            "notify.key",
        ])
        .unwrap();
        assert_eq!(args.notify.as_deref(), Some(&[][..]));
    }

    /// Identity pairs split on the FIRST '=', and degenerate spellings are
    /// rejected.
    #[test]
    fn test_parse_identity_pair() {
        assert_eq!(
            parse_identity_pair("user.sub=sub-123").unwrap(),
            ("user.sub".to_string(), "sub-123".to_string())
        );
        // Values may carry '='.
        assert_eq!(
            parse_identity_pair("user.sub=a=b").unwrap(),
            ("user.sub".to_string(), "a=b".to_string())
        );
        assert!(parse_identity_pair("no-equals").is_err());
        assert!(parse_identity_pair("=value").is_err());
        assert!(parse_identity_pair("key=").is_err());
    }

    /// The service id is one path segment of the notification URL, and the
    /// admin API contract requires `{id}` to be URL-path encoded: reserved
    /// characters like `#` and `?` must not change the parsed URL, and a
    /// plain id must pass through readable. (Codex review, PR #30.)
    #[test]
    fn test_notify_url_percent_encodes_service_id() {
        // A plain id is untouched, and a trailing '/' on the base is eaten.
        assert_eq!(
            notify_url("https://vs:8021/", "zipline"),
            "https://vs:8021/admin/services/zipline/changed"
        );
        // '#' would start a fragment and '?' a query: both must be encoded
        // so the '/changed' suffix stays part of the path.
        assert_eq!(
            notify_url("https://vs:8021", "svc#1"),
            "https://vs:8021/admin/services/svc%231/changed"
        );
        assert_eq!(
            notify_url("https://vs:8021", "svc?x=1"),
            "https://vs:8021/admin/services/svc%3Fx%3D1/changed"
        );
        // '/' would add a path segment; '%' must round-trip decodable.
        assert_eq!(
            notify_url("https://vs:8021", "a/b"),
            "https://vs:8021/admin/services/a%2Fb/changed"
        );
        assert_eq!(
            notify_url("https://vs:8021", "100%"),
            "https://vs:8021/admin/services/100%25/changed"
        );
    }

    /// The notify body matches the admin API contract: `{}` for everything,
    /// one single-pair object per identity otherwise.
    #[test]
    fn test_notify_body_shapes() {
        assert_eq!(notify_body(&[]), json!({}));
        assert_eq!(
            notify_body(&[
                ("user.sub".to_string(), "sub-123".to_string()),
                (
                    "device.zpr.adapter.cn".to_string(),
                    "dev.zpr.org".to_string()
                ),
            ]),
            json!({
                "identities": [
                    { "user.sub": "sub-123" },
                    { "device.zpr.adapter.cn": "dev.zpr.org" }
                ]
            })
        );
    }
}
