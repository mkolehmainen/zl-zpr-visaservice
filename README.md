# visa service

ZPR visa service implementation (under active development).


## Crates / Packages / Libraries

- `vs` - The ZPR Visa Service. Aka "v2vs" -- the "v2" used to differentiate it
  from the "v1", prototype visa service.
- `libeval` - The "evaluator" library used by the `vs` and `zpt`. Includes the
  code that compares a description of network traffic to policy to determine if
  a visa should be issued.
- `zpt` - ZPR Policy Tester is a command line tool for testing how `libeval`
  evaluates policy.
- `vs-admin` - CLI based administration client for the visa service. Exercises
  the HTTPS admin api of `vs`.
- `zpr-dashboard` - CLI based "GUI" dashboard for monitoring visa
  service activity.
- `admin-api-types` - Library crate for data structures used by `vs` and
  `vs-admin`.
- `integration-test` - Shell-based integration tests. Includes evaluation tests
  of `libeval` using `zpt`.
- `tools` - Helper scripts, including `zpr-pki` for PKI operations.

Most of the visa service code depends on the
[zpr-common](https://github.com/org-zpr/zpr-common.git) repository, which
defines data structures used in the NODE-VS API and the policy binary format.
This dependency is pulled automatically via git in `Cargo.toml`, so no manual 
setup is required.


## Prerequisites

- **Rust** - Edition 2024. Install via [rustup](https://rustup.rs/).
- **Make** - The build is driven by a root Cargo workspace.
- **OpenSSL** - Via the `openssl` crate.
- **Redis/Valkey** - Required at runtime by `vs`.


## To build

Run `make` or `cargo build` in this top-level directory.

Run `make test` or `cargo test` in this top-level directory to run all
the unit tests.


## Release build (prototype vs only)

Run `make release` to produce a release tarball of the visa service tools. This
builds everything, then packages the `vs`, `vs-admin`, and `zpt` binaries into
`build-release/`.


## Admin HTTPS API

The visa service (`vs`) exposes an HTTPS admin API on port 8182 by default.
The `vs-admin` command line tool consumes this API.

See [admin-http-api.txt](admin-http-api.txt) for full endpoint documentation.

## JWKS CONNECT proxy (OIDC trusted services)

An `api = "oidc"` trusted service periodically refreshes the provider's
signing keys from its `jwks_uri`. The visa service typically has no direct
internet route, so the fetch can be tunneled through an on-net HTTP
**CONNECT forward proxy** — off-the-shelf software (squid, tinyproxy,
anything that speaks `CONNECT`) fronted by a ZPR adapter. TLS runs
end-to-end from the visa service to the JWKS host; the proxy sees only
`CONNECT host:443` and ciphertext, so it can deny service but never forge
keys. It must be a forward proxy, never a reverse proxy or anything that
terminates TLS.

### Declaring the proxy in ZPLC

The proxy is an ordinary on-net service, named from the trusted-service
declaration via its `service` key:

```toml
[trusted_services.google]
api             = "oidc"
issuer          = "https://accounts.google.com"
jwks_uri        = "https://www.googleapis.com/oauth2/v3/certs"
# ... client_id, allowed_domains, seed_jwks, etc.
service         = "google-jwks-proxy"   # names the CONNECT proxy service

[protocols.tcp]
l4protocol = "TCP"
port = 3128

# The proxy itself: an ordinary on-net service. The compiler weaves the
# visa-service access rule for it; no hand-written ZPL is needed.
[services.google-jwks-proxy]
protocol = "tcp"
port = 3128
provider = [["device.zpr.adapter.cn", "proxy1.zpr"]]
```

The adapter whose CN matches the `provider` attributes docks the proxy onto
the ZPR network. Several trusted services may share one proxy.

### What the visa service does with it

On every refresh the visa service re-resolves the current provider of the
named service (providers come and go; a proxy that reconnects at a new
address is picked up on the next refresh), then issues
`CONNECT <jwks-host>:443` through it and performs ordinary TLS with the
JWKS host, verified against system roots.

Rules enforced by the visa service:

- **`jwks_uri` must be `https://` when a proxy is configured.** The
  CONNECT proxy tunnels HTTPS only; a plain-`http://` URI would bypass the
  policy-designated proxy and fetch in cleartext, so it is rejected at
  policy load.
- **Redirects are never followed.** The `jwks_uri` is pinned by policy; a
  redirect (in particular off HTTPS) fails the refresh.
- **Responses are capped at 1 MiB.** Real key sets are a few kilobytes;
  an oversized body fails the refresh.
- **Fetch failures never discard keys.** If the proxy is unreachable or
  the fetch fails, the previously cached (or policy-seeded `seed_jwks`)
  keys keep serving until a later refresh succeeds.

Omitting `service` means the visa service fetches `jwks_uri` directly and
therefore needs its own internet egress.


