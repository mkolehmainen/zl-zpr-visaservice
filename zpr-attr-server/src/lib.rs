//! `zpr-attr-server` — the reference implementation of the `zpr-attr/1`
//! attribute-service protocol (zipline#72 umbrella, task V3 / zipline#80).
//!
//! A second, deliberately small implementation of the server side of the
//! protocol: it serves a `file`-store JSON over `POST /query` and
//! `GET /schema`, and can post a `changed` notification to a visa service.
//! It exists as the executable example for implementers (zipline first), the
//! fixture for the end-to-end test tier, and the thing that keeps the spec
//! honest — the contract tests in `tests/contract.rs` hold this crate to
//! every example in the spec and to the vendored OpenAPI rendering.
//!
//! **Normative reference:** `zl-zpr-dev-context/docs/ATTRIBUTE_SERVICE.md`
//! ("The wire protocol"). The OpenAPI file in `tests/` is a non-normative
//! rendering of the same protocol. This is a development and test tool, not
//! a product binary.

pub mod router;
pub mod store;
