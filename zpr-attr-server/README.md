# zpr-attr-server

The reference implementation of the `zpr-attr/1` attribute-service
protocol: a small HTTPS server that answers a ZPR visa service's
`POST /query` and `GET /schema` from a `file`-store JSON, plus a notify
mode that posts a `changed` notification to a visa service.

**This is a development and test tool, not a product binary.** It exists as
the executable example for `zpr-attr/1` implementers, the fixture for the
end-to-end test tier, and a second implementation that keeps the protocol
honest. The only normative reference for the protocol is
`zl-zpr-dev-context/docs/ATTRIBUTE_SERVICE.md` ("The wire protocol"); the
OpenAPI rendering vendored at `tests/zpr-attr-v1.openapi.yaml` is
non-normative, and the contract tests in `tests/contract.rs` hold this
server to both.

## Serve mode

```sh
zpr-attr-server --listen 127.0.0.1:8443 \
                --cert server.pem --key server.key \
                --token-file query.token \
                --data attrs.json
```

- `--cert` / `--key`: the server's TLS credentials (PEM). TLS is mandatory
  in `zpr-attr/1`.
- `--token-file`: the one bearer token allowed to query, trimmed of
  surrounding whitespace. Everything else is `401`.
- `--data`: the attribute data, in **exactly the visa service `file`
  store's JSON format** (identity key -> identity value -> attribute name
  -> values), so one fixture drives both a `file` store and this server.
  Two server-only extensions:
  - an optional top-level `_schema` key: an array of SCIM 2.0 attribute
    definitions returned verbatim by `GET /schema`. Absent, definitions
    are derived from the data (`type: string`, `multiValued` when any
    entry holds more than one value).
  - an entry may be spelled `{"values": [...], "expires_at": "<RFC 3339>"}`
    instead of a bare array when its `/query` answer should carry an
    `expires_at`.

Lookup follows the `file` store's union-and-conflict rule: every matched
identity contributes its attributes, and two matched records disagreeing on
a value is `409` — the server never picks a winner. An unknown actor is a
successful `{"attributes": {}}`.

## Notify mode

Simulates an attribute change by calling the visa service admin API
(`POST /admin/services/{id}/changed`) and exiting:

```sh
# Targeted: these actors changed.
zpr-attr-server --notify user.sub=sub-123 \
                --vs-url https://vs:8021 --vs-service zipline \
                --vs-api-key-file notify.key --vs-ca-cert vs-ca.pem

# Everything changed (empty body {}).
zpr-attr-server --notify \
                --vs-url https://vs:8021 --vs-service zipline \
                --vs-api-key-file notify.key --vs-ca-cert vs-ca.pem
```

The API key should be a `notify`-level key bound to the trusted-service id
(`vsapikey ... --service <id>`). Success is the admin API's `202` and
nothing else.
