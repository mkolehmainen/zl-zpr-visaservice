# Visa Service (v2)

ZPR Visa Service binary written in rust.

## Prerequisites

- A running ValKey (or Redis) server. By default `vs` connects to
  `redis://127.0.0.1:6379`.
- A compiled policy file (`.bin2` format).

## To build

- `make`
- `make test` run the unit tests
- `make check` run `cargo fmt --check` and compile with warnings as errors

## To run

The `vs` has sensible defaults. If a `vs.toml` file is present in the working
directory it will be loaded automatically. See `vs.toml` for all available
options and their defaults.

To run with defaults:

```
vs /path/to/policy.bin2
```

- To use a custom configuration file: `-c my-config.toml`.
- For verbose log output: `-v`.
- To print the minimum policy compiler version this build accepts and exit:
  `--min-compiler-version` (MAJOR and MINOR must match exactly, PATCH must be
  at least the printed value).

By default, `vs` will look for TLS credentials in `admin-tls-cert.pem` and
`admin-tls-key.pem`. You can generate these:

```bash
openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out admin-tls-cert.pem -keyout admin-tls-key.pem
```

## vsapikey

This also builds the binary `vsapikey` which is used to generate API keys
for accessing the HTTPS admin api.

