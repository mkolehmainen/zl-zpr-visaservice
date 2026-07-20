# AGENTS.md

## Repo Map
Rust workspace with main crate `vs` (visa service) and supporting crates:
`libeval`, `zpt`, `vs-admin`, `admin-api-types`.
(`zpr-common` is in a separate repository.)

## Coding Style
- Prefer to not duplicate code. Use helper functions when possible.
- For refactors/renames, search usages across all crates in this workspace.
- Never patch a failing test you didn't write unless explicitly told to do so.
- Any functions written (include tests) should have a brief comment explaining what they do.

## Required Rust Workflow
- After Rust edits: run `cargo build` and fix errors.
- Then run `cargo fmt -- --check` and fix formatting.
- Run `cargo test` when tests exist or are relevant.

## Project Note
- ZPR addresses are IPv6 and must use prefix `fd5a:5052`.
- This is early release code so we do not care about migrating existing database state.