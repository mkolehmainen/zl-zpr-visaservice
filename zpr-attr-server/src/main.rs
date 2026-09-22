//! The `zpr-attr-server` binary: serve a file-store JSON over `zpr-attr/1`,
//! or post a `changed` notification to a visa service. A development and
//! test tool, not a product binary — `docs/ATTRIBUTE_SERVICE.md` is the
//! only normative reference.

/// Stub entry point (zipline#80 step 1); step 3 implements serving and
/// `--notify`.
fn main() -> std::process::ExitCode {
    eprintln!("zpr-attr-server: not implemented yet (zipline#80 step 3)");
    std::process::ExitCode::FAILURE
}
