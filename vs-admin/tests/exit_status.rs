//! Process-level exit-status contract for `vs-admin` (zipline#38 review).
//!
//! Shell automation keys off the exit code: a failed subcommand MUST exit
//! nonzero, or a deploy script will keep going believing a hot policy
//! install (or any other admin action) succeeded when the service rejected
//! it. These tests drive the real binary via CARGO_BIN_EXE and assert on
//! `ExitStatus` only — no visa service is required because every case fails
//! before or at the connection attempt.

use std::process::Command;

/// A CA cert that parses, so argument handling proceeds past TLS setup.
const CA_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ca.crt");

fn vs_admin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vs-admin"));
    // Isolate from the environment so resolve_api_key sees only our args.
    cmd.env_remove("VS_API_KEY");
    cmd
}

/// `install` with a policy file that does not exist must exit nonzero.
/// This is the exact case from the review: the executor returns Err, and
/// main must propagate that to the process exit status.
#[test]
fn install_missing_policy_file_exits_nonzero() {
    let out = vs_admin()
        .args([
            "--svc-url",
            "https://[::1]:1", // never reached: the file open fails first
            "--ca-cert",
            CA_CERT,
            "--api-key",
            "test-key",
            "install",
            "/nonexistent/policy.zplc",
        ])
        .output()
        .expect("failed to spawn vs-admin");
    assert!(
        !out.status.success(),
        "install with a missing policy file must exit nonzero, got {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Any subcommand whose executor returns Err must exit nonzero — `network`
/// against an unreachable service is the cheapest representative.
#[test]
fn failed_request_exits_nonzero() {
    let out = vs_admin()
        .args([
            "--svc-url",
            "https://[::1]:1", // nothing listens on port 1
            "--ca-cert",
            CA_CERT,
            "--api-key",
            "test-key",
            "network",
        ])
        .output()
        .expect("failed to spawn vs-admin");
    assert!(
        !out.status.success(),
        "a failed admin request must exit nonzero, got {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Missing api key is already an explicit exit(1); pin that behaviour.
#[test]
fn missing_api_key_exits_nonzero() {
    let out = vs_admin()
        .args([
            "--svc-url",
            "https://[::1]:1",
            "--ca-cert",
            CA_CERT,
            "network",
        ])
        .output()
        .expect("failed to spawn vs-admin");
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(1));
}

/// Guard the other direction: a purely local success path still exits 0.
#[test]
fn help_exits_zero() {
    let out = vs_admin()
        .arg("--help")
        .output()
        .expect("failed to spawn vs-admin");
    assert!(out.status.success());
}
