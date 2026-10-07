//! zipline#184: `vs --min-compiler-version` prints the minimum policy compiler
//! version (MAJOR.MINOR.PATCH) on one line and exits 0, before logging, config
//! load, identity or ValKey — so it works on a host with none of them.

use std::process::Command;

#[test]
fn min_compiler_version_prints_version_and_exits() {
    // Empty working directory: no vs.toml, nothing else to load.
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_vs"))
        .arg("--min-compiler-version")
        .current_dir(dir.path())
        .output()
        .expect("failed to run vs");

    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        out.status.success(),
        "vs --min-compiler-version must exit 0, got {:?}; stdout={stdout:?} stderr={stderr:?}",
        out.status
    );
    assert!(
        stderr.is_empty(),
        "no log noise expected on stderr: {stderr:?}"
    );

    // Exactly one line: MAJOR.MINOR.PATCH followed by a newline.
    let line = stdout
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("stdout must end in a newline: {stdout:?}"));
    let parts: Vec<&str> = line.split('.').collect();
    assert_eq!(parts.len(), 3, "expected MAJOR.MINOR.PATCH, got {stdout:?}");
    for p in &parts {
        assert!(
            !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()),
            "expected numeric MAJOR.MINOR.PATCH, got {stdout:?}"
        );
    }
}
