//! Phase C1 (gate test) — the production `tabeliao publish` CLI must
//! emit a SignedRoot with `algorithm=Ed25519` when invoked through
//! the default code path.
//!
//! Audit (2026-05-09) showed `Cmd::Publish` only constructed
//! `Blake3Signer` despite docs claiming Ed25519 was production. This
//! test pins the new default + the file-based key-source against
//! regression: any future PR that re-defaults to Blake3 or breaks
//! `--signing-key-file` fails CI.
//!
//! It also pins one negative invariant: when no key is supplied via
//! either `--signing-key-file` or `--signing-key`, the binary exits
//! non-zero (no silent default-to-zero-key path).

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    // cargo puts test-built binaries next to integration test deps.
    PathBuf::from(env!("CARGO_BIN_EXE_tabeliao"))
}

fn write_temp(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.as_file_mut().write_all(content.as_bytes()).unwrap();
    f
}

#[test]
fn publish_without_any_signing_key_exits_nonzero() {
    let manifest = write_temp(r#"{"schemaVersion":2}"#);
    let cfg = write_temp(
        r#"
kind: oci-image
name: x
version: 0.0.1
publisher_id: t@pleme.io
org: pleme-io
attestation: {}
"#,
    );
    let out = Command::new(binary_path())
        .args([
            "publish",
            "--manifest", manifest.path().to_str().unwrap(),
            "--config", cfg.path().to_str().unwrap(),
            "--cartorio", "http://localhost:0",
            "--lacre", "http://localhost:0",
            "--image", "x/y",
            "--reference", "v1",
        ])
        .env_remove("TABELIAO_SIGNING_KEY")
        .env_remove("TABELIAO_SIGNING_KEY_FILE")
        .output()
        .unwrap();
    assert!(!out.status.success(), "must exit non-zero w/o signing key");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no signing key supplied")
            || stderr.contains("required arguments were not provided")
            || stderr.contains("--signing-key"),
        "expected helpful error about missing key, got: {stderr}",
    );
}

#[test]
fn publish_with_inline_blake3_warns_and_uses_blake3() {
    // Blake3 is still allowed but should warn. We can't easily inspect
    // the resulting wire signature without a live cartorio, but we can
    // confirm the binary accepts the flag without erroring at parse.
    let cfg = write_temp(
        r#"
kind: oci-image
name: x
version: 0.0.1
publisher_id: t@pleme.io
org: pleme-io
attestation: {}
"#,
    );
    let manifest = write_temp(r#"{"schemaVersion":2}"#);
    // Use unreachable cartorio/lacre; we just want to validate the
    // signer-construction codepath, not the network round-trip.
    let out = Command::new(binary_path())
        .args([
            "publish",
            "--manifest", manifest.path().to_str().unwrap(),
            "--config", cfg.path().to_str().unwrap(),
            "--cartorio", "http://127.0.0.1:1",
            "--lacre", "http://127.0.0.1:1",
            "--image", "x/y",
            "--reference", "v1",
            "--algorithm", "blake3",
            "--signing-key", &"a".repeat(64),
        ])
        .env_remove("TABELIAO_SIGNING_KEY")
        .env_remove("TABELIAO_SIGNING_KEY_FILE")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Blake3 keyed-HMAC")
            || stderr.contains("blake3")
            || stderr.contains("WARN"),
        "expected Blake3 deprecation warning, got: {stderr}",
    );
}

#[test]
fn publish_default_algorithm_is_ed25519_when_signing_key_file_supplied() {
    // Build a real key file, run publish with default algorithm.
    // Same network-failure pattern: we want to validate that the
    // signer construction succeeds + the algorithm choice is Ed25519.
    let mut keyfile = tempfile::NamedTempFile::new().unwrap();
    // Use a deterministic non-zero private key.
    keyfile.as_file_mut().write_all(b"01".repeat(32).as_slice()).unwrap();
    let cfg = write_temp(
        r#"
kind: oci-image
name: x
version: 0.0.1
publisher_id: t@pleme.io
org: pleme-io
attestation: {}
"#,
    );
    let manifest = write_temp(r#"{"schemaVersion":2}"#);
    let out = Command::new(binary_path())
        .args([
            "publish",
            "--manifest", manifest.path().to_str().unwrap(),
            "--config", cfg.path().to_str().unwrap(),
            "--cartorio", "http://127.0.0.1:1",
            "--lacre", "http://127.0.0.1:1",
            "--image", "x/y",
            "--reference", "v1",
            "--signing-key-file", keyfile.path().to_str().unwrap(),
        ])
        .env_remove("TABELIAO_SIGNING_KEY")
        .env_remove("TABELIAO_SIGNING_KEY_FILE")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The binary should log the Ed25519 path BEFORE attempting the
    // network call. We only assert we see the signing-algorithm log,
    // not that publish succeeded (it can't reach cartorio).
    assert!(
        stderr.contains("Ed25519")
            || stderr.contains("signing with Ed25519")
            || stderr.contains("publisher Ed25519 public key"),
        "expected Ed25519 production-path log, got stderr: {stderr}",
    );
}

#[test]
fn publish_with_stdin_signing_key_succeeds() {
    // Phase C2 — the most-secure key source. Pipe a key on stdin;
    // the binary should accept it (and proceed to attempt the network
    // call). We assert the Ed25519 path is selected — the same way
    // we assert it for --signing-key-file.
    let cfg = write_temp(
        r#"
kind: oci-image
name: x
version: 0.0.1
publisher_id: t@pleme.io
org: pleme-io
attestation: {}
"#,
    );
    let manifest = write_temp(r#"{"schemaVersion":2}"#);
    use std::process::Stdio;
    let mut child = Command::new(binary_path())
        .args([
            "publish",
            "--manifest", manifest.path().to_str().unwrap(),
            "--config", cfg.path().to_str().unwrap(),
            "--cartorio", "http://127.0.0.1:1",
            "--lacre", "http://127.0.0.1:1",
            "--image", "x/y",
            "--reference", "v1",
            "--signing-key-stdin",
        ])
        .env_remove("TABELIAO_SIGNING_KEY")
        .env_remove("TABELIAO_SIGNING_KEY_FILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        // Trailing newline simulates `cofre apply | ...` style pipe.
        stdin.write_all(b"01".repeat(32).as_slice()).unwrap();
        stdin.write_all(b"\n").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Ed25519")
            || stderr.contains("publisher Ed25519 public key"),
        "expected Ed25519 production-path log via --signing-key-stdin, stderr: {stderr}",
    );
}

#[test]
fn publish_with_stdin_rejects_non_hex_garbage() {
    // Garbage on stdin must fail with a clear key-parse error, not
    // panic, not silently default to a zero key.
    let cfg = write_temp(
        r#"
kind: oci-image
name: x
version: 0.0.1
publisher_id: t@pleme.io
org: pleme-io
attestation: {}
"#,
    );
    let manifest = write_temp(r#"{"schemaVersion":2}"#);
    use std::process::Stdio;
    let mut child = Command::new(binary_path())
        .args([
            "publish",
            "--manifest", manifest.path().to_str().unwrap(),
            "--config", cfg.path().to_str().unwrap(),
            "--cartorio", "http://127.0.0.1:1",
            "--lacre", "http://127.0.0.1:1",
            "--image", "x/y",
            "--reference", "v1",
            "--signing-key-stdin",
        ])
        .env_remove("TABELIAO_SIGNING_KEY")
        .env_remove("TABELIAO_SIGNING_KEY_FILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"this-is-not-a-hex-key\n").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success(), "garbage stdin must exit non-zero");
}

#[test]
fn stdin_and_inline_are_mutually_exclusive() {
    let cfg = write_temp(
        r#"
kind: oci-image
name: x
version: 0.0.1
publisher_id: t@pleme.io
org: pleme-io
attestation: {}
"#,
    );
    let manifest = write_temp(r#"{"schemaVersion":2}"#);
    let out = Command::new(binary_path())
        .args([
            "publish",
            "--manifest", manifest.path().to_str().unwrap(),
            "--config", cfg.path().to_str().unwrap(),
            "--cartorio", "http://127.0.0.1:1",
            "--lacre", "http://127.0.0.1:1",
            "--image", "x/y",
            "--reference", "v1",
            "--signing-key-stdin",
            "--signing-key", &"a".repeat(64),
        ])
        .env_remove("TABELIAO_SIGNING_KEY")
        .env_remove("TABELIAO_SIGNING_KEY_FILE")
        .output()
        .unwrap();
    assert!(!out.status.success(), "stdin + inline must be rejected");
}

#[test]
fn signing_key_file_and_inline_are_mutually_exclusive() {
    let cfg = write_temp(
        r#"
kind: oci-image
name: x
version: 0.0.1
publisher_id: t@pleme.io
org: pleme-io
attestation: {}
"#,
    );
    let manifest = write_temp(r#"{"schemaVersion":2}"#);
    let mut keyfile = tempfile::NamedTempFile::new().unwrap();
    keyfile.as_file_mut().write_all(b"01".repeat(32).as_slice()).unwrap();
    let out = Command::new(binary_path())
        .args([
            "publish",
            "--manifest", manifest.path().to_str().unwrap(),
            "--config", cfg.path().to_str().unwrap(),
            "--cartorio", "http://127.0.0.1:1",
            "--lacre", "http://127.0.0.1:1",
            "--image", "x/y",
            "--reference", "v1",
            "--signing-key-file", keyfile.path().to_str().unwrap(),
            "--signing-key", &"a".repeat(64),
        ])
        .env_remove("TABELIAO_SIGNING_KEY")
        .env_remove("TABELIAO_SIGNING_KEY_FILE")
        .output()
        .unwrap();
    assert!(!out.status.success(), "must reject double key supply");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot be used with")
            || stderr.contains("conflicts")
            || stderr.contains("mutually exclusive"),
        "expected clap mutual-exclusion error, got: {stderr}",
    );
}
