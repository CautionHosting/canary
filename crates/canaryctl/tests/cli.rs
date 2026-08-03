use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use canary_core::keys::{KeySet, MasterSeed};
use canary_core::statement::{sign_statement, Payload, Status, CLAIM_TYPE};
use chrono::{SecondsFormat, Timelike as _, Utc};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("canaryctl-cli-{label}-{}-{n}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_canaryctl"))
        .args(args)
        .output()
        .unwrap()
}

fn path_arg(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn version_reports_the_release_version() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "canaryctl 0.1.0\n"
    );
}

fn write_trusted_pcrs(path: &Path) {
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "pcr0": "ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03",
            "pcr1": "ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03",
            "pcr2": "21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a"
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn deployment_add_refuses_silent_replacement_and_allows_explicit_replace() {
    let dir = TempDir::new("config");
    let config = dir.join("canary.json");
    let pcrs = dir.join("trusted_hashes.json");
    write_trusted_pcrs(&pcrs);

    let first = run(&[
        "deployment",
        "add",
        "--config",
        path_arg(&config),
        "--canary-id",
        "caution-canary-demo",
        "--id",
        "payments-prod",
        "--name",
        "Payments production",
        "--url",
        "https://payments.example.com/attestation",
        "--pcrs",
        path_arg(&pcrs),
    ]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let baseline = std::fs::read(&config).unwrap();

    let refused = run(&[
        "deployment",
        "add",
        "--config",
        path_arg(&config),
        "--id",
        "payments-prod",
        "--name",
        "Replacement",
        "--url",
        "https://payments.example.com/attestation",
        "--pcrs",
        path_arg(&pcrs),
    ]);
    assert!(!refused.status.success());
    assert_eq!(std::fs::read(&config).unwrap(), baseline);

    let replaced = run(&[
        "deployment",
        "add",
        "--config",
        path_arg(&config),
        "--id",
        "payments-prod",
        "--name",
        "Replacement",
        "--url",
        "https://payments.example.com/attestation",
        "--pcrs",
        path_arg(&pcrs),
        "--replace",
    ]);
    assert!(replaced.status.success());
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    assert_eq!(saved["targets"][0]["name"], "Replacement");
}

#[test]
fn deployment_add_accepts_only_caddy_with_independently_supplied_pcrs() {
    let dir = TempDir::new("caddy-config");
    let config = dir.join("canary.json");
    let pcrs = dir.join("trusted_hashes.json");
    write_trusted_pcrs(&pcrs);

    let added = run(&[
        "deployment",
        "add",
        "--config",
        path_arg(&config),
        "--canary-id",
        "caution-canary-demo",
        "--id",
        "payments-prod",
        "--url",
        "https://payments.example.com/attestation",
        "--e2e-mode",
        "caddy",
        "--pcrs",
        path_arg(&pcrs),
    ]);
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    assert_eq!(saved["targets"][0]["e2e_mode"], "caddy");

    let unknown = run(&[
        "deployment",
        "add",
        "--id",
        "other",
        "--url",
        "https://other.example.com/attestation",
        "--e2e-mode",
        "steve",
        "--pcrs",
        path_arg(&pcrs),
    ]);
    assert!(!unknown.status.success());

    let tofu = run(&[
        "deployment",
        "add",
        "--id",
        "other",
        "--url",
        "https://other.example.com/attestation",
        "--e2e-mode",
        "caddy",
        "--tofu",
        "--accept-tofu",
    ]);
    assert!(!tofu.status.success());
    assert!(String::from_utf8_lossy(&tofu.stderr).contains("cannot be used with"));
}

#[test]
fn identity_create_process_enforces_nonoverwrite_and_permissions() {
    let dir = TempDir::new("seed");
    let env_file = dir.join(".env");

    let first = run(&["identity", "create", "--env-file", path_arg(&env_file)]);
    assert!(first.status.success());
    let original = std::fs::read(&env_file).unwrap();
    assert!(String::from_utf8_lossy(&original).starts_with("CANARY_MASTER_SEED="));

    let refused = run(&["identity", "create", "--env-file", path_arg(&env_file)]);
    assert!(!refused.status.success());
    assert_eq!(std::fs::read(&env_file).unwrap(), original);

    let forced = run(&[
        "identity",
        "create",
        "--env-file",
        path_arg(&env_file),
        "--force",
    ]);
    assert!(forced.status.success());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&env_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn offline_statement_verification_round_trips_through_cli_process() {
    let dir = TempDir::new("statement");
    let statement_path = dir.join("statement.json");
    let keys_path = dir.join("keys.json");

    let seed = MasterSeed::from_base64(&STANDARD.encode([0x33; 32])).unwrap();
    let keyset = KeySet::derive(&seed, "caution-canary-demo").unwrap();
    let issued = Utc::now().with_nanosecond(0).unwrap();
    let timestamp = issued.to_rfc3339_opts(SecondsFormat::Secs, true);
    let statement = sign_statement(
        Payload {
            claim_type: CLAIM_TYPE.to_string(),
            target_id: "payments-prod".to_string(),
            target_origin: "https://payments.example.com".to_string(),
            status: Status::Verified,
            reason: "ALL_CHECKS_PASSED".to_string(),
            config_digest: format!("sha256:{}", "a".repeat(64)),
            evidence_digest: Some(format!("sha256:{}", "b".repeat(64))),
            tls: None,
            observed_at: Some(timestamp.clone()),
            issued_at: timestamp,
            expires_at: (issued + chrono::Duration::seconds(180))
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            verifier_id: "caution-canary-demo".to_string(),
            key_epoch: 0,
        },
        &keyset,
    )
    .unwrap();
    std::fs::write(
        &statement_path,
        serde_json::to_vec_pretty(&statement).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &keys_path,
        serde_json::to_vec_pretty(&keyset.keys_document()).unwrap(),
    )
    .unwrap();

    let pass = run(&[
        "artifact",
        "verify-statement",
        "--statement",
        path_arg(&statement_path),
        "--keys",
        path_arg(&keys_path),
    ]);
    assert!(
        pass.status.success(),
        "{}",
        String::from_utf8_lossy(&pass.stderr)
    );
    assert!(String::from_utf8_lossy(&pass.stdout).contains("PARTIAL CHECK"));

    let json_pass = run(&[
        "--json",
        "artifact",
        "verify-statement",
        "--statement",
        path_arg(&statement_path),
        "--keys",
        path_arg(&keys_path),
    ]);
    assert!(json_pass.status.success());
    let rendered: serde_json::Value = serde_json::from_slice(&json_pass.stdout).unwrap();
    assert_eq!(rendered["schema_version"], 1);
    assert_eq!(rendered["command"], "artifact.verify-statement");
    assert_eq!(rendered["ok"], true);
    assert!(rendered["result"]["partial"].as_bool().unwrap());

    let mut tampered = statement;
    tampered.signers[0].signatures[0].sig = "A".to_string();
    std::fs::write(
        &statement_path,
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();
    let fail = run(&[
        "artifact",
        "verify-statement",
        "--statement",
        path_arg(&statement_path),
        "--keys",
        path_arg(&keys_path),
    ]);
    assert!(!fail.status.success());
}

#[test]
fn json_and_verbose_are_mutually_exclusive() {
    let output = run(&["--json", "--verbose", "identity", "create"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
}

#[test]
fn parsed_json_errors_are_one_json_object() {
    let output = run(&[
        "--json",
        "artifact",
        "verify-evidence",
        "--evidence",
        "/definitely/missing/evidence.json",
        "--pcrs",
        "/definitely/missing/pcrs.json",
    ]);
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let rendered: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rendered["schema_version"], 1);
    assert_eq!(rendered["ok"], false);
    assert!(rendered["error"]
        .as_str()
        .unwrap()
        .contains("evidence bundle"));
}

#[test]
fn watch_rejects_one_shot_json_output_before_loading_config() {
    let output = run(&[
        "--json",
        "watch",
        "--config",
        "/definitely/missing/canary-watch.json",
    ]);
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let rendered: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rendered["command"], "watch");
    assert!(rendered["error"]
        .as_str()
        .unwrap()
        .contains("not supported"));

    let verbose = run(&[
        "--verbose",
        "watch",
        "--config",
        "/definitely/missing/canary-watch.json",
    ]);
    assert!(!verbose.status.success());
    assert!(String::from_utf8_lossy(&verbose.stderr).contains("not supported"));
}

#[test]
fn watch_exposes_one_explicit_local_testing_flag() {
    let output = run(&["watch", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--insecure"));
    assert!(!help.contains("--insecure-canary"));
    assert!(!help.contains("--allow-http-webhooks"));
}

#[test]
fn offline_evidence_verification_uses_public_fixture_and_rejects_replay() {
    let dir = TempDir::new("evidence");
    let evidence_path = dir.join("evidence.json");
    let pcrs_path = dir.join("trusted_hashes.json");
    std::fs::write(
        &evidence_path,
        include_str!("../../canary-core/tests/data/evidence-v0-vector.json"),
    )
    .unwrap();
    write_trusted_pcrs(&pcrs_path);

    let pass = run(&[
        "artifact",
        "verify-evidence",
        "--evidence",
        path_arg(&evidence_path),
        "--pcrs",
        path_arg(&pcrs_path),
    ]);
    assert!(
        pass.status.success(),
        "{}",
        String::from_utf8_lossy(&pass.stderr)
    );

    let mut replay: serde_json::Value = serde_json::from_str(include_str!(
        "../../canary-core/tests/data/evidence-v0-vector.json"
    ))
    .unwrap();
    replay["nonce"] = serde_json::Value::String(STANDARD.encode([0x10; 32]));
    std::fs::write(&evidence_path, serde_json::to_vec_pretty(&replay).unwrap()).unwrap();
    let fail = run(&[
        "artifact",
        "verify-evidence",
        "--evidence",
        path_arg(&evidence_path),
        "--pcrs",
        path_arg(&pcrs_path),
    ]);
    assert!(!fail.status.success());
    assert!(String::from_utf8_lossy(&fail.stderr).contains("NONCE_MISMATCH"));
}

#[test]
fn capture_rejects_http_url_before_network_or_write() {
    let dir = TempDir::new("capture-http");
    let config = dir.join("canary.json");
    let output = run(&[
        "deployment",
        "add",
        "--config",
        path_arg(&config),
        "--canary-id",
        "caution-canary-demo",
        "--id",
        "payments-prod",
        "--name",
        "Payments production",
        "--url",
        "http://payments.example.com/attestation",
        "--tofu",
        "--accept-tofu",
    ]);
    assert!(!output.status.success());
    assert!(!config.exists());
}

#[test]
fn enroll_rejects_non_https_origin_without_writing_keys() {
    let dir = TempDir::new("inspect-http");
    let keys = dir.join("keys.json");
    let pcrs = dir.join("trusted_hashes.json");
    let output = run(&[
        "enroll",
        "--url",
        "http://canary.example.com",
        "--pcrs",
        path_arg(&pcrs),
        "--keys",
        path_arg(&keys),
    ]);
    assert!(!output.status.success());
    assert!(!keys.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("HTTPS origin"));
}

#[test]
fn verification_commands_require_an_explicit_trust_mode() {
    let dir = TempDir::new("trust-mode");
    let keys = dir.join("keys.json");
    let evidence = dir.join("evidence.json");

    let enroll = run(&[
        "enroll",
        "--url",
        "https://canary.example.com",
        "--keys",
        path_arg(&keys),
    ]);
    assert!(!enroll.status.success());
    let enroll_error = String::from_utf8_lossy(&enroll.stderr);
    assert!(enroll_error.contains("--pcrs"));
    assert!(enroll_error.contains("--insecure"));

    let evidence = run(&[
        "artifact",
        "verify-evidence",
        "--evidence",
        path_arg(&evidence),
    ]);
    assert!(!evidence.status.success());
    let evidence_error = String::from_utf8_lossy(&evidence.stderr);
    assert!(evidence_error.contains("--pcrs"));

    let live = run(&["verify", "--url", "https://canary.example.com"]);
    assert!(!live.status.success());
    let live_error = String::from_utf8_lossy(&live.stderr);
    assert!(live_error.contains("--pcrs"));
    assert!(live_error.contains("--insecure"));

    let history = run(&[
        "verify",
        "--url",
        "https://canary.example.com",
        "--deployment",
        "payments-prod",
        "--attempt",
        "1",
    ]);
    assert!(!history.status.success());
    let history_error = String::from_utf8_lossy(&history.stderr);
    assert!(history_error.contains("--pcrs"));
    assert!(history_error.contains("--insecure"));
}

#[test]
fn clean_break_rejects_legacy_commands_and_flags() {
    for legacy in [
        "config",
        "capture",
        "seed",
        "inspect-node",
        "verify-history",
        "verify-statement",
    ] {
        let output = run(&[legacy, "--help"]);
        assert!(
            !output.status.success(),
            "legacy command {legacy} still works"
        );
    }
    let output = run(&[
        "deployment",
        "add",
        "--id",
        "payments-prod",
        "--attestation-url",
        "https://payments.example.com/attestation",
        "--tofu",
        "--accept-tofu",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--attestation-url"));
}

#[test]
fn verify_attempt_requires_exactly_one_deployment_before_network_access() {
    let no_deployment = run(&[
        "verify",
        "--url",
        "https://canary.example.com",
        "--insecure",
        "--attempt",
        "1",
    ]);
    assert!(!no_deployment.status.success());
    assert!(String::from_utf8_lossy(&no_deployment.stderr).contains("exactly one --deployment"));

    let two_deployments = run(&[
        "verify",
        "--url",
        "https://canary.example.com",
        "--insecure",
        "--deployment",
        "one",
        "--deployment",
        "two",
        "--attempt",
        "1",
    ]);
    assert!(!two_deployments.status.success());
    assert!(String::from_utf8_lossy(&two_deployments.stderr).contains("exactly one --deployment"));
}
