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
fn add_target_refuses_silent_replacement_and_allows_explicit_replace() {
    let dir = TempDir::new("config");
    let config = dir.join("canary.json");
    let pcrs = dir.join("trusted_hashes.json");
    write_trusted_pcrs(&pcrs);

    let first = run(&[
        "add-target",
        "--config",
        path_arg(&config),
        "--canary-id",
        "caution-canary-demo",
        "--id",
        "payments-prod",
        "--name",
        "Payments production",
        "--attestation-url",
        "https://payments.example.com/attestation",
        "--expected-pcrs",
        path_arg(&pcrs),
    ]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let baseline = std::fs::read(&config).unwrap();

    let refused = run(&[
        "add-target",
        "--config",
        path_arg(&config),
        "--id",
        "payments-prod",
        "--name",
        "Replacement",
        "--attestation-url",
        "https://payments.example.com/attestation",
        "--expected-pcrs",
        path_arg(&pcrs),
    ]);
    assert!(!refused.status.success());
    assert_eq!(std::fs::read(&config).unwrap(), baseline);

    let replaced = run(&[
        "add-target",
        "--config",
        path_arg(&config),
        "--id",
        "payments-prod",
        "--name",
        "Replacement",
        "--attestation-url",
        "https://payments.example.com/attestation",
        "--expected-pcrs",
        path_arg(&pcrs),
        "--replace",
    ]);
    assert!(replaced.status.success());
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    assert_eq!(saved["targets"][0]["name"], "Replacement");
}

#[test]
fn add_target_accepts_only_caddy_with_independently_supplied_pcrs() {
    let dir = TempDir::new("caddy-config");
    let config = dir.join("canary.json");
    let pcrs = dir.join("trusted_hashes.json");
    write_trusted_pcrs(&pcrs);

    let added = run(&[
        "add-target",
        "--config",
        path_arg(&config),
        "--canary-id",
        "caution-canary-demo",
        "--id",
        "payments-prod",
        "--attestation-url",
        "https://payments.example.com/attestation",
        "--e2e-mode",
        "caddy",
        "--expected-pcrs",
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
        "add-target",
        "--id",
        "other",
        "--attestation-url",
        "https://other.example.com/attestation",
        "--e2e-mode",
        "steve",
        "--expected-pcrs",
        path_arg(&pcrs),
    ]);
    assert!(!unknown.status.success());

    let tofu = run(&[
        "add-target",
        "--id",
        "other",
        "--attestation-url",
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
fn create_signing_seed_enforces_nonoverwrite_and_permissions() {
    let dir = TempDir::new("seed");
    let env_file = dir.join(".env");

    let first = run(&["create-signing-seed", "--output", path_arg(&env_file)]);
    assert!(first.status.success());
    let original = std::fs::read(&env_file).unwrap();
    assert!(String::from_utf8_lossy(&original).starts_with("CANARY_MASTER_SEED="));

    let refused = run(&["create-signing-seed", "--output", path_arg(&env_file)]);
    assert!(!refused.status.success());
    assert_eq!(std::fs::read(&env_file).unwrap(), original);

    let forced = run(&[
        "create-signing-seed",
        "--output",
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
        "verify-statement",
        "--statement",
        path_arg(&statement_path),
        "--trusted-keys",
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
        "verify-statement",
        "--statement",
        path_arg(&statement_path),
        "--trusted-keys",
        path_arg(&keys_path),
    ]);
    assert!(json_pass.status.success());
    let rendered: serde_json::Value = serde_json::from_slice(&json_pass.stdout).unwrap();
    assert_eq!(rendered["schema_version"], 1);
    assert_eq!(rendered["command"], "artifact.verify-statement");
    assert_eq!(rendered["ok"], true);
    assert!(rendered["result"]["partial"].as_bool().unwrap());

    let legacy_pass = run(&[
        "artifact",
        "verify-statement",
        "--statement",
        path_arg(&statement_path),
        "--keys",
        path_arg(&keys_path),
    ]);
    assert!(legacy_pass.status.success());

    let mut tampered = statement;
    tampered.signers[0].signatures[0].sig = "A".to_string();
    std::fs::write(
        &statement_path,
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();
    let fail = run(&[
        "verify-statement",
        "--statement",
        path_arg(&statement_path),
        "--trusted-keys",
        path_arg(&keys_path),
    ]);
    assert!(!fail.status.success());
}

#[test]
fn json_and_verbose_are_mutually_exclusive() {
    let output = run(&["--json", "--verbose", "create-signing-seed"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
}

#[test]
fn parsed_json_errors_are_one_json_object() {
    let output = run(&[
        "--json",
        "verify-evidence",
        "--evidence",
        "/definitely/missing/evidence.json",
        "--expected-pcrs",
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
fn watch_exposes_separate_explicit_local_testing_flags() {
    let output = run(&["watch", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--skip-canary-attestation"));
    assert!(help.contains("--allow-http-canary"));
    assert!(help.contains("--allow-http-webhooks"));
    assert!(!help.contains("--insecure"));
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
        "verify-evidence",
        "--evidence",
        path_arg(&evidence_path),
        "--expected-pcrs",
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
        "verify-evidence",
        "--evidence",
        path_arg(&evidence_path),
        "--expected-pcrs",
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
        "add-target",
        "--config",
        path_arg(&config),
        "--canary-id",
        "caution-canary-demo",
        "--id",
        "payments-prod",
        "--name",
        "Payments production",
        "--attestation-url",
        "http://payments.example.com/attestation",
        "--tofu",
        "--accept-tofu",
    ]);
    assert!(!output.status.success());
    assert!(!config.exists());
}

#[test]
fn save_canary_keys_rejects_non_https_origin_without_writing_keys() {
    let dir = TempDir::new("inspect-http");
    let keys = dir.join("keys.json");
    let pcrs = dir.join("trusted_hashes.json");
    let output = run(&[
        "save-canary-keys",
        "--canary-url",
        "http://canary.example.com",
        "--expected-pcrs",
        path_arg(&pcrs),
        "--output",
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

    let save_keys = run(&[
        "save-canary-keys",
        "--canary-url",
        "https://canary.example.com",
        "--output",
        path_arg(&keys),
    ]);
    assert!(!save_keys.status.success());
    let save_keys_error = String::from_utf8_lossy(&save_keys.stderr);
    assert!(save_keys_error.contains("--expected-pcrs"));
    assert!(save_keys_error.contains("--skip-canary-attestation"));

    let evidence = run(&["verify-evidence", "--evidence", path_arg(&evidence)]);
    assert!(!evidence.status.success());
    let evidence_error = String::from_utf8_lossy(&evidence.stderr);
    assert!(evidence_error.contains("--expected-pcrs"));

    let live = run(&["verify", "--canary-url", "https://canary.example.com"]);
    assert!(!live.status.success());
    let live_error = String::from_utf8_lossy(&live.stderr);
    assert!(live_error.contains("--expected-pcrs"));
    assert!(live_error.contains("--skip-canary-attestation"));

    let history = run(&[
        "verify-attempt",
        "--canary-url",
        "https://canary.example.com",
        "--target",
        "payments-prod",
        "--attempt",
        "1",
    ]);
    assert!(!history.status.success());
    let history_error = String::from_utf8_lossy(&history.stderr);
    assert!(history_error.contains("--expected-pcrs"));
    assert!(history_error.contains("--skip-canary-attestation"));
}

#[test]
fn explicit_local_flags_preserve_the_existing_trust_boundary() {
    let dir = TempDir::new("explicit-local-flags");
    let output = dir.join("keys.json");
    let pcrs = dir.join("trusted_hashes.json");

    let allow_without_skip = run(&[
        "save-canary-keys",
        "--canary-url",
        "http://localhost:8080",
        "--allow-http",
        "--output",
        path_arg(&output),
    ]);
    assert!(!allow_without_skip.status.success());
    assert!(String::from_utf8_lossy(&allow_without_skip.stderr)
        .contains("--allow-http requires --skip-canary-attestation"));

    let conflicting_modes = run(&[
        "save-canary-keys",
        "--canary-url",
        "https://canary.example.com",
        "--expected-pcrs",
        path_arg(&pcrs),
        "--skip-canary-attestation",
        "--output",
        path_arg(&output),
    ]);
    assert!(!conflicting_modes.status.success());
    assert!(String::from_utf8_lossy(&conflicting_modes.stderr)
        .contains("exactly one of --expected-pcrs or --skip-canary-attestation"));

    let http_without_permission = run(&[
        "save-canary-keys",
        "--canary-url",
        "http://localhost:8080",
        "--skip-canary-attestation",
        "--output",
        path_arg(&output),
    ]);
    assert!(!http_without_permission.status.success());
    assert!(String::from_utf8_lossy(&http_without_permission.stderr)
        .contains("--canary-url must be an HTTPS origin"));

    let watch_http_without_skip = run(&[
        "watch",
        "--allow-http-canary",
        "--config",
        "/definitely/missing/canary-watch.json",
    ]);
    assert!(!watch_http_without_skip.status.success());
    assert!(String::from_utf8_lossy(&watch_http_without_skip.stderr)
        .contains("--allow-http-canary requires --skip-canary-attestation"));
}

#[test]
fn new_commands_preserve_schema_v1_json_identifiers() {
    let dir = TempDir::new("json-command-identifiers");
    let env_file = dir.join(".env");
    let seed = run(&[
        "--json",
        "create-signing-seed",
        "--output",
        path_arg(&env_file),
    ]);
    assert!(seed.status.success());
    let rendered: serde_json::Value = serde_json::from_slice(&seed.stdout).unwrap();
    assert_eq!(rendered["schema_version"], 1);
    assert_eq!(rendered["command"], "identity.create");

    let config = dir.join("canary.json");
    let pcrs = dir.join("trusted_hashes.json");
    write_trusted_pcrs(&pcrs);
    let target = run(&[
        "--json",
        "add-target",
        "--config",
        path_arg(&config),
        "--canary-id",
        "caution-canary-demo",
        "--id",
        "payments-prod",
        "--attestation-url",
        "https://payments.example.com/attestation",
        "--expected-pcrs",
        path_arg(&pcrs),
    ]);
    assert!(target.status.success());
    let rendered: serde_json::Value = serde_json::from_slice(&target.stdout).unwrap();
    assert_eq!(rendered["schema_version"], 1);
    assert_eq!(rendered["command"], "deployment.add");
    assert_eq!(rendered["result"]["deployment"], "payments-prod");
}

#[test]
fn top_level_help_is_flat_and_hides_compatibility_commands() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    let visible_commands = help
        .lines()
        .skip_while(|line| *line != "Commands:")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(visible_commands.len(), 8, "unexpected command list: {help}");
    let mut previous = 0;
    for command in [
        "add-target",
        "create-signing-seed",
        "save-canary-keys",
        "verify",
        "verify-attempt",
        "watch",
        "verify-statement",
        "verify-evidence",
    ] {
        let position = help.find(command).unwrap();
        assert!(position >= previous, "{command} is out of workflow order");
        previous = position;
    }
    for legacy in ["deployment", "identity", "enroll", "artifact"] {
        assert!(!help
            .lines()
            .any(|line| line.trim_start().starts_with(legacy)));
    }
    assert!(!visible_commands
        .iter()
        .any(|line| line.trim_start().starts_with("help")));
}

#[test]
fn verify_help_uses_singular_target_and_keeps_history_separate() {
    let output = run(&["verify", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--target <TARGET>"));
    assert!(!help.contains("--targets"));
    assert!(!help.contains("--attempt"));
    assert!(!help.contains("--deployment"));
}

#[test]
fn legacy_commands_and_flags_remain_hidden_compatibility_aliases() {
    for legacy_help in [
        &["deployment", "add", "--help"][..],
        &["identity", "create", "--help"][..],
        &["enroll", "--help"][..],
        &["artifact", "verify-statement", "--help"][..],
        &["artifact", "verify-evidence", "--help"][..],
    ] {
        assert!(run(legacy_help).status.success());
    }

    let dir = TempDir::new("legacy-seed");
    let env_file = dir.join(".env");
    let output = run(&["identity", "create", "--env-file", path_arg(&env_file)]);
    assert!(output.status.success());
    assert!(env_file.exists());

    let config = dir.join("canary.json");
    let pcrs = dir.join("trusted_hashes.json");
    write_trusted_pcrs(&pcrs);
    let output = run(&[
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
        "--pcrs",
        path_arg(&pcrs),
    ]);
    assert!(output.status.success());
    assert!(config.exists());

    let keys = dir.join("keys.json");
    let canonical = run(&[
        "save-canary-keys",
        "--canary-url",
        "not-a-url",
        "--skip-canary-attestation",
        "--allow-http",
        "--output",
        path_arg(&keys),
    ]);
    let legacy = run(&[
        "enroll",
        "--url",
        "not-a-url",
        "--insecure",
        "--keys",
        path_arg(&keys),
    ]);
    assert_eq!(legacy.status, canonical.status);
    assert_eq!(legacy.stderr, canonical.stderr);

    let missing_evidence = dir.join("missing-evidence.json");
    let canonical = run(&[
        "verify-evidence",
        "--evidence",
        path_arg(&missing_evidence),
        "--expected-pcrs",
        path_arg(&pcrs),
    ]);
    let legacy = run(&[
        "artifact",
        "verify-evidence",
        "--evidence",
        path_arg(&missing_evidence),
        "--pcrs",
        path_arg(&pcrs),
    ]);
    assert_eq!(legacy.status, canonical.status);
    assert_eq!(legacy.stderr, canonical.stderr);

    let missing_watch = dir.join("missing-watch.json");
    let canonical = run(&[
        "watch",
        "--config",
        path_arg(&missing_watch),
        "--skip-canary-attestation",
        "--allow-http-canary",
        "--allow-http-webhooks",
    ]);
    let legacy = run(&["watch", "--config", path_arg(&missing_watch), "--insecure"]);
    assert_eq!(legacy.status, canonical.status);
    assert_eq!(legacy.stderr, canonical.stderr);
}

#[test]
fn verify_attempt_requires_one_target_and_positive_attempt_before_network_access() {
    let no_target = run(&[
        "verify-attempt",
        "--canary-url",
        "https://canary.example.com",
        "--skip-canary-attestation",
        "--attempt",
        "1",
    ]);
    assert!(!no_target.status.success());
    assert!(String::from_utf8_lossy(&no_target.stderr).contains("--target"));

    let two_targets = run(&[
        "verify-attempt",
        "--canary-url",
        "https://canary.example.com",
        "--skip-canary-attestation",
        "--target",
        "one",
        "--target",
        "two",
        "--attempt",
        "1",
    ]);
    assert!(!two_targets.status.success());

    let non_positive = run(&[
        "verify-attempt",
        "--canary-url",
        "https://canary.example.com",
        "--skip-canary-attestation",
        "--target",
        "one",
        "--attempt",
        "0",
    ]);
    assert!(!non_positive.status.success());
    assert!(String::from_utf8_lossy(&non_positive.stderr).contains("positive history ID"));
}

#[test]
fn legacy_verify_attempt_flags_remain_compatible() {
    let no_target = run(&[
        "verify",
        "--url",
        "https://canary.example.com",
        "--insecure",
        "--attempt",
        "1",
    ]);
    assert!(!no_target.status.success());
    assert!(String::from_utf8_lossy(&no_target.stderr).contains("exactly one --target"));

    let two_targets = run(&[
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
    assert!(!two_targets.status.success());
    assert!(String::from_utf8_lossy(&two_targets.stderr).contains("exactly one --target"));
}
