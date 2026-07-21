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
fn config_add_refuses_silent_replacement_and_allows_explicit_replace() {
    let dir = TempDir::new("config");
    let config = dir.join("canary.json");
    let pcrs = dir.join("trusted_hashes.json");
    write_trusted_pcrs(&pcrs);

    let first = run(&[
        "config",
        "add",
        "--config",
        path_arg(&config),
        "--node-id",
        "caution-canary-demo",
        "--id",
        "payments-prod",
        "--name",
        "Payments production",
        "--attestation-url",
        "https://payments.example.com/attestation",
        "--pcrs-file",
        path_arg(&pcrs),
    ]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let baseline = std::fs::read(&config).unwrap();

    let refused = run(&[
        "config",
        "add",
        "--config",
        path_arg(&config),
        "--id",
        "payments-prod",
        "--name",
        "Replacement",
        "--attestation-url",
        "https://payments.example.com/attestation",
        "--pcrs-file",
        path_arg(&pcrs),
    ]);
    assert!(!refused.status.success());
    assert_eq!(std::fs::read(&config).unwrap(), baseline);

    let replaced = run(&[
        "config",
        "add",
        "--config",
        path_arg(&config),
        "--id",
        "payments-prod",
        "--name",
        "Replacement",
        "--attestation-url",
        "https://payments.example.com/attestation",
        "--pcrs-file",
        path_arg(&pcrs),
        "--replace",
    ]);
    assert!(replaced.status.success());
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    assert_eq!(saved["targets"][0]["name"], "Replacement");
}

#[test]
fn seed_generate_process_enforces_nonoverwrite_and_permissions() {
    let dir = TempDir::new("seed");
    let env_file = dir.join(".env");

    let first = run(&["seed", "generate", "--env-file", path_arg(&env_file)]);
    assert!(first.status.success());
    let original = std::fs::read(&env_file).unwrap();
    assert!(String::from_utf8_lossy(&original).starts_with("CANARY_MASTER_SEED="));

    let refused = run(&["seed", "generate", "--env-file", path_arg(&env_file)]);
    assert!(!refused.status.success());
    assert_eq!(std::fs::read(&env_file).unwrap(), original);

    let forced = run(&[
        "seed",
        "generate",
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
        "--keys",
        path_arg(&keys_path),
    ]);
    assert!(
        pass.status.success(),
        "{}",
        String::from_utf8_lossy(&pass.stderr)
    );

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
        "--keys",
        path_arg(&keys_path),
    ]);
    assert!(!fail.status.success());
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
        "--pcrs-file",
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
        "--pcrs-file",
        path_arg(&pcrs_path),
    ]);
    assert!(!fail.status.success());
    assert!(String::from_utf8_lossy(&fail.stderr).contains("NONCE_MISMATCH"));
}

#[test]
fn capture_rejects_insecure_url_before_network_or_write() {
    let dir = TempDir::new("capture-http");
    let config = dir.join("canary.json");
    let output = run(&[
        "capture",
        "--config",
        path_arg(&config),
        "--node-id",
        "caution-canary-demo",
        "--id",
        "payments-prod",
        "--name",
        "Payments production",
        "--attestation-url",
        "http://payments.example.com/attestation",
        "--accept-tofu",
    ]);
    assert!(!output.status.success());
    assert!(!config.exists());
}

#[test]
fn inspect_node_rejects_non_https_origin_without_writing_keys() {
    let dir = TempDir::new("inspect-http");
    let keys = dir.join("keys.json");
    let output = run(&[
        "inspect-node",
        "--url",
        "http://canary.example.com",
        "--keys-out",
        path_arg(&keys),
    ]);
    assert!(!output.status.success());
    assert!(!keys.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("HTTPS origin"));
}
