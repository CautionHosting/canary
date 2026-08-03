//! Shared config-file loading/upsert/writing logic for trusted-PCR and TOFU
//! `deployment add` flows (spec §15 steps 2a/2b).

use std::path::Path;

use anyhow::{bail, Context, Result};
use canary_core::canonical::digest_canonical;
use canary_core::config::{
    Config, ExpectedPcrs, Target, DEFAULT_HISTORY_LIMIT, DEFAULT_PROBE_INTERVAL_SECONDS,
};
use serde::Deserialize;

use crate::atomic_file;

/// The `.caution/trusted_hashes.json` shape produced by `caution verify
/// --save-pcrs` (spec §15 step 1). Extra fields such as `verified_at` are
/// allowed and ignored.
#[derive(Debug, Deserialize)]
pub struct TrustedHashesFile {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
}

impl TrustedHashesFile {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading PCRs file {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing PCRs file {}", path.display()))
    }

    pub fn into_expected_pcrs(self) -> ExpectedPcrs {
        ExpectedPcrs {
            pcr0: self.pcr0,
            pcr1: self.pcr1,
            pcr2: self.pcr2,
        }
    }
}

/// Load `path` as a `Config` if it exists, otherwise start a fresh empty one
/// rooted at `node_id`. `node_id` is required (and used) only when the file
/// does not yet exist; if the file exists its own `node_id` is kept.
pub fn load_or_create_config(path: &Path, node_id: Option<&str>) -> Result<Config> {
    if path.exists() {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let config: Config = serde_json::from_str(&text)
            .with_context(|| format!("parsing config {}", path.display()))?;
        Ok(config)
    } else {
        let node_id = node_id.context(
            "config file does not exist yet; --canary-id is required to create a new one",
        )?;
        Ok(Config {
            version: 0,
            node_id: node_id.to_string(),
            probe_interval_seconds: DEFAULT_PROBE_INTERVAL_SECONDS,
            history_limit: DEFAULT_HISTORY_LIMIT,
            targets: Vec::new(),
        })
    }
}

/// Insert or replace a target in `config`. Errors if the id already exists
/// and `replace` is false.
pub fn upsert_target(config: &mut Config, target: Target, replace: bool) -> Result<()> {
    if let Some(existing) = config.targets.iter_mut().find(|t| t.id == target.id) {
        if !replace {
            bail!(
                "deployment {:?} already exists in config; pass --replace to overwrite it",
                target.id
            );
        }
        *existing = target;
    } else {
        config.targets.push(target);
    }
    Ok(())
}

/// Validate `config`, then write it back to `path` as pretty JSON and return
/// its `config_digest`. Does not write anything if validation fails.
pub fn validate_and_write(path: &Path, config: &Config) -> Result<String> {
    config
        .validate()
        .with_context(|| "config failed validation; not writing")?;

    let digest = digest_canonical(config).context("computing config_digest")?;
    let pretty =
        serde_json::to_string_pretty(config).context("serializing config to pretty JSON")? + "\n";
    atomic_file::write(path, pretty.as_bytes(), 0o644)
        .with_context(|| format!("writing config {}", path.display()))?;

    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path(name: &str) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("canaryctl-config-test-{name}-{n}.json"))
    }

    fn valid_pcr(byte: u8) -> String {
        hex::encode([byte; 48])
    }

    fn sample_target(id: &str) -> Target {
        Target {
            id: id.to_string(),
            name: "Payments production".to_string(),
            attestation_url: "https://payments.example.com/attestation".to_string(),
            e2e_mode: None,
            expected_pcrs: ExpectedPcrs {
                pcr0: valid_pcr(0xaa),
                pcr1: valid_pcr(0xbb),
                pcr2: valid_pcr(0xcc),
            },
        }
    }

    #[test]
    fn creates_new_config_and_round_trips() {
        let path = temp_path("new");
        let mut config = load_or_create_config(&path, Some("caution-canary-demo")).unwrap();
        upsert_target(&mut config, sample_target("payments-prod"), false).unwrap();
        let digest = validate_and_write(&path, &config).unwrap();
        assert!(digest.starts_with("sha256:"));

        let reloaded = load_or_create_config(&path, None).unwrap();
        assert_eq!(reloaded, config);
        assert_eq!(reloaded.targets.len(), 1);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn missing_canary_id_for_new_file_errors() {
        let path = temp_path("missing-canary-id");
        let err = load_or_create_config(&path, None).unwrap_err();
        assert!(err.to_string().contains("--canary-id"));
    }

    #[test]
    fn duplicate_id_without_replace_errors() {
        let mut config = load_or_create_config(&temp_path("dup"), Some("node")).unwrap();
        upsert_target(&mut config, sample_target("payments-prod"), false).unwrap();
        let err = upsert_target(&mut config, sample_target("payments-prod"), false).unwrap_err();
        assert!(err.to_string().contains("--replace"));
    }

    #[test]
    fn duplicate_id_with_replace_overwrites() {
        let mut config = load_or_create_config(&temp_path("replace"), Some("node")).unwrap();
        upsert_target(&mut config, sample_target("payments-prod"), false).unwrap();
        let mut replacement = sample_target("payments-prod");
        replacement.name = "Renamed".to_string();
        upsert_target(&mut config, replacement, true).unwrap();
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.targets[0].name, "Renamed");
    }

    #[test]
    fn invalid_config_is_not_written() {
        let path = temp_path("invalid");
        let mut config = load_or_create_config(&path, Some("bad node!")).unwrap();
        upsert_target(&mut config, sample_target("payments-prod"), false).unwrap();
        assert!(validate_and_write(&path, &config).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn trusted_hashes_file_ignores_extra_fields() {
        let path = temp_path("hashes").with_extension("json");
        std::fs::write(
            &path,
            serde_json::json!({
                "pcr0": valid_pcr(0x01),
                "pcr1": valid_pcr(0x02),
                "pcr2": valid_pcr(0x03),
                "verified_at": "2026-07-17T00:00:00Z",
            })
            .to_string(),
        )
        .unwrap();
        let loaded = TrustedHashesFile::load(&path).unwrap();
        assert_eq!(loaded.pcr0, valid_pcr(0x01));
        std::fs::remove_file(&path).unwrap();
    }
}
