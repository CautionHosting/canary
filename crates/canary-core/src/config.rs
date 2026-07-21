//! `canary.json` schema and validation (spec §6).
//!
//! `Config` is the deserialized shape of the measured configuration file.
//! `Config::validate` enforces every rule in spec §6: unique stable
//! identifiers, HTTPS-only target URLs without credentials or fragments, and
//! SHA-384-sized, canonical-lowercase, nonzero PCR0/1/2 values. Unknown
//! fields are rejected everywhere so a misspelling never silently weakens
//! policy.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Fixed PCR indices Canary cares about, in canonical order.
pub const PCR_INDICES: [u8; 3] = [0, 1, 2];

/// SHA-384 digest length in hex characters (48 bytes * 2).
const PCR_HEX_LEN: usize = 96;

/// Maximum number of targets allowed in one config (spec §6).
const MAX_TARGETS: usize = 100;

pub const DEFAULT_PROBE_INTERVAL_SECONDS: u64 = 60;
/// Must exceed canaryd's five-second jitter so successive anchored due times
/// cannot move backwards.
pub const MIN_PROBE_INTERVAL_SECONDS: u64 = 6;
pub const MAX_PROBE_INTERVAL_SECONDS: u64 = 86_400;
pub const DEFAULT_HISTORY_LIMIT: u32 = 1_000;
pub const MAX_HISTORY_LIMIT: u32 = 10_000;

const fn default_probe_interval_seconds() -> u64 {
    DEFAULT_PROBE_INTERVAL_SECONDS
}

const fn default_history_limit() -> u32 {
    DEFAULT_HISTORY_LIMIT
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub node_id: String,
    #[serde(default = "default_probe_interval_seconds")]
    pub probe_interval_seconds: u64,
    #[serde(default = "default_history_limit")]
    pub history_limit: u32,
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
    pub name: String,
    pub attestation_url: String,
    pub expected_pcrs: ExpectedPcrs,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedPcrs {
    #[serde(rename = "0")]
    pub pcr0: String,
    #[serde(rename = "1")]
    pub pcr1: String,
    #[serde(rename = "2")]
    pub pcr2: String,
}

impl ExpectedPcrs {
    /// Iterate PCR values in fixed order 0, 1, 2.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &str)> {
        [
            (0u8, self.pcr0.as_str()),
            (1u8, self.pcr1.as_str()),
            (2u8, self.pcr2.as_str()),
        ]
        .into_iter()
    }

    fn get(&self, index: u8) -> &str {
        match index {
            0 => &self.pcr0,
            1 => &self.pcr1,
            2 => &self.pcr2,
            _ => unreachable!("only PCR0/1/2 are modeled"),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("unsupported config version {0}, only 0 is supported")]
    UnsupportedVersion(u32),
    #[error("bad identifier {0:?}: must be a non-empty ASCII string of alphanumerics, '-' or '_'")]
    BadIdentifier(String),
    #[error("duplicate id {0:?}")]
    DuplicateId(String),
    #[error("at least one target is required")]
    NoTargets,
    #[error("too many targets: {0}, limit is {MAX_TARGETS}")]
    TooManyTargets(usize),
    #[error("probe_interval_seconds must be between {MIN_PROBE_INTERVAL_SECONDS} and {MAX_PROBE_INTERVAL_SECONDS}")]
    BadProbeInterval,
    #[error("history_limit must be between 1 and {MAX_HISTORY_LIMIT}")]
    BadHistoryLimit,
    #[error("target {target_id:?} has an invalid attestation_url: {reason}")]
    InvalidUrl { target_id: String, reason: String },
    #[error("target {target_id:?} attestation_url must not contain credentials")]
    UrlHasCredentials { target_id: String },
    #[error("target {target_id:?} attestation_url must not contain a fragment")]
    UrlHasFragment { target_id: String },
    #[error("target {target_id:?} attestation_url must use https")]
    NotHttps { target_id: String },
    #[error("target {target_id:?} PCR{pcr} has wrong length {len}, expected {PCR_HEX_LEN}")]
    BadPcrLength {
        target_id: String,
        pcr: u8,
        len: usize,
    },
    #[error("target {target_id:?} PCR{pcr} is not canonical lowercase hex")]
    PcrNotLowercaseHex { target_id: String, pcr: u8 },
    #[error("target {target_id:?} PCR{pcr} is all-zero, debug/zero PCR policies are rejected")]
    ZeroPcr { target_id: String, pcr: u8 },
}

pub(crate) fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn validate_pcr(target_id: &str, index: u8, hex: &str) -> Result<(), ConfigError> {
    if hex.len() != PCR_HEX_LEN {
        return Err(ConfigError::BadPcrLength {
            target_id: target_id.to_string(),
            pcr: index,
            len: hex.len(),
        });
    }
    if !hex
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(ConfigError::PcrNotLowercaseHex {
            target_id: target_id.to_string(),
            pcr: index,
        });
    }
    if hex.chars().all(|c| c == '0') {
        return Err(ConfigError::ZeroPcr {
            target_id: target_id.to_string(),
            pcr: index,
        });
    }
    Ok(())
}

/// Validate one target URL before any network request is made.
pub fn validate_attestation_url(target_id: &str, raw: &str) -> Result<(), ConfigError> {
    let url = Url::parse(raw).map_err(|e| ConfigError::InvalidUrl {
        target_id: target_id.to_string(),
        reason: e.to_string(),
    })?;
    if url.scheme() != "https" {
        return Err(ConfigError::NotHttps {
            target_id: target_id.to_string(),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::UrlHasCredentials {
            target_id: target_id.to_string(),
        });
    }
    if url.fragment().is_some() {
        return Err(ConfigError::UrlHasFragment {
            target_id: target_id.to_string(),
        });
    }
    Ok(())
}

impl Config {
    /// Validate this config against every rule in spec §6.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 0 {
            return Err(ConfigError::UnsupportedVersion(self.version));
        }
        if !is_valid_identifier(&self.node_id) {
            return Err(ConfigError::BadIdentifier(self.node_id.clone()));
        }
        if self.targets.is_empty() {
            return Err(ConfigError::NoTargets);
        }
        if self.targets.len() > MAX_TARGETS {
            return Err(ConfigError::TooManyTargets(self.targets.len()));
        }
        if !(MIN_PROBE_INTERVAL_SECONDS..=MAX_PROBE_INTERVAL_SECONDS)
            .contains(&self.probe_interval_seconds)
        {
            return Err(ConfigError::BadProbeInterval);
        }
        if !(1..=MAX_HISTORY_LIMIT).contains(&self.history_limit) {
            return Err(ConfigError::BadHistoryLimit);
        }

        let mut seen_ids = std::collections::HashSet::with_capacity(self.targets.len() + 1);
        seen_ids.insert(self.node_id.as_str());

        for target in &self.targets {
            if !is_valid_identifier(&target.id) {
                return Err(ConfigError::BadIdentifier(target.id.clone()));
            }
            if !seen_ids.insert(target.id.as_str()) {
                return Err(ConfigError::DuplicateId(target.id.clone()));
            }

            validate_attestation_url(&target.id, &target.attestation_url)?;

            for index in PCR_INDICES {
                validate_pcr(&target.id, index, target.expected_pcrs.get(index))?;
            }
        }

        Ok(())
    }
}

/// Parse and fully validate a `canary.json` document from its JSON text.
pub fn parse_and_validate(json: &str) -> Result<Config, ConfigParseError> {
    let config: Config = serde_json::from_str(json)?;
    config.validate()?;
    Ok(config)
}

#[derive(Debug, Error)]
pub enum ConfigParseError {
    #[error("failed to parse canary.json: {0}")]
    Parse(#[from] serde_json::Error),
    #[error(transparent)]
    Invalid(#[from] ConfigError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_pcr(byte: u8) -> String {
        hex::encode([byte; 48])
    }

    fn valid_config_json() -> serde_json::Value {
        serde_json::json!({
            "version": 0,
            "node_id": "caution-canary-demo",
            "targets": [
                {
                    "id": "payments-prod",
                    "name": "Payments production",
                    "attestation_url": "https://payments.example.com/attestation",
                    "expected_pcrs": {
                        "0": valid_pcr(0xaa),
                        "1": valid_pcr(0xbb),
                        "2": valid_pcr(0xcc),
                    }
                }
            ]
        })
    }

    #[test]
    fn valid_config_parses_and_validates() {
        let json = valid_config_json().to_string();
        let config = parse_and_validate(&json).expect("should validate");
        assert_eq!(config.version, 0);
        assert_eq!(config.node_id, "caution-canary-demo");
        assert_eq!(
            config.probe_interval_seconds,
            DEFAULT_PROBE_INTERVAL_SECONDS
        );
        assert_eq!(config.history_limit, DEFAULT_HISTORY_LIMIT);
        assert_eq!(config.targets.len(), 1);
    }

    #[test]
    fn runtime_limits_are_configurable_and_bounded() {
        let mut json = valid_config_json();
        json["probe_interval_seconds"] = serde_json::json!(300);
        json["history_limit"] = serde_json::json!(2_000);
        let config = parse_and_validate(&json.to_string()).unwrap();
        assert_eq!(config.probe_interval_seconds, 300);
        assert_eq!(config.history_limit, 2_000);

        json["probe_interval_seconds"] = serde_json::json!(MIN_PROBE_INTERVAL_SECONDS - 1);
        let config: Config = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::BadProbeInterval
        );

        json["probe_interval_seconds"] = serde_json::json!(60);
        json["history_limit"] = serde_json::json!(MAX_HISTORY_LIMIT + 1);
        let config: Config = serde_json::from_value(json).unwrap();
        assert_eq!(config.validate().unwrap_err(), ConfigError::BadHistoryLimit);
    }

    #[test]
    fn runtime_policy_changes_config_digest() {
        let base = parse_and_validate(&valid_config_json().to_string()).unwrap();
        let base_digest = crate::canonical::digest_canonical(&base).unwrap();

        let mut changed_interval = base.clone();
        changed_interval.probe_interval_seconds += 1;
        assert_ne!(
            crate::canonical::digest_canonical(&changed_interval).unwrap(),
            base_digest
        );

        let mut changed_history = base;
        changed_history.history_limit += 1;
        assert_ne!(
            crate::canonical::digest_canonical(&changed_history).unwrap(),
            base_digest
        );
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let mut json = valid_config_json();
        json["extra_field"] = serde_json::json!("oops");
        let err = serde_json::from_str::<Config>(&json.to_string()).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn unknown_target_field_is_rejected() {
        let mut json = valid_config_json();
        json["targets"][0]["extra"] = serde_json::json!("oops");
        let err = serde_json::from_str::<Config>(&json.to_string()).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn unknown_pcr_field_is_rejected() {
        let mut json = valid_config_json();
        json["targets"][0]["expected_pcrs"]["3"] = serde_json::json!(valid_pcr(0xdd));
        let err = serde_json::from_str::<Config>(&json.to_string()).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn missing_pcr_field_is_rejected() {
        let mut json = valid_config_json();
        json["targets"][0]["expected_pcrs"]
            .as_object_mut()
            .unwrap()
            .remove("2");
        let err = serde_json::from_str::<Config>(&json.to_string()).unwrap_err();
        assert!(err.to_string().contains("missing field"));
    }

    #[test]
    fn version_must_be_zero() {
        let mut json = valid_config_json();
        json["version"] = serde_json::json!(1);
        let config: Config = serde_json::from_str(&json.to_string()).unwrap();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::UnsupportedVersion(1)
        );
    }

    #[test]
    fn duplicate_target_id_is_rejected() {
        let mut json = valid_config_json();
        let target = json["targets"][0].clone();
        json["targets"].as_array_mut().unwrap().push(target);
        let config: Config = serde_json::from_str(&json.to_string()).unwrap();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::DuplicateId("payments-prod".to_string())
        );
    }

    #[test]
    fn node_id_colliding_with_target_id_is_rejected() {
        let mut json = valid_config_json();
        json["node_id"] = serde_json::json!("payments-prod");
        let config: Config = serde_json::from_str(&json.to_string()).unwrap();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::DuplicateId("payments-prod".to_string())
        );
    }

    #[test]
    fn zero_targets_is_rejected() {
        let mut json = valid_config_json();
        json["targets"] = serde_json::json!([]);
        let config: Config = serde_json::from_str(&json.to_string()).unwrap();
        assert_eq!(config.validate().unwrap_err(), ConfigError::NoTargets);
    }

    #[test]
    fn too_many_targets_is_rejected() {
        let mut json = valid_config_json();
        let template = json["targets"][0].clone();
        let mut targets = Vec::new();
        for i in 0..101 {
            let mut t = template.clone();
            t["id"] = serde_json::json!(format!("target-{i}"));
            targets.push(t);
        }
        json["targets"] = serde_json::json!(targets);
        let config: Config = serde_json::from_str(&json.to_string()).unwrap();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::TooManyTargets(101)
        );
    }

    #[test]
    fn http_url_is_rejected() {
        let mut json = valid_config_json();
        json["targets"][0]["attestation_url"] =
            serde_json::json!("http://payments.example.com/attestation");
        let config: Config = serde_json::from_str(&json.to_string()).unwrap();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::NotHttps {
                target_id: "payments-prod".to_string()
            }
        );
    }

    #[test]
    fn url_with_credentials_is_rejected() {
        let mut json = valid_config_json();
        json["targets"][0]["attestation_url"] =
            serde_json::json!("https://user:pass@payments.example.com/attestation");
        let config: Config = serde_json::from_str(&json.to_string()).unwrap();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::UrlHasCredentials {
                target_id: "payments-prod".to_string()
            }
        );
    }

    #[test]
    fn url_with_fragment_is_rejected() {
        let mut json = valid_config_json();
        json["targets"][0]["attestation_url"] =
            serde_json::json!("https://payments.example.com/attestation#frag");
        let config: Config = serde_json::from_str(&json.to_string()).unwrap();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::UrlHasFragment {
                target_id: "payments-prod".to_string()
            }
        );
    }

    #[test]
    fn pcr_wrong_length_is_rejected() {
        let mut json = valid_config_json();
        json["targets"][0]["expected_pcrs"]["0"] = serde_json::json!("aabb");
        let config: Config = serde_json::from_str(&json.to_string()).unwrap();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::BadPcrLength {
                target_id: "payments-prod".to_string(),
                pcr: 0,
                len: 4,
            }
        );
    }

    #[test]
    fn pcr_uppercase_hex_is_rejected() {
        let mut json = valid_config_json();
        let mut upper = valid_pcr(0xaa);
        upper.make_ascii_uppercase();
        json["targets"][0]["expected_pcrs"]["0"] = serde_json::json!(upper);
        let config: Config = serde_json::from_str(&json.to_string()).unwrap();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::PcrNotLowercaseHex {
                target_id: "payments-prod".to_string(),
                pcr: 0,
            }
        );
    }

    #[test]
    fn pcr_all_zero_is_rejected() {
        let mut json = valid_config_json();
        json["targets"][0]["expected_pcrs"]["0"] = serde_json::json!(valid_pcr(0x00));
        let config: Config = serde_json::from_str(&json.to_string()).unwrap();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::ZeroPcr {
                target_id: "payments-prod".to_string(),
                pcr: 0,
            }
        );
    }

    #[test]
    fn bad_identifier_charset_is_rejected() {
        let mut json = valid_config_json();
        json["targets"][0]["id"] = serde_json::json!("payments prod!");
        let config: Config = serde_json::from_str(&json.to_string()).unwrap();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::BadIdentifier("payments prod!".to_string())
        );
    }

    #[test]
    fn expected_pcrs_iter_is_fixed_order() {
        let pcrs = ExpectedPcrs {
            pcr0: valid_pcr(0x01),
            pcr1: valid_pcr(0x02),
            pcr2: valid_pcr(0x03),
        };
        let collected: Vec<(u8, &str)> = pcrs.iter().collect();
        assert_eq!(collected[0].0, 0);
        assert_eq!(collected[1].0, 1);
        assert_eq!(collected[2].0, 2);
    }
}
