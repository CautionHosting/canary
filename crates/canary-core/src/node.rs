//! Strict node-attestation and public config wrapper contracts (spec §7.3, §13).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::canonical::{digest_canonical, CanonicalError};
use crate::config::{is_valid_identifier, Config, ConfigError};
use crate::keys::KEY_EPOCH;

/// Protocol embedded by Bootproofd into Canary's signed Nitro user data.
pub const NODE_PROTOCOL: &str = "caution-canary-v0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeMetadata {
    pub protocol: String,
    pub node_id: String,
    pub config_digest: String,
    pub keyset_digest: String,
    pub key_epoch: u32,
}

/// Exact `/config.json` application response shape.  The configuration remains
/// the frozen Phase 1 `Config` object; this wrapper adds no policy surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigDocument {
    pub config: Config,
    pub config_digest: String,
}

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("invalid config: {0}")]
    Config(#[from] ConfigError),
    #[error("canonicalization failed: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("node metadata protocol must be {NODE_PROTOCOL:?}")]
    WrongProtocol,
    #[error("node metadata has an invalid node_id")]
    InvalidNodeId,
    #[error("node metadata key_epoch must be {KEY_EPOCH}")]
    WrongKeyEpoch,
    #[error("{field} must be a canonical sha256 digest")]
    InvalidDigest { field: &'static str },
    #[error("config_digest does not match the canonical config")]
    ConfigDigestMismatch,
}

impl NodeMetadata {
    pub fn new(
        node_id: String,
        config_digest: String,
        keyset_digest: String,
    ) -> Result<Self, NodeError> {
        let metadata = Self {
            protocol: NODE_PROTOCOL.to_string(),
            node_id,
            config_digest,
            keyset_digest,
            key_epoch: KEY_EPOCH,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Validate strict user-data contents before writing or accepting it.
    pub fn validate(&self) -> Result<(), NodeError> {
        if self.protocol != NODE_PROTOCOL {
            return Err(NodeError::WrongProtocol);
        }
        if !is_valid_identifier(&self.node_id) {
            return Err(NodeError::InvalidNodeId);
        }
        if self.key_epoch != KEY_EPOCH {
            return Err(NodeError::WrongKeyEpoch);
        }
        validate_digest("config_digest", &self.config_digest)?;
        validate_digest("keyset_digest", &self.keyset_digest)?;
        Ok(())
    }
}

impl ConfigDocument {
    pub fn new(config: Config) -> Result<Self, NodeError> {
        config.validate()?;
        let config_digest = digest_canonical(&config)?;
        Ok(Self {
            config,
            config_digest,
        })
    }

    /// Validate both the frozen config and its canonical binding digest.
    pub fn validate(&self) -> Result<(), NodeError> {
        self.config.validate()?;
        validate_digest("config_digest", &self.config_digest)?;
        if self.config_digest != digest_canonical(&self.config)? {
            return Err(NodeError::ConfigDigestMismatch);
        }
        Ok(())
    }
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), NodeError> {
    let valid = value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if valid {
        Ok(())
    } else {
        Err(NodeError::InvalidDigest { field })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn config() -> Config {
        serde_json::from_value(serde_json::json!({
            "version": 0,
            "node_id": "canary-a",
            "targets": [{
                "id": "target-a", "name": "Target", "attestation_url": "https://example.com/attestation",
                "expected_pcrs": {"0": "a".repeat(96), "1": "b".repeat(96), "2": "c".repeat(96)}
            }]
        })).unwrap()
    }

    #[test]
    fn metadata_is_strict_and_validated() {
        let metadata = NodeMetadata::new("canary-a".into(), digest('a'), digest('b')).unwrap();
        assert_eq!(metadata.protocol, NODE_PROTOCOL);
        assert!(serde_json::from_str::<NodeMetadata>(r#"{"protocol":"caution-canary-v0","node_id":"canary-a","config_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","keyset_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","key_epoch":0,"extra":true}"#).is_err());
        let mut wrong = metadata;
        wrong.key_epoch = 1;
        assert!(matches!(wrong.validate(), Err(NodeError::WrongKeyEpoch)));
    }

    #[test]
    fn config_document_binds_canonical_config() {
        let document = ConfigDocument::new(config()).unwrap();
        document.validate().unwrap();
        let mut changed = document;
        changed.config.targets[0].name = "Changed".into();
        assert!(matches!(
            changed.validate(),
            Err(NodeError::ConfigDigestMismatch)
        ));
    }
}
