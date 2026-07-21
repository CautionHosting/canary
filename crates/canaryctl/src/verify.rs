//! `canaryctl artifact verify-statement` (spec §9, §15 step 6).
//!
//! Verification is deliberately offline in V0: the statement and public-key
//! document come from local files, and the caller must obtain the keys through
//! an independently trusted channel. Fetching both artifacts from the same
//! unverified node would prove only self-consistency, not signer identity.

use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use canary_core::keys::KeysDocument;
use canary_core::statement::{verify_statement, Statement};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

const PROTOCOL: &str = "caution-canary-v0";
const ALG_ED25519: &str = "Ed25519";
const ALG_ML_DSA_65: &str = "ML-DSA-65";

pub(crate) struct OfflineStatementOutcome {
    target_id: String,
    status: String,
    expires_at: String,
}

impl OfflineStatementOutcome {
    pub(crate) fn concise_text(&self) -> String {
        format!(
            "PARTIAL CHECK — statement signature valid\n{}  {}",
            self.target_id, self.status
        )
    }

    pub(crate) fn json_result(&self) -> Value {
        json!({"partial": true, "target_id": self.target_id, "status": self.status, "expires_at": self.expires_at})
    }
}

pub fn run_offline(statement_path: &Path, keys_path: &Path) -> Result<OfflineStatementOutcome> {
    let statement: Statement = load_json(statement_path)?;
    let keys: KeysDocument = load_json(keys_path)?;
    verify_and_report(&statement, &keys)
}

fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn verify_and_report(
    statement: &Statement,
    keys: &KeysDocument,
) -> Result<OfflineStatementOutcome> {
    verify_at(statement, keys, Utc::now())?;
    Ok(OfflineStatementOutcome {
        target_id: statement.payload.target_id.clone(),
        status: format!("{:?}", statement.payload.status).to_uppercase(),
        expires_at: statement.payload.expires_at.clone(),
    })
}

pub(crate) fn verify_at(
    statement: &Statement,
    keys: &KeysDocument,
    now: DateTime<Utc>,
) -> Result<()> {
    validate_keys_document(statement, keys)?;
    let ed_pk = find_key(keys, ALG_ED25519)?;
    let ml_pk = find_key(keys, ALG_ML_DSA_65)?;

    verify_statement(statement, &ed_pk, &ml_pk, now)
        .map_err(|err| anyhow::anyhow!("statement verification failed: {err}"))
}

fn validate_keys_document(statement: &Statement, keys: &KeysDocument) -> Result<()> {
    if keys.protocol != PROTOCOL {
        bail!("keys document protocol must be {PROTOCOL}");
    }
    if keys.node_id != statement.payload.verifier_id {
        bail!("keys document node_id does not match the signed verifier_id");
    }
    if keys.key_epoch != statement.payload.key_epoch {
        bail!("keys document key_epoch does not match the signed key_epoch");
    }
    if keys.keys.len() != 2 {
        bail!("V0 keys document must contain exactly two keys");
    }
    if keys.keys.iter().any(|key| key.encoding != "base64url") {
        bail!("V0 public keys must use base64url encoding");
    }
    for algorithm in [ALG_ED25519, ALG_ML_DSA_65] {
        if keys.keys.iter().filter(|key| key.alg == algorithm).count() != 1 {
            bail!("V0 keys document must contain exactly one {algorithm} key");
        }
    }
    if keys
        .keys
        .iter()
        .any(|key| key.alg != ALG_ED25519 && key.alg != ALG_ML_DSA_65)
    {
        bail!("V0 keys document contains an unsupported algorithm");
    }
    Ok(())
}

fn find_key(keys: &KeysDocument, alg: &str) -> Result<Vec<u8>> {
    let entry = keys
        .keys
        .iter()
        .find(|key| key.alg == alg)
        .with_context(|| format!("keys document has no {alg} entry"))?;
    URL_SAFE_NO_PAD
        .decode(&entry.public_key)
        .with_context(|| format!("decoding base64url {alg} public key"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use canary_core::keys::{base64url_nopad, KeySet, MasterSeed};
    use canary_core::statement::{sign_statement, Payload, Status, CLAIM_TYPE};

    fn test_keyset() -> KeySet {
        let seed = MasterSeed::from_base64(&STANDARD.encode([0x33u8; 32])).unwrap();
        KeySet::derive(&seed, "caution-canary-demo").unwrap()
    }

    fn test_keys_document(ks: &KeySet) -> KeysDocument {
        ks.keys_document()
    }

    fn verified_payload(observed_at: &str, expires_at: &str) -> Payload {
        Payload {
            claim_type: CLAIM_TYPE.to_string(),
            target_id: "payments-prod".to_string(),
            target_origin: "https://payments.example.com".to_string(),
            status: Status::Verified,
            reason: "ALL_CHECKS_PASSED".to_string(),
            config_digest: format!("sha256:{}", "a".repeat(64)),
            evidence_digest: Some(format!("sha256:{}", "b".repeat(64))),
            observed_at: Some(observed_at.to_string()),
            issued_at: observed_at.to_string(),
            expires_at: expires_at.to_string(),
            verifier_id: "caution-canary-demo".to_string(),
            key_epoch: 0,
        }
    }

    fn signed_fixture() -> (Statement, KeySet) {
        let ks = test_keyset();
        let stmt = sign_statement(
            verified_payload("2026-07-17T12:00:00Z", "2026-07-17T12:03:00Z"),
            &ks,
        )
        .unwrap();
        (stmt, ks)
    }

    #[test]
    fn offline_verify_passes_for_valid_fresh_statement() {
        let (stmt, ks) = signed_fixture();
        let keys = test_keys_document(&ks);
        let now = "2026-07-17T12:01:00Z".parse().unwrap();

        verify_at(&stmt, &keys, now).expect("valid fresh statement should pass");
    }

    #[test]
    fn offline_verify_fails_for_expired_statement() {
        let (stmt, ks) = signed_fixture();
        let keys = test_keys_document(&ks);
        let now = "2026-07-17T12:03:00Z".parse().unwrap();

        let err = verify_at(&stmt, &keys, now).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn offline_verify_fails_for_wrong_signer_keys() {
        let (stmt, _) = signed_fixture();
        let other_ks = {
            let seed = MasterSeed::from_base64(&STANDARD.encode([0x99u8; 32])).unwrap();
            KeySet::derive(&seed, "caution-canary-demo").unwrap()
        };
        let wrong_keys = test_keys_document(&other_ks);
        let now = "2026-07-17T12:01:00Z".parse().unwrap();

        assert!(verify_at(&stmt, &wrong_keys, now).is_err());
    }

    #[test]
    fn keys_identity_must_match_signed_verifier() {
        let (stmt, ks) = signed_fixture();
        let mut keys = test_keys_document(&ks);
        keys.node_id = "different-canary".to_string();
        let now = "2026-07-17T12:01:00Z".parse().unwrap();

        let err = verify_at(&stmt, &keys, now).unwrap_err();
        assert!(err.to_string().contains("node_id"));
    }

    #[test]
    fn duplicate_key_algorithm_is_rejected() {
        let (stmt, ks) = signed_fixture();
        let mut keys = test_keys_document(&ks);
        keys.keys[1] = keys.keys[0].clone();
        let now = "2026-07-17T12:01:00Z".parse().unwrap();

        let err = verify_at(&stmt, &keys, now).unwrap_err();
        assert!(err.to_string().contains("exactly one Ed25519"));
    }

    #[test]
    fn find_key_missing_algorithm_errors() {
        let ks = test_keyset();
        let mut keys = test_keys_document(&ks);
        keys.keys.retain(|key| key.alg != ALG_ML_DSA_65);
        let err = find_key(&keys, ALG_ML_DSA_65).unwrap_err();
        assert!(err.to_string().contains(ALG_ML_DSA_65));
    }

    #[test]
    fn base64url_roundtrip_sanity() {
        let bytes = [1u8, 2, 3, 4, 250, 251];
        let encoded = base64url_nopad(&bytes);
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }
}
