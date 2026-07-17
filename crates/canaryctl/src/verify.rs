//! `canaryctl verify-statement` (spec §9, §15 step 6).
//!
//! Verifies a hybrid Ed25519 + ML-DSA-65 signed statement either offline
//! (from local files) or online (fetched from a running Canary node).

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use canary_core::keys::KeysDocument;
use canary_core::statement::{verify_statement, Statement};
use chrono::Utc;

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

pub fn run_offline(statement_path: &Path, keys_path: &Path) -> Result<()> {
    let statement: Statement = load_json(statement_path)?;
    let keys: KeysDocument = load_json(keys_path)?;
    verify_and_report(&statement, &keys)
}

pub fn run_online(node_url: &str, target: &str) -> Result<()> {
    let node_url = node_url.trim_end_matches('/');

    let keys: KeysDocument = ureq::get(&format!("{node_url}/keys.json"))
        .timeout(HTTP_TIMEOUT)
        .call()
        .with_context(|| format!("GET {node_url}/keys.json"))?
        .into_json()
        .context("parsing keys.json")?;

    let statement: Statement = ureq::get(&format!("{node_url}/targets/{target}/statement"))
        .timeout(HTTP_TIMEOUT)
        .call()
        .with_context(|| format!("GET {node_url}/targets/{target}/statement"))?
        .into_json()
        .context("parsing statement JSON")?;

    verify_and_report(&statement, &keys)
}

fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn verify_and_report(statement: &Statement, keys: &KeysDocument) -> Result<()> {
    let ed_pk = find_key(keys, "Ed25519")?;
    let ml_pk = find_key(keys, "ML-DSA-65")?;

    match verify_statement(statement, &ed_pk, &ml_pk, Utc::now()) {
        Ok(()) => {
            println!("PASS");
            println!("  target_id:    {}", statement.payload.target_id);
            println!("  status:       {:?}", statement.payload.status);
            println!("  claim_type:   {}", statement.payload.claim_type);
            println!("  expires_at:   {}", statement.payload.expires_at);
            Ok(())
        }
        Err(err) => {
            println!("FAIL: {err}");
            bail!("statement verification failed: {err}");
        }
    }
}

fn find_key(keys: &KeysDocument, alg: &str) -> Result<Vec<u8>> {
    let entry = keys
        .keys
        .iter()
        .find(|k| k.alg == alg)
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
        ks.keys_document("caution-canary-demo")
    }

    fn verified_payload(expires_at: &str) -> Payload {
        Payload {
            claim_type: CLAIM_TYPE.to_string(),
            target_id: "payments-prod".to_string(),
            target_origin: "https://payments.example.com".to_string(),
            status: Status::Verified,
            reason: "ALL_CHECKS_PASSED".to_string(),
            config_digest: "sha256:deadbeef".to_string(),
            evidence_digest: Some("sha256:cafef00d".to_string()),
            observed_at: Some("2026-07-17T12:00:00Z".to_string()),
            issued_at: "2026-07-17T12:00:00Z".to_string(),
            expires_at: expires_at.to_string(),
            verifier_id: "caution-canary-demo".to_string(),
            key_epoch: 0,
        }
    }

    #[test]
    fn offline_verify_passes_for_valid_fresh_statement() {
        let ks = test_keyset();
        let far_future = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        let stmt = sign_statement(
            verified_payload(&far_future),
            &ks,
            "caution-canary-demo",
            0,
        )
        .unwrap();
        let keys = test_keys_document(&ks);

        verify_and_report(&stmt, &keys).expect("valid fresh statement should pass");
    }

    #[test]
    fn offline_verify_fails_for_expired_statement() {
        let ks = test_keyset();
        let past = "2020-01-01T00:00:00Z";
        let stmt =
            sign_statement(verified_payload(past), &ks, "caution-canary-demo", 0).unwrap();
        let keys = test_keys_document(&ks);

        let err = verify_and_report(&stmt, &keys).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn offline_verify_fails_for_wrong_signer_keys() {
        let ks = test_keyset();
        let other_ks = {
            let seed = MasterSeed::from_base64(&STANDARD.encode([0x99u8; 32])).unwrap();
            KeySet::derive(&seed, "caution-canary-demo").unwrap()
        };
        let far_future = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        let stmt = sign_statement(
            verified_payload(&far_future),
            &ks,
            "caution-canary-demo",
            0,
        )
        .unwrap();
        let wrong_keys = test_keys_document(&other_ks);

        assert!(verify_and_report(&stmt, &wrong_keys).is_err());
    }

    #[test]
    fn find_key_missing_algorithm_errors() {
        let ks = test_keyset();
        let mut keys = test_keys_document(&ks);
        keys.keys.retain(|k| k.alg != "ML-DSA-65");
        let err = find_key(&keys, "ML-DSA-65").unwrap_err();
        assert!(err.to_string().contains("ML-DSA-65"));
    }

    #[test]
    fn base64url_roundtrip_sanity() {
        let bytes = [1u8, 2, 3, 4, 250, 251];
        let encoded = base64url_nopad(&bytes);
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }
}
