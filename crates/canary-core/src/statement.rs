//! Hybrid-signed statement envelope: signing and verification (spec §9, §3, §10).
//!
//! A statement is the signed, canonical claim that a Canary emits about one
//! target: `caution.canary.pcr-match.v0`. The signed bytes are the fixed
//! domain prefix `"caution.canary.statement.v0\0"` concatenated with the
//! RFC 8785 canonical JSON of the payload (not the whole envelope). Both
//! Ed25519 and ML-DSA-65 sign those exact bytes; V0 verification requires
//! both signatures to validate.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::canonical::{canonicalize, CanonicalError};
use crate::keys::{base64url_nopad, verify_ed25519, verify_ml_dsa, KeyError, KeySet};

/// Domain-separation prefix for the signed message (spec §9).
const SIGN_PREFIX: &[u8] = b"caution.canary.statement.v0\0";

/// The only claim type in V0 (spec §3).
pub const CLAIM_TYPE: &str = "caution.canary.pcr-match.v0";

const ALG_ED25519: &str = "Ed25519";
const ALG_ML_DSA_65: &str = "ML-DSA-65";

#[derive(Debug, thiserror::Error)]
pub enum StatementError {
    #[error("canonicalization failed: {0}")]
    Canonical(#[from] CanonicalError),

    #[error("missing required signature: {0}")]
    MissingSignature(&'static str),

    #[error("ed25519 verification failed: {0}")]
    Ed25519(KeyError),

    #[error("ml-dsa-65 verification failed: {0}")]
    MlDsa(KeyError),

    #[error("invalid base64 signature: {0}")]
    BadSignatureEncoding(#[from] base64::DecodeError),

    #[error("statement expired")]
    Expired,

    #[error("bad timestamp: {0}")]
    BadTimestamp(#[from] chrono::ParseError),

    #[error("statement has no signers")]
    NoSigners,
}

/// Target state (spec §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Verified,
    Failed,
    Pending,
    Unreachable,
    Stale,
}

/// The signed claim payload (spec §9). Field order matches the spec example.
///
/// `reason` is a stable machine-readable value (spec §10, e.g.
/// `ALL_CHECKS_PASSED`); callers pass `evidence::ProbeReason::as_str()`. This
/// module accepts a plain `String` to avoid coupling to that type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    pub claim_type: String,
    pub target_id: String,
    pub target_origin: String,
    pub status: Status,
    pub reason: String,
    pub config_digest: String,
    pub evidence_digest: Option<String>,
    pub observed_at: Option<String>,
    pub issued_at: String,
    pub expires_at: String,
    pub verifier_id: String,
    pub key_epoch: u32,
}

/// One algorithm's signature over the signed message, base64url (no padding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub alg: String,
    pub sig: String,
}

/// One signer's contribution: all signatures it produced over the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signer {
    pub verifier_id: String,
    pub key_epoch: u32,
    pub signatures: Vec<Signature>,
}

/// The full signed statement envelope (spec §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub payload: Payload,
    pub signers: Vec<Signer>,
}

/// Build the exact bytes that both algorithms sign: the domain prefix
/// followed by the RFC 8785 canonical JSON of `payload`.
fn signed_message(payload: &Payload) -> Result<Vec<u8>, StatementError> {
    let canon = canonicalize(payload)?;
    let mut msg = Vec::with_capacity(SIGN_PREFIX.len() + canon.len());
    msg.extend_from_slice(SIGN_PREFIX);
    msg.extend_from_slice(&canon);
    Ok(msg)
}

/// Sign `payload` with both Ed25519 and ML-DSA-65 from `keyset`, producing
/// the full envelope with one signer carrying both signatures (spec §9).
pub fn sign_statement(
    payload: Payload,
    keyset: &KeySet,
    verifier_id: &str,
    key_epoch: u32,
) -> Result<Statement, StatementError> {
    let msg = signed_message(&payload)?;

    let ed_sig = keyset.sign_ed25519(&msg);
    let ml_sig = keyset.sign_ml_dsa(&msg);

    let signer = Signer {
        verifier_id: verifier_id.to_string(),
        key_epoch,
        signatures: vec![
            Signature {
                alg: ALG_ED25519.to_string(),
                sig: base64url_nopad(&ed_sig),
            },
            Signature {
                alg: ALG_ML_DSA_65.to_string(),
                sig: base64url_nopad(&ml_sig),
            },
        ],
    };

    Ok(Statement {
        payload,
        signers: vec![signer],
    })
}

/// Verify `stmt` against the trusted public keys. Requires the first signer
/// to carry both an Ed25519 and an ML-DSA-65 signature, both valid, and
/// requires `now <= expires_at`. The caller is responsible for trusting
/// `ed25519_pk`/`ml_dsa_pk` (e.g. from a verified `/keys.json`); matching a
/// `keyset_digest` to attestation is canaryctl's job, not this function's.
pub fn verify_statement(
    stmt: &Statement,
    ed25519_pk: &[u8],
    ml_dsa_pk: &[u8],
    now: DateTime<Utc>,
) -> Result<(), StatementError> {
    let msg = signed_message(&stmt.payload)?;

    let signer = stmt.signers.first().ok_or(StatementError::NoSigners)?;

    let ed_sig = signer
        .signatures
        .iter()
        .find(|s| s.alg == ALG_ED25519)
        .ok_or(StatementError::MissingSignature(ALG_ED25519))?;
    let ml_sig = signer
        .signatures
        .iter()
        .find(|s| s.alg == ALG_ML_DSA_65)
        .ok_or(StatementError::MissingSignature(ALG_ML_DSA_65))?;

    let ed_sig_bytes = URL_SAFE_NO_PAD.decode(&ed_sig.sig)?;
    let ml_sig_bytes = URL_SAFE_NO_PAD.decode(&ml_sig.sig)?;

    verify_ed25519(ed25519_pk, &msg, &ed_sig_bytes).map_err(StatementError::Ed25519)?;
    verify_ml_dsa(ml_dsa_pk, &msg, &ml_sig_bytes).map_err(StatementError::MlDsa)?;

    let expires_at: DateTime<Utc> = stmt.payload.expires_at.parse()?;
    if now > expires_at {
        return Err(StatementError::Expired);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterSeed;
    use base64::engine::general_purpose::STANDARD;

    fn test_keyset() -> KeySet {
        let seed_b64 = STANDARD.encode([0x11u8; 32]);
        let seed = MasterSeed::from_base64(&seed_b64).unwrap();
        KeySet::derive(&seed, "caution-canary-demo").unwrap()
    }

    fn verified_payload() -> Payload {
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
            expires_at: "2026-07-17T12:03:00Z".to_string(),
            verifier_id: "caution-canary-demo".to_string(),
            key_epoch: 0,
        }
    }

    fn unreachable_payload() -> Payload {
        Payload {
            claim_type: CLAIM_TYPE.to_string(),
            target_id: "payments-prod".to_string(),
            target_origin: "https://payments.example.com".to_string(),
            status: Status::Unreachable,
            reason: "UNREACHABLE".to_string(),
            config_digest: "sha256:deadbeef".to_string(),
            evidence_digest: None,
            observed_at: None,
            issued_at: "2026-07-17T12:00:00Z".to_string(),
            expires_at: "2026-07-17T12:03:00Z".to_string(),
            verifier_id: "caution-canary-demo".to_string(),
            key_epoch: 0,
        }
    }

    fn before_expiry() -> DateTime<Utc> {
        "2026-07-17T12:01:00Z".parse().unwrap()
    }

    fn after_expiry() -> DateTime<Utc> {
        "2026-07-17T12:10:00Z".parse().unwrap()
    }

    #[test]
    fn round_trip_verified() {
        let ks = test_keyset();
        let stmt = sign_statement(verified_payload(), &ks, "caution-canary-demo", 0).unwrap();
        verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .expect("verification should succeed");
    }

    #[test]
    fn tampered_payload_field_fails() {
        let ks = test_keyset();
        let mut stmt = sign_statement(verified_payload(), &ks, "caution-canary-demo", 0).unwrap();
        stmt.payload.target_id = "some-other-target".to_string();

        let err = verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .unwrap_err();
        assert!(matches!(err, StatementError::Ed25519(_)));
    }

    #[test]
    fn missing_ml_dsa_signature_fails() {
        let ks = test_keyset();
        let mut stmt = sign_statement(verified_payload(), &ks, "caution-canary-demo", 0).unwrap();
        stmt.signers[0]
            .signatures
            .retain(|s| s.alg != ALG_ML_DSA_65);

        let err = verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            StatementError::MissingSignature(ALG_ML_DSA_65)
        ));
    }

    #[test]
    fn missing_ed25519_signature_fails() {
        let ks = test_keyset();
        let mut stmt = sign_statement(verified_payload(), &ks, "caution-canary-demo", 0).unwrap();
        stmt.signers[0].signatures.retain(|s| s.alg != ALG_ED25519);

        let err = verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            StatementError::MissingSignature(ALG_ED25519)
        ));
    }

    #[test]
    fn corrupted_signature_bytes_fail() {
        let ks = test_keyset();
        let mut stmt = sign_statement(verified_payload(), &ks, "caution-canary-demo", 0).unwrap();
        let ed_sig = stmt.signers[0]
            .signatures
            .iter_mut()
            .find(|s| s.alg == ALG_ED25519)
            .unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(&ed_sig.sig).unwrap();
        raw[0] ^= 0xff;
        ed_sig.sig = URL_SAFE_NO_PAD.encode(raw);

        let err = verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .unwrap_err();
        assert!(matches!(err, StatementError::Ed25519(_)));
    }

    #[test]
    fn expired_statement_fails_even_with_valid_signatures() {
        let ks = test_keyset();
        let stmt = sign_statement(verified_payload(), &ks, "caution-canary-demo", 0).unwrap();

        let err = verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            after_expiry(),
        )
        .unwrap_err();
        assert!(matches!(err, StatementError::Expired));
    }

    #[test]
    fn non_verified_payload_nulls_round_trip() {
        let payload = unreachable_payload();
        let canon = canonicalize(&payload).unwrap();
        let s = String::from_utf8(canon).unwrap();
        assert!(s.contains(r#""evidence_digest":null"#));
        assert!(s.contains(r#""observed_at":null"#));

        let ks = test_keyset();
        let stmt = sign_statement(payload, &ks, "caution-canary-demo", 0).unwrap();
        verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .expect("verification should succeed for non-VERIFIED payload");
    }

    #[test]
    fn canonical_payload_bytes_are_deterministic() {
        let a = signed_message(&verified_payload()).unwrap();
        let b = signed_message(&verified_payload()).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with(SIGN_PREFIX));
    }

    #[test]
    fn signing_is_valid_even_though_ml_dsa_sig_bytes_vary() {
        // ML-DSA-65 signing is hedged (randomized); two signing runs over the
        // same payload need not produce identical signature bytes, but both
        // must still verify successfully.
        let ks = test_keyset();
        let stmt_a = sign_statement(verified_payload(), &ks, "caution-canary-demo", 0).unwrap();
        let stmt_b = sign_statement(verified_payload(), &ks, "caution-canary-demo", 0).unwrap();

        verify_statement(
            &stmt_a,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .unwrap();
        verify_statement(
            &stmt_b,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .unwrap();
    }
}
