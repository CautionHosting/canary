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
use url::Url;

use crate::canonical::{canonicalize, CanonicalError};
use crate::config::is_valid_identifier;
use crate::keys::{base64url_nopad, verify_ed25519, verify_ml_dsa, KeyError, KeySet, KEY_EPOCH};

/// Domain-separation prefix for the signed message (spec §9).
const SIGN_PREFIX: &[u8] = b"caution.canary.statement.v0\0";

/// The only claim type in V0 (spec §3).
pub const CLAIM_TYPE: &str = "caution.canary.pcr-match.v0";

const ALG_ED25519: &str = "Ed25519";
const ALG_ML_DSA_65: &str = "ML-DSA-65";
const STATEMENT_TTL_SECONDS: i64 = 180;
const MAX_FUTURE_SKEW_SECONDS: i64 = 30;

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

    #[error("statement issued too far in the future")]
    NotYetValid,

    #[error("bad timestamp: {0}")]
    BadTimestamp(#[from] chrono::ParseError),

    #[error("statement has no signers")]
    NoSigners,

    #[error("invalid statement payload: {0}")]
    InvalidPayload(String),

    #[error("invalid statement envelope: {0}")]
    InvalidEnvelope(String),
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub alg: String,
    pub sig: String,
}

/// One signer's contribution: all signatures it produced over the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signer {
    pub verifier_id: String,
    pub key_epoch: u32,
    pub signatures: Vec<Signature>,
}

/// The full signed statement envelope (spec §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, StatementError> {
    value.parse().map_err(StatementError::BadTimestamp)
}

fn is_canonical_https_origin(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.origin().ascii_serialization() == value
}

fn validate_payload(payload: &Payload) -> Result<(DateTime<Utc>, DateTime<Utc>), StatementError> {
    if payload.claim_type != CLAIM_TYPE {
        return Err(StatementError::InvalidPayload(format!(
            "claim_type must be {CLAIM_TYPE:?}"
        )));
    }
    if payload.key_epoch != KEY_EPOCH {
        return Err(StatementError::InvalidPayload(format!(
            "key_epoch must be {KEY_EPOCH} in V0"
        )));
    }
    if !is_valid_identifier(&payload.target_id) || !is_valid_identifier(&payload.verifier_id) {
        return Err(StatementError::InvalidPayload(
            "target_id and verifier_id must be canonical ASCII identifiers".to_string(),
        ));
    }
    if payload.reason.is_empty() {
        return Err(StatementError::InvalidPayload(
            "reason must be non-empty".to_string(),
        ));
    }
    if !is_canonical_https_origin(&payload.target_origin) {
        return Err(StatementError::InvalidPayload(
            "target_origin must be a canonical HTTPS origin without a trailing slash".to_string(),
        ));
    }
    if !is_sha256_digest(&payload.config_digest) {
        return Err(StatementError::InvalidPayload(
            "config_digest must be a canonical sha256 digest".to_string(),
        ));
    }
    if payload
        .evidence_digest
        .as_deref()
        .is_some_and(|digest| !is_sha256_digest(digest))
    {
        return Err(StatementError::InvalidPayload(
            "evidence_digest must be a canonical sha256 digest".to_string(),
        ));
    }

    let issued_at = parse_timestamp(&payload.issued_at)?;
    let expires_at = parse_timestamp(&payload.expires_at)?;
    let anchor = match payload.status {
        Status::Verified | Status::Failed => {
            let observed_at = payload.observed_at.as_deref().ok_or_else(|| {
                StatementError::InvalidPayload(
                    "VERIFIED and FAILED require observed_at".to_string(),
                )
            })?;
            if payload.status == Status::Verified && payload.evidence_digest.is_none() {
                return Err(StatementError::InvalidPayload(
                    "VERIFIED requires evidence_digest".to_string(),
                ));
            }
            let observed_at = parse_timestamp(observed_at)?;
            if observed_at > issued_at {
                return Err(StatementError::InvalidPayload(
                    "observed_at must not be later than issued_at".to_string(),
                ));
            }
            observed_at
        }
        Status::Pending | Status::Unreachable | Status::Stale => {
            if payload.observed_at.is_some() || payload.evidence_digest.is_some() {
                return Err(StatementError::InvalidPayload(
                    "PENDING, UNREACHABLE and STALE must not carry target evidence".to_string(),
                ));
            }
            issued_at
        }
    };

    if payload.status == Status::Verified && payload.reason != "ALL_CHECKS_PASSED" {
        return Err(StatementError::InvalidPayload(
            "VERIFIED requires ALL_CHECKS_PASSED".to_string(),
        ));
    }
    if payload.status != Status::Verified && payload.reason == "ALL_CHECKS_PASSED" {
        return Err(StatementError::InvalidPayload(
            "ALL_CHECKS_PASSED is valid only for VERIFIED".to_string(),
        ));
    }

    let expected_expiry = anchor
        .checked_add_signed(chrono::Duration::seconds(STATEMENT_TTL_SECONDS))
        .ok_or_else(|| {
            StatementError::InvalidPayload("definitive timestamp is out of range".to_string())
        })?;
    if expires_at != expected_expiry {
        return Err(StatementError::InvalidPayload(format!(
            "expires_at must be exactly {STATEMENT_TTL_SECONDS} seconds after the definitive timestamp"
        )));
    }
    if issued_at > expires_at {
        return Err(StatementError::InvalidPayload(
            "issued_at must not be later than expires_at".to_string(),
        ));
    }

    Ok((issued_at, expires_at))
}

/// Sign `payload` with both Ed25519 and ML-DSA-65 from `keyset`, producing
/// the full envelope with one signer carrying both signatures (spec §9).
pub fn sign_statement(payload: Payload, keyset: &KeySet) -> Result<Statement, StatementError> {
    validate_payload(&payload)?;
    if payload.verifier_id != keyset.node_id() {
        return Err(StatementError::InvalidPayload(
            "verifier_id does not match the node identity used to derive the signing keys"
                .to_string(),
        ));
    }
    let msg = signed_message(&payload)?;

    let ed_sig = keyset.sign_ed25519(&msg);
    let ml_sig = keyset.sign_ml_dsa(&msg).map_err(StatementError::MlDsa)?;

    let signer = Signer {
        verifier_id: payload.verifier_id.clone(),
        key_epoch: payload.key_epoch,
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

/// Verify `stmt` against the trusted public keys. V0 requires exactly one signer,
/// matching the signed verifier identity and key epoch, carrying exactly one
/// Ed25519 and one ML-DSA-65 signature. Both must be valid and `now` must be
/// earlier than `expires_at`. The caller is responsible for trusting
/// `ed25519_pk`/`ml_dsa_pk` (e.g. from a verified `/keys.json`); matching a
/// `keyset_digest` to attestation is canaryctl's job, not this function's.
pub fn verify_statement(
    stmt: &Statement,
    ed25519_pk: &[u8],
    ml_dsa_pk: &[u8],
    now: DateTime<Utc>,
) -> Result<(), StatementError> {
    let (issued_at, expires_at) = validate_payload(&stmt.payload)?;
    let latest_acceptable_issue = now
        .checked_add_signed(chrono::Duration::seconds(MAX_FUTURE_SKEW_SECONDS))
        .unwrap_or(DateTime::<Utc>::MAX_UTC);
    if issued_at > latest_acceptable_issue {
        return Err(StatementError::NotYetValid);
    }
    if now >= expires_at {
        return Err(StatementError::Expired);
    }
    let msg = signed_message(&stmt.payload)?;

    let signer = match stmt.signers.as_slice() {
        [] => return Err(StatementError::NoSigners),
        [signer] => signer,
        _ => {
            return Err(StatementError::InvalidEnvelope(
                "V0 statements must contain exactly one signer".to_string(),
            ));
        }
    };
    if signer.verifier_id != stmt.payload.verifier_id || signer.key_epoch != stmt.payload.key_epoch
    {
        return Err(StatementError::InvalidEnvelope(
            "signer identity does not match the signed verifier_id and key_epoch".to_string(),
        ));
    }

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

    if signer.signatures.len() != 2 {
        return Err(StatementError::InvalidEnvelope(
            "the V0 signer must contain exactly two signatures".to_string(),
        ));
    }

    let ed_sig_bytes = URL_SAFE_NO_PAD.decode(&ed_sig.sig)?;
    let ml_sig_bytes = URL_SAFE_NO_PAD.decode(&ml_sig.sig)?;

    verify_ed25519(ed25519_pk, &msg, &ed_sig_bytes).map_err(StatementError::Ed25519)?;
    verify_ml_dsa(ml_dsa_pk, &msg, &ml_sig_bytes).map_err(StatementError::MlDsa)?;

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
            config_digest: format!("sha256:{}", "a".repeat(64)),
            evidence_digest: Some(format!("sha256:{}", "b".repeat(64))),
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
            config_digest: format!("sha256:{}", "a".repeat(64)),
            evidence_digest: None,
            observed_at: None,
            issued_at: "2026-07-17T12:00:00Z".to_string(),
            expires_at: "2026-07-17T12:03:00Z".to_string(),
            verifier_id: "caution-canary-demo".to_string(),
            key_epoch: 0,
        }
    }

    fn failed_payload_without_decoded_evidence() -> Payload {
        Payload {
            status: Status::Failed,
            reason: "MALFORMED_EVIDENCE".to_string(),
            evidence_digest: None,
            ..verified_payload()
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
        let stmt = sign_statement(verified_payload(), &ks).unwrap();
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
        let mut stmt = sign_statement(verified_payload(), &ks).unwrap();
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
        let mut stmt = sign_statement(verified_payload(), &ks).unwrap();
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
        let mut stmt = sign_statement(verified_payload(), &ks).unwrap();
        stmt.signers[0].signatures.retain(|s| s.alg != ALG_ED25519);

        let err = verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .unwrap_err();
        assert!(matches!(err, StatementError::MissingSignature(ALG_ED25519)));
    }

    #[test]
    fn corrupted_signature_bytes_fail() {
        let ks = test_keyset();
        let mut stmt = sign_statement(verified_payload(), &ks).unwrap();
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
        let stmt = sign_statement(verified_payload(), &ks).unwrap();

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
        let stmt = sign_statement(payload, &ks).unwrap();
        verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .expect("verification should succeed for non-VERIFIED payload");
    }

    #[test]
    fn failed_payload_can_report_undecodable_evidence_without_digest() {
        let ks = test_keyset();
        let stmt = sign_statement(failed_payload_without_decoded_evidence(), &ks).unwrap();

        verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .expect("FAILED may lack a digest when no document bytes could be decoded");
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
        let stmt_a = sign_statement(verified_payload(), &ks).unwrap();
        let stmt_b = sign_statement(verified_payload(), &ks).unwrap();

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

    #[test]
    fn wrong_claim_type_is_rejected_before_signing() {
        let ks = test_keyset();
        let mut payload = verified_payload();
        payload.claim_type = "not-the-v0-claim".to_string();

        let err = sign_statement(payload, &ks).unwrap_err();
        assert!(matches!(err, StatementError::InvalidPayload(_)));
    }

    #[test]
    fn signer_metadata_must_match_signed_payload() {
        let ks = test_keyset();
        let mut stmt = sign_statement(verified_payload(), &ks).unwrap();
        stmt.signers[0].verifier_id = "different-canary".to_string();

        let err = verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .unwrap_err();
        assert!(matches!(err, StatementError::InvalidEnvelope(_)));
    }

    #[test]
    fn signing_keys_must_match_payload_verifier_identity() {
        let ks = test_keyset();
        let mut payload = verified_payload();
        payload.verifier_id = "different-canary".to_string();

        let err = sign_statement(payload, &ks).unwrap_err();
        assert!(matches!(err, StatementError::InvalidPayload(_)));
    }

    #[test]
    fn non_v0_lifetime_is_rejected() {
        let ks = test_keyset();
        let mut payload = verified_payload();
        payload.expires_at = "2026-07-18T12:00:00Z".to_string();

        let err = sign_statement(payload, &ks).unwrap_err();
        assert!(matches!(err, StatementError::InvalidPayload(_)));
    }

    #[test]
    fn statement_is_expired_at_exact_expiry_time() {
        let ks = test_keyset();
        let stmt = sign_statement(verified_payload(), &ks).unwrap();
        let at_expiry = "2026-07-17T12:03:00Z".parse().unwrap();

        let err = verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            at_expiry,
        )
        .unwrap_err();
        assert!(matches!(err, StatementError::Expired));
    }

    #[test]
    fn statement_issued_too_far_in_future_is_rejected() {
        let ks = test_keyset();
        let stmt = sign_statement(verified_payload(), &ks).unwrap();
        let too_early = "2026-07-17T11:59:29Z".parse().unwrap();

        let err = verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            too_early,
        )
        .unwrap_err();
        assert!(matches!(err, StatementError::NotYetValid));
    }

    #[test]
    fn extra_signature_is_rejected() {
        let ks = test_keyset();
        let mut stmt = sign_statement(verified_payload(), &ks).unwrap();
        let duplicate = stmt.signers[0].signatures[0].clone();
        stmt.signers[0].signatures.push(duplicate);

        let err = verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .unwrap_err();
        assert!(matches!(err, StatementError::InvalidEnvelope(_)));
    }

    #[test]
    fn extra_signer_is_rejected_in_v0() {
        let ks = test_keyset();
        let mut stmt = sign_statement(verified_payload(), &ks).unwrap();
        stmt.signers.push(stmt.signers[0].clone());

        let err = verify_statement(
            &stmt,
            &ks.ed25519_public_key_bytes(),
            &ks.ml_dsa_public_key_bytes(),
            before_expiry(),
        )
        .unwrap_err();
        assert!(matches!(err, StatementError::InvalidEnvelope(_)));
    }

    #[test]
    fn noncanonical_target_origin_is_rejected() {
        let ks = test_keyset();
        let mut payload = verified_payload();
        payload.target_origin = "https://payments.example.com/attestation".to_string();

        let err = sign_statement(payload, &ks).unwrap_err();
        assert!(matches!(err, StatementError::InvalidPayload(_)));
    }

    #[test]
    fn unknown_payload_field_is_rejected() {
        let mut value = serde_json::to_value(verified_payload()).unwrap();
        value["unexpected"] = serde_json::json!(true);

        let err = serde_json::from_value::<Payload>(value).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }
}
