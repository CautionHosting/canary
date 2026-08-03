//! Bootproof evidence verification (spec §7.1, §7.2, §10).
//!
//! Thin wrapper over `bootproof-sdk`'s verifier-only Nitro format: turns a raw
//! Bootproof attestation document + expected PCRs + nonce into a typed
//! [`EvidenceOutcome`] carrying a stable [`ProbeReason`].
//!
//! This module is verifier-only. It must never import
//! `aws-nitro-enclaves-nsm-api`, open `/dev/nsm`, or generate attestations
//! (spec §7.2) — it only consumes attestation documents produced elsewhere by
//! the Caution Bootproof service.

use std::collections::HashMap;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bootproof_sdk::format::nitro::{Nitro, NitroPcrs};
use bootproof_sdk::VerifiableSignedAttestationFormat;
use chrono::{DateTime, SecondsFormat, Utc};
use coset::{CborSerializable, CoseSign1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::{digest_canonical, CanonicalError};
use crate::config::is_valid_identifier;

/// Wire protocol identifier for evidence bundles served and consumed by V0.
pub const EVIDENCE_PROTOCOL: &str = "caution-canary-evidence-v0";

/// Stable, machine-readable probe outcome reasons (spec §10).
///
/// `HTTP_ERROR`, `TIMEOUT` and `UNREACHABLE` are transport-layer reasons
/// produced by the `canaryd` HTTP layer, not by this module; they are
/// included here only so the full stable reason set lives in one enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProbeReason {
    AllChecksPassed,
    PcrMismatch,
    DebugOrZeroPcr,
    InvalidCertificateChain,
    InvalidSignature,
    NonceMismatch,
    MalformedEvidence,
    TlsBindingMismatch,
    /// Set by the `canaryd` HTTP layer, not by this module.
    HttpError,
    /// Set by the `canaryd` HTTP layer, not by this module.
    Timeout,
    /// Set by the `canaryd` HTTP layer, not by this module.
    Unreachable,
    InternalError,
}

impl ProbeReason {
    /// The exact `SCREAMING_SNAKE_CASE` wire string for this reason.
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeReason::AllChecksPassed => "ALL_CHECKS_PASSED",
            ProbeReason::PcrMismatch => "PCR_MISMATCH",
            ProbeReason::DebugOrZeroPcr => "DEBUG_OR_ZERO_PCR",
            ProbeReason::InvalidCertificateChain => "INVALID_CERTIFICATE_CHAIN",
            ProbeReason::InvalidSignature => "INVALID_SIGNATURE",
            ProbeReason::NonceMismatch => "NONCE_MISMATCH",
            ProbeReason::MalformedEvidence => "MALFORMED_EVIDENCE",
            ProbeReason::TlsBindingMismatch => "TLS_BINDING_MISMATCH",
            ProbeReason::HttpError => "HTTP_ERROR",
            ProbeReason::Timeout => "TIMEOUT",
            ProbeReason::Unreachable => "UNREACHABLE",
            ProbeReason::InternalError => "INTERNAL_ERROR",
        }
    }
}

/// Errors from this module's own helpers (not from `bootproof-sdk` itself,
/// which are mapped into [`ProbeReason`] inside [`EvidenceOutcome`]).
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("invalid hex for {field}: {source}")]
    BadHex {
        field: &'static str,
        #[source]
        source: hex::FromHexError,
    },
}

/// A self-contained, language-neutral V0 evidence artifact.
///
/// `document` and `nonce` use canonical standard base64. `manifest` is copied
/// from Bootproof only for diagnostics and is never used as verification
/// policy. Expected PCRs deliberately remain outside this bundle so callers
/// must obtain them through a separately trusted channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    pub protocol: String,
    pub target_id: String,
    pub document: String,
    pub nonce: String,
    pub observed_at: String,
    pub evidence_digest: String,
    pub manifest: serde_json::Value,
    pub manifest_digest: String,
}

/// Validated and decoded fields from an [`EvidenceBundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEvidenceBundle {
    pub document: Vec<u8>,
    pub nonce: [u8; 32],
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceBundleError {
    #[error("unsupported evidence protocol {0:?}")]
    UnsupportedProtocol(String),

    #[error("invalid target identifier {0:?}")]
    InvalidTargetId(String),

    #[error("invalid standard base64 in {field}: {source}")]
    InvalidBase64 {
        field: &'static str,
        #[source]
        source: base64::DecodeError,
    },

    #[error("{0} must use canonical padded standard base64")]
    NonCanonicalBase64(&'static str),

    #[error("nonce must decode to exactly 32 bytes, got {0}")]
    InvalidNonceLength(usize),

    #[error("attestation document must not be empty")]
    EmptyDocument,

    #[error("invalid observed_at timestamp: {0}")]
    InvalidTimestamp(#[from] chrono::ParseError),

    #[error("observed_at must be canonical UTC RFC 3339 with whole seconds")]
    NonCanonicalTimestamp,

    #[error("{field} mismatch: declared {declared}, computed {computed}")]
    DigestMismatch {
        field: &'static str,
        declared: String,
        computed: String,
    },

    #[error("manifest canonicalization failed: {0}")]
    Canonical(#[from] CanonicalError),
}

impl EvidenceBundle {
    /// Validate the frozen V0 wire contract and decode the evidence inputs.
    /// This checks both declared digests, but never treats `manifest` as
    /// signed policy.
    pub fn decode_and_validate(&self) -> Result<DecodedEvidenceBundle, EvidenceBundleError> {
        if self.protocol != EVIDENCE_PROTOCOL {
            return Err(EvidenceBundleError::UnsupportedProtocol(
                self.protocol.clone(),
            ));
        }
        if !is_valid_identifier(&self.target_id) {
            return Err(EvidenceBundleError::InvalidTargetId(self.target_id.clone()));
        }

        let document = decode_canonical_base64("document", &self.document)?;
        if document.is_empty() {
            return Err(EvidenceBundleError::EmptyDocument);
        }
        let nonce_bytes = decode_canonical_base64("nonce", &self.nonce)?;
        let nonce_len = nonce_bytes.len();
        let nonce: [u8; 32] = nonce_bytes
            .try_into()
            .map_err(|_| EvidenceBundleError::InvalidNonceLength(nonce_len))?;

        let observed_at: DateTime<Utc> = self.observed_at.parse()?;
        if observed_at.to_rfc3339_opts(SecondsFormat::Secs, true) != self.observed_at {
            return Err(EvidenceBundleError::NonCanonicalTimestamp);
        }

        ensure_digest(
            "evidence_digest",
            &self.evidence_digest,
            &evidence_digest(&document),
        )?;
        ensure_digest(
            "manifest_digest",
            &self.manifest_digest,
            &digest_canonical(&self.manifest)?,
        )?;

        Ok(DecodedEvidenceBundle {
            document,
            nonce,
            observed_at,
        })
    }
}

fn decode_canonical_base64(
    field: &'static str,
    encoded: &str,
) -> Result<Vec<u8>, EvidenceBundleError> {
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|source| EvidenceBundleError::InvalidBase64 { field, source })?;
    if STANDARD.encode(&decoded) != encoded {
        return Err(EvidenceBundleError::NonCanonicalBase64(field));
    }
    Ok(decoded)
}

fn ensure_digest(
    field: &'static str,
    declared: &str,
    computed: &str,
) -> Result<(), EvidenceBundleError> {
    if declared != computed {
        return Err(EvidenceBundleError::DigestMismatch {
            field,
            declared: declared.to_string(),
            computed: computed.to_string(),
        });
    }
    Ok(())
}

/// The result of verifying one Bootproof evidence document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceOutcome {
    /// Whether verification succeeded (`reason == ALL_CHECKS_PASSED`).
    pub passed: bool,
    pub reason: ProbeReason,
    /// `sha256:<hex>` of the decoded COSE attestation document bytes
    /// (spec §9: "the SHA-256 digest of the decoded COSE attestation
    /// document bytes").
    pub evidence_digest: String,
    /// The `user_data` bytes embedded in the attestation payload, extracted
    /// only on a passing verification (spec §7.3). `None` on failure or if
    /// absent.
    pub user_data: Option<Vec<u8>>,
    /// PCR0/1/2 extracted from a payload only after its AWS certificate chain,
    /// COSE signature, and caller-supplied nonce have all been verified.
    ///
    /// This remains available on an authenticated PCR policy mismatch so
    /// callers can safely show the actual measurement alongside policy.
    pub pcr_claims: Option<AuthenticatedPcrClaims>,
}

/// The three meaningful Nitro PCR values represented as lowercase hex.
///
/// These are a diagnostic representation only; `NitroPcrs` remains the
/// verifier's byte-oriented input type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcrValues {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
}

/// Per-PCR comparison of authenticated measurements against Canary policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcrMatches {
    pub pcr0: bool,
    pub pcr1: bool,
    pub pcr2: bool,
}

/// Authenticated observed PCRs and the policy used to evaluate them.
///
/// A value of this type is only produced after `bootproof-sdk` has validated
/// the AWS certificate chain, COSE signature, and supplied nonce against the
/// same observed PCR values. It therefore never represents merely decoded,
/// unauthenticated CBOR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedPcrClaims {
    pub observed: PcrValues,
    pub expected: PcrValues,
    pub matches: PcrMatches,
}

/// SHA-256 digest of `bytes`, formatted as `sha256:<64 lowercase hex chars>`.
pub fn evidence_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Decode three hex-encoded PCR strings (PCR0/1/2) into the `NitroPcrs` shape
/// expected by `bootproof-sdk`. Reusable by `canaryd` and `canaryctl`.
pub fn pcrs_from_hex(pcr0: &str, pcr1: &str, pcr2: &str) -> Result<NitroPcrs, EvidenceError> {
    let decode = |field: &'static str, s: &str| {
        hex::decode(s).map_err(|source| EvidenceError::BadHex { field, source })
    };

    let mut pcrs: NitroPcrs = HashMap::new();
    pcrs.insert(0, decode("pcr0", pcr0)?);
    pcrs.insert(1, decode("pcr1", pcr1)?);
    pcrs.insert(2, decode("pcr2", pcr2)?);
    Ok(pcrs)
}

/// True if any of PCR0/1/2 in `pcrs` is present but all-zero, which spec
/// §7.1 treats as a debug/unmeasured enclave signal. Config validation is
/// responsible for rejecting all-zero *expected* PCR policies outright; this
/// is a defense-in-depth short circuit for whatever expected PCRs happen to
/// reach this function.
fn expected_pcrs_are_zero(pcrs: &NitroPcrs) -> bool {
    [0u8, 1, 2].iter().any(|idx| {
        pcrs.get(idx)
            .is_some_and(|v| !v.is_empty() && v.iter().all(|b| *b == 0))
    })
}

/// Extract the `user_data` bytes from a verified attestation payload
/// (spec §7.3), following the `Value::Map -> "user_data" -> Value::Bytes`
/// path used by the reference `caution verify` implementation.
fn extract_user_data(payload: &serde_cbor::Value) -> Option<Vec<u8>> {
    let serde_cbor::Value::Map(map) = payload else {
        return None;
    };
    match map.get(&serde_cbor::Value::Text("user_data".to_string())) {
        Some(serde_cbor::Value::Bytes(user_data)) => Some(user_data.clone()),
        _ => None,
    }
}

/// Extract PCR0/1/2 from a Nitro payload. Callers must not treat the result
/// as authenticated until `Nitro::verify` has succeeded: this function is
/// also used to obtain candidate PCRs with which to drive that verification.
fn extract_pcrs(payload: &serde_cbor::Value) -> Option<NitroPcrs> {
    let serde_cbor::Value::Map(map) = payload else {
        return None;
    };
    let serde_cbor::Value::Map(pcrs) = map.get(&serde_cbor::Value::Text("pcrs".to_string()))?
    else {
        return None;
    };

    let mut result = NitroPcrs::new();
    for index in [0u8, 1, 2] {
        let serde_cbor::Value::Bytes(value) =
            pcrs.get(&serde_cbor::Value::Integer(i128::from(index)))?
        else {
            return None;
        };
        if value.is_empty() {
            return None;
        }
        result.insert(index, value.clone());
    }
    Some(result)
}

/// Decode just enough untrusted COSE/CBOR to learn the PCR candidates used
/// for verification. The returned values are deliberately not exposed: they
/// become authenticated only when a subsequent `Nitro::verify` succeeds
/// against these exact candidates.
fn extract_candidate_pcrs(document_bytes: &[u8]) -> Option<NitroPcrs> {
    let cose = CoseSign1::from_slice(document_bytes).ok()?;
    let payload = cose.payload?;
    let payload: serde_cbor::Value = serde_cbor::from_slice(&payload).ok()?;
    extract_pcrs(&payload)
}

fn pcr_values(pcrs: &NitroPcrs) -> Option<PcrValues> {
    Some(PcrValues {
        pcr0: hex::encode(pcrs.get(&0)?),
        pcr1: hex::encode(pcrs.get(&1)?),
        pcr2: hex::encode(pcrs.get(&2)?),
    })
}

fn pcr_matches(observed: &NitroPcrs, expected: &NitroPcrs) -> Option<PcrMatches> {
    Some(PcrMatches {
        pcr0: observed.get(&0)? == expected.get(&0)?,
        pcr1: observed.get(&1)? == expected.get(&1)?,
        pcr2: observed.get(&2)? == expected.get(&2)?,
    })
}

fn authenticated_pcr_claims(
    verified_payload: &serde_cbor::Value,
    expected_pcrs: &NitroPcrs,
) -> Option<AuthenticatedPcrClaims> {
    let observed = extract_pcrs(verified_payload)?;
    Some(AuthenticatedPcrClaims {
        observed: pcr_values(&observed)?,
        expected: pcr_values(expected_pcrs)?,
        matches: pcr_matches(&observed, expected_pcrs)?,
    })
}

fn observed_pcrs_are_zero(claims: &AuthenticatedPcrClaims) -> bool {
    [
        &claims.observed.pcr0,
        &claims.observed.pcr1,
        &claims.observed.pcr2,
    ]
    .iter()
    .any(|value| value.bytes().all(|byte| byte == b'0'))
}

/// Map a `bootproof-sdk` verification error to the closest stable
/// [`ProbeReason`] (spec §10).
///
/// - `InvalidCABundle` -> `INVALID_CERTIFICATE_CHAIN` (AWS root/cert chain).
/// - `BadSignature` -> `INVALID_SIGNATURE` (COSE ES384 signature failure).
/// - `InvalidNonce` -> `NONCE_MISMATCH` (nonce present but doesn't match).
/// - `InvalidAAD` -> `PCR_MISMATCH` (this is exactly how the sdk reports a
///   PCR value that doesn't match the expected value).
/// - `MalformedData` / `MissingData` -> `MALFORMED_EVIDENCE` (CBOR/COSE
///   decode failure or an expected field/shape missing from the payload).
/// - `UnsupportedAlgorithm` -> `MALFORMED_EVIDENCE` (the document uses a
///   signing algorithm other than the one expected shape; closest to "the
///   evidence isn't the document we know how to parse" rather than a
///   transport/internal condition).
/// - `InvalidNonceSize` -> `INTERNAL_ERROR` (the *caller-supplied* nonce is
///   too short; `canaryd` always generates 32-byte nonces per spec §7.1, so
///   this indicates a bug on our side, not a defect in the evidence).
/// - `AttestationParameter` -> `INTERNAL_ERROR` (missing PCR0/1/2 in the
///   expected-PCR map passed to `Nitro::new`; a construction-time bug on our
///   side since `pcrs_from_hex` always populates all three).
fn map_verify_error(err: &bootproof_sdk::format::Error) -> ProbeReason {
    use bootproof_sdk::format::Error as SdkError;
    match err {
        SdkError::InvalidCABundle => ProbeReason::InvalidCertificateChain,
        SdkError::BadSignature => ProbeReason::InvalidSignature,
        SdkError::InvalidNonce => ProbeReason::NonceMismatch,
        SdkError::InvalidAAD(_) => ProbeReason::PcrMismatch,
        SdkError::MalformedData(_) | SdkError::MissingData(_) => ProbeReason::MalformedEvidence,
        SdkError::UnsupportedAlgorithm(_, _) => ProbeReason::MalformedEvidence,
        SdkError::InvalidNonceSize(_) => ProbeReason::InternalError,
        SdkError::AttestationParameter(_) => ProbeReason::InternalError,
    }
}

/// Verify a raw Bootproof attestation document against expected PCRs and a
/// nonce, per spec §7.1: "Decodes `document` and verifies it with the
/// verifier side of `bootproof-sdk`, equivalent to
/// `Nitro::new(document, expected_pcrs).verify(now, nonce)`."
///
/// It first extracts PCR0/1/2 as untrusted candidates, then asks
/// `bootproof-sdk` to authenticate the document using those exact values.
/// The caller's PCR policy is applied only after certificate-chain,
/// COSE-signature, and nonce verification succeed. This safely preserves
/// observed measurements for a `PCR_MISMATCH` diagnostic.
///
/// Never panics: all `bootproof-sdk` errors and malformed input are captured
/// in the returned [`EvidenceOutcome`].
pub fn verify_evidence(
    document_bytes: &[u8],
    expected_pcrs: &NitroPcrs,
    nonce: &[u8],
    now: Duration,
) -> EvidenceOutcome {
    let evidence_digest = evidence_digest(document_bytes);

    if expected_pcrs_are_zero(expected_pcrs) {
        return EvidenceOutcome {
            passed: false,
            reason: ProbeReason::DebugOrZeroPcr,
            evidence_digest,
            user_data: None,
            pcr_claims: None,
        };
    }

    let candidate_pcrs = match extract_candidate_pcrs(document_bytes) {
        Some(pcrs) => pcrs,
        None => {
            return EvidenceOutcome {
                passed: false,
                reason: ProbeReason::MalformedEvidence,
                evidence_digest,
                user_data: None,
                pcr_claims: None,
            };
        }
    };

    let nitro = match Nitro::new(document_bytes.to_vec(), candidate_pcrs) {
        Ok(nitro) => nitro,
        Err(err) => {
            return EvidenceOutcome {
                passed: false,
                reason: map_verify_error(&err),
                evidence_digest,
                user_data: None,
                pcr_claims: None,
            };
        }
    };

    match nitro.verify(now, &nonce) {
        Ok(payload) => match authenticated_pcr_claims(&payload, expected_pcrs) {
            Some(pcr_claims) if observed_pcrs_are_zero(&pcr_claims) => EvidenceOutcome {
                passed: false,
                reason: ProbeReason::DebugOrZeroPcr,
                evidence_digest,
                user_data: None,
                pcr_claims: Some(pcr_claims),
            },
            Some(pcr_claims)
                if !pcr_claims.matches.pcr0
                    || !pcr_claims.matches.pcr1
                    || !pcr_claims.matches.pcr2 =>
            {
                EvidenceOutcome {
                    passed: false,
                    reason: ProbeReason::PcrMismatch,
                    evidence_digest,
                    user_data: None,
                    pcr_claims: Some(pcr_claims),
                }
            }
            Some(pcr_claims) => EvidenceOutcome {
                passed: true,
                reason: ProbeReason::AllChecksPassed,
                evidence_digest,
                user_data: extract_user_data(&payload),
                pcr_claims: Some(pcr_claims),
            },
            // `Nitro::verify` already required PCR0/1/2 from this payload,
            // so this is defensive against an SDK contract change.
            None => EvidenceOutcome {
                passed: false,
                reason: ProbeReason::InternalError,
                evidence_digest,
                user_data: None,
                pcr_claims: None,
            },
        },
        Err(err) => EvidenceOutcome {
            passed: false,
            reason: map_verify_error(&err),
            evidence_digest,
            user_data: None,
            pcr_claims: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    const VALID_TIME: Duration = Duration::from_secs(1_766_510_416);
    const PCR_0_AND_1: &str = "ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03";
    const PCR_2: &str = "21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a";
    const NONCE: &str = "d041b23bce8678bbc7c174bd8494c4f9759386eec963ec69bfd45c1452b10636";

    fn valid_fixture() -> Vec<u8> {
        STANDARD
            .decode(include_str!("../tests/data/aws-test.cbor.b64").trim())
            .unwrap()
    }

    fn valid_pcrs() -> NitroPcrs {
        pcrs_from_hex(PCR_0_AND_1, PCR_0_AND_1, PCR_2).unwrap()
    }

    fn valid_nonce() -> Vec<u8> {
        hex::decode(NONCE).unwrap()
    }

    fn golden_bundle() -> EvidenceBundle {
        EvidenceBundle {
            protocol: EVIDENCE_PROTOCOL.to_string(),
            target_id: "payments-prod".to_string(),
            document: include_str!("../tests/data/aws-test.cbor.b64")
                .trim()
                .to_string(),
            nonce: STANDARD.encode(valid_nonce()),
            observed_at: "2025-12-23T17:20:16Z".to_string(),
            evidence_digest:
                "sha256:6afe913ae239fc83c44fd21c367f6ca9bf1b1b31d737c4720fd42cd49deb2c47"
                    .to_string(),
            manifest: serde_json::json!({}),
            manifest_digest:
                "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                    .to_string(),
        }
    }

    #[test]
    fn published_evidence_vector_reproduces_byte_for_byte() {
        let encoded = serde_json::to_string_pretty(&golden_bundle()).unwrap() + "\n";
        assert_eq!(
            encoded,
            include_str!("../tests/data/evidence-v0-vector.json")
        );

        let decoded = golden_bundle().decode_and_validate().unwrap();
        let outcome = verify_evidence(&decoded.document, &valid_pcrs(), &decoded.nonce, VALID_TIME);
        assert!(outcome.passed);
    }

    #[test]
    fn evidence_bundle_rejects_digest_and_nonce_tampering() {
        let mut bad_digest = golden_bundle();
        bad_digest.evidence_digest = format!("sha256:{}", "0".repeat(64));
        assert!(matches!(
            bad_digest.decode_and_validate(),
            Err(EvidenceBundleError::DigestMismatch {
                field: "evidence_digest",
                ..
            })
        ));

        let mut bad_nonce = golden_bundle();
        bad_nonce.nonce = STANDARD.encode([0u8; 31]);
        assert!(matches!(
            bad_nonce.decode_and_validate(),
            Err(EvidenceBundleError::InvalidNonceLength(31))
        ));
    }

    #[test]
    fn valid_bootproof_fixture_passes() {
        let document = valid_fixture();
        let outcome = verify_evidence(&document, &valid_pcrs(), &valid_nonce(), VALID_TIME);

        assert!(outcome.passed);
        assert_eq!(outcome.reason, ProbeReason::AllChecksPassed);
        assert_eq!(
            outcome.evidence_digest,
            "sha256:6afe913ae239fc83c44fd21c367f6ca9bf1b1b31d737c4720fd42cd49deb2c47"
        );
        assert_eq!(
            outcome.pcr_claims,
            Some(AuthenticatedPcrClaims {
                observed: PcrValues {
                    pcr0: PCR_0_AND_1.to_string(),
                    pcr1: PCR_0_AND_1.to_string(),
                    pcr2: PCR_2.to_string(),
                },
                expected: PcrValues {
                    pcr0: PCR_0_AND_1.to_string(),
                    pcr1: PCR_0_AND_1.to_string(),
                    pcr2: PCR_2.to_string(),
                },
                matches: PcrMatches {
                    pcr0: true,
                    pcr1: true,
                    pcr2: true,
                },
            })
        );
    }

    #[test]
    fn replayed_evidence_with_wrong_nonce_fails() {
        let document = valid_fixture();
        let wrong_nonce = [0x10; 32];
        let outcome = verify_evidence(&document, &valid_pcrs(), &wrong_nonce, VALID_TIME);

        assert!(!outcome.passed);
        assert_eq!(outcome.reason, ProbeReason::NonceMismatch);
    }

    #[test]
    fn valid_evidence_with_wrong_pcr_fails() {
        let document = valid_fixture();
        let mut pcrs = valid_pcrs();
        pcrs.get_mut(&0).unwrap()[1] ^= 0xff;
        let outcome = verify_evidence(&document, &pcrs, &valid_nonce(), VALID_TIME);

        assert!(!outcome.passed);
        assert_eq!(outcome.reason, ProbeReason::PcrMismatch);
        let claims = outcome
            .pcr_claims
            .expect("authenticated PCR claims remain available on mismatch");
        assert_eq!(claims.observed.pcr0, PCR_0_AND_1);
        assert_eq!(claims.expected.pcr0, hex::encode(pcrs.get(&0).unwrap()));
        assert_eq!(
            claims.matches,
            PcrMatches {
                pcr0: false,
                pcr1: true,
                pcr2: true,
            }
        );
    }

    #[test]
    fn tampered_evidence_signature_fails() {
        let mut document = valid_fixture();
        let last = document.last_mut().unwrap();
        *last ^= 0xff;
        let outcome = verify_evidence(&document, &valid_pcrs(), &valid_nonce(), VALID_TIME);

        assert!(!outcome.passed);
        assert_eq!(outcome.reason, ProbeReason::InvalidSignature);
        assert!(outcome.pcr_claims.is_none());
    }

    #[test]
    fn pcrs_from_hex_happy_path() {
        let pcrs = pcrs_from_hex("aa", "bb", "cc").expect("valid hex decodes");
        assert_eq!(pcrs.get(&0), Some(&vec![0xaa]));
        assert_eq!(pcrs.get(&1), Some(&vec![0xbb]));
        assert_eq!(pcrs.get(&2), Some(&vec![0xcc]));
    }

    #[test]
    fn pcrs_from_hex_bad_hex_rejected() {
        let err = pcrs_from_hex("zz", "bb", "cc").expect_err("invalid hex must error");
        assert!(matches!(err, EvidenceError::BadHex { field: "pcr0", .. }));
    }

    #[test]
    fn pcrs_from_hex_bad_hex_reports_correct_field() {
        let err = pcrs_from_hex("aa", "bb", "zz").expect_err("invalid hex must error");
        assert!(matches!(err, EvidenceError::BadHex { field: "pcr2", .. }));
    }

    #[test]
    fn evidence_digest_format() {
        let digest = evidence_digest(b"hello world");
        assert!(digest.starts_with("sha256:"));
        let hex_part = digest.strip_prefix("sha256:").unwrap();
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));

        // Known SHA-256("hello world").
        assert_eq!(
            hex_part,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn evidence_digest_is_deterministic_and_input_sensitive() {
        let a = evidence_digest(b"abc");
        let b = evidence_digest(b"abc");
        let c = evidence_digest(b"abcd");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn probe_reason_serde_round_trip() {
        let cases: &[(ProbeReason, &str)] = &[
            (ProbeReason::AllChecksPassed, "\"ALL_CHECKS_PASSED\""),
            (ProbeReason::PcrMismatch, "\"PCR_MISMATCH\""),
            (ProbeReason::DebugOrZeroPcr, "\"DEBUG_OR_ZERO_PCR\""),
            (
                ProbeReason::InvalidCertificateChain,
                "\"INVALID_CERTIFICATE_CHAIN\"",
            ),
            (ProbeReason::InvalidSignature, "\"INVALID_SIGNATURE\""),
            (ProbeReason::NonceMismatch, "\"NONCE_MISMATCH\""),
            (ProbeReason::MalformedEvidence, "\"MALFORMED_EVIDENCE\""),
            (ProbeReason::TlsBindingMismatch, "\"TLS_BINDING_MISMATCH\""),
            (ProbeReason::HttpError, "\"HTTP_ERROR\""),
            (ProbeReason::Timeout, "\"TIMEOUT\""),
            (ProbeReason::Unreachable, "\"UNREACHABLE\""),
            (ProbeReason::InternalError, "\"INTERNAL_ERROR\""),
        ];

        for (reason, expected_json) in cases {
            let json = serde_json::to_string(reason).unwrap();
            assert_eq!(&json, expected_json);
            assert_eq!(json.trim_matches('"'), reason.as_str());

            let round_tripped: ProbeReason = serde_json::from_str(&json).unwrap();
            assert_eq!(round_tripped, *reason);
        }
    }

    #[test]
    fn malformed_document_never_panics_and_reports_malformed_or_internal() {
        let garbage = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03];
        let pcrs = pcrs_from_hex("aa", "bb", "cc").unwrap();
        let nonce = [0u8; 32];

        let outcome = verify_evidence(&garbage, &pcrs, &nonce, Duration::from_secs(0));

        assert!(!outcome.passed);
        assert!(matches!(
            outcome.reason,
            ProbeReason::MalformedEvidence | ProbeReason::InternalError
        ));
        assert!(outcome.user_data.is_none());
        assert!(outcome.evidence_digest.starts_with("sha256:"));
    }

    #[test]
    fn empty_document_never_panics() {
        let pcrs = pcrs_from_hex("aa", "bb", "cc").unwrap();
        let nonce = [0u8; 32];

        let outcome = verify_evidence(&[], &pcrs, &nonce, Duration::from_secs(0));

        assert!(!outcome.passed);
        assert!(matches!(
            outcome.reason,
            ProbeReason::MalformedEvidence | ProbeReason::InternalError
        ));
    }

    #[test]
    fn random_bytes_never_panic() {
        // A handful of pseudo-random-looking byte strings; none of these are
        // valid COSE/CBOR, so this exercises MalformedData decode paths
        // without needing a real fixture.
        let samples: &[&[u8]] = &[
            &[0x01; 64],
            &[0xff; 128],
            b"not cbor at all, just text",
            &[0x84, 0x43, 0xa1, 0x01, 0x38, 0x22],
        ];
        let pcrs = pcrs_from_hex("aa", "bb", "cc").unwrap();
        let nonce = [0u8; 32];

        for sample in samples {
            let outcome = verify_evidence(sample, &pcrs, &nonce, Duration::from_secs(0));
            assert!(!outcome.passed);
        }
    }

    #[test]
    fn all_zero_expected_pcr_short_circuits_to_debug_reason() {
        let mut pcrs: NitroPcrs = HashMap::new();
        pcrs.insert(0, vec![0u8; 32]);
        pcrs.insert(1, vec![0u8; 32]);
        pcrs.insert(2, vec![0u8; 32]);
        let nonce = [0u8; 32];

        let outcome = verify_evidence(&[0xaa, 0xbb], &pcrs, &nonce, Duration::from_secs(0));

        assert!(!outcome.passed);
        assert_eq!(outcome.reason, ProbeReason::DebugOrZeroPcr);
    }

    // NOTE: A positive ALL_CHECKS_PASSED path requires a real signed Nitro
    // attestation document (COSE_Sign1 over a valid AWS Nitro cert chain).
    // bootproof-sdk's own fixture
    // (bootproof/crates/bootproof-sdk/src/format/nitro.rs `CBOR_DATA`) is
    // gated behind a fixed `VALID_DURATION` tied to that certificate's
    // validity window and is not re-exported from the crate, so it cannot be
    // cheaply reused here without vendoring a binary fixture file into this
    // crate. This needs an integration-level fixture in canaryd (or a
    // re-exported test-only constant from bootproof-sdk) to cover the
    // positive path end-to-end.
}
