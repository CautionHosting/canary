//! Shared verifier-side parsing for live Bootproof responses.

use anyhow::{bail, Context, Result};

/// Candidate PCR0/1/2, lowercase hex, extracted from a signed attestation
/// document. These values are not policy until the caller explicitly chooses
/// TOFU mode and verifies the same document against them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidatePcrs {
    pub(crate) pcr0: String,
    pub(crate) pcr1: String,
    pub(crate) pcr2: String,
}

/// Decode a COSE_Sign1 document and pull PCR0/1/2 out of its CBOR payload.
/// This deliberately only extracts candidate values; callers must still run
/// `canary_core::evidence::verify_evidence` before accepting anything.
pub(crate) fn extract_candidate_pcrs(document: &[u8]) -> Result<CandidatePcrs> {
    let top: serde_cbor::Value =
        serde_cbor::from_slice(document).context("CBOR-decoding COSE_Sign1 document")?;
    let elements = match top {
        serde_cbor::Value::Array(elements) => elements,
        serde_cbor::Value::Tag(_, inner) => match *inner {
            serde_cbor::Value::Array(elements) => elements,
            other => bail!("COSE_Sign1: expected a tagged array, got {other:?}"),
        },
        other => bail!("COSE_Sign1: expected an array, got {other:?}"),
    };
    if elements.len() != 4 {
        bail!(
            "COSE_Sign1: expected 4 elements (protected, unprotected, payload, signature), got {}",
            elements.len()
        );
    }
    let payload_bytes = match &elements[2] {
        serde_cbor::Value::Bytes(bytes) => bytes.clone(),
        other => bail!("COSE_Sign1: expected byte-string payload, got {other:?}"),
    };
    let payload: serde_cbor::Value =
        serde_cbor::from_slice(&payload_bytes).context("CBOR-decoding attestation payload")?;
    let payload_map = match &payload {
        serde_cbor::Value::Map(map) => map,
        other => bail!("attestation payload: expected a map, got {other:?}"),
    };
    let pcrs_value = payload_map
        .get(&serde_cbor::Value::Text("pcrs".to_string()))
        .context("attestation payload has no \"pcrs\" field")?;
    let pcrs_map = match pcrs_value {
        serde_cbor::Value::Map(map) => map,
        other => bail!("attestation payload \"pcrs\": expected a map, got {other:?}"),
    };
    let pcr_hex = |index: u8| -> Result<String> {
        match pcrs_map.get(&serde_cbor::Value::Integer(index.into())) {
            Some(serde_cbor::Value::Bytes(bytes)) => Ok(hex::encode(bytes)),
            Some(other) => bail!("PCR{index}: expected a byte-string, got {other:?}"),
            None => bail!("attestation payload is missing PCR{index}"),
        }
    };
    Ok(CandidatePcrs {
        pcr0: pcr_hex(0)?,
        pcr1: pcr_hex(1)?,
        pcr2: pcr_hex(2)?,
    })
}
