//! `canaryctl capture` — fast POC TOFU enrollment (spec §4, §15 step 2b).
//!
//! Challenges a live target's `/attestation` endpoint, extracts candidate
//! PCR0/1/2 from the signed COSE_Sign1 document, validates the document's
//! chain/signature/nonce against exactly those candidate values, then
//! requires explicit human confirmation (or `--accept-tofu`) before writing
//! them into `canary.json`. This is Trust On First Use: it proves only that
//! future observations keep matching these live-enrolled values, never that
//! they match reviewed or independently reproduced source (spec §4, README
//! "Read this before enrolling PCRs").

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use canary_core::config::{validate_attestation_url, Config, ExpectedPcrs, Target};
use canary_core::evidence::{pcrs_from_hex, verify_evidence};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::config_cmd::{load_or_create_config, upsert_target, validate_and_write};

const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const MAX_ATTESTATION_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Serialize)]
struct NonceRequest {
    nonce: String,
}

#[derive(Deserialize)]
struct AttestationResponse {
    document: String,
    #[allow(dead_code)]
    #[serde(default)]
    manifest: serde_json::Value,
}

/// Candidate PCR0/1/2, lowercase hex, extracted from a signed attestation
/// document before Canary's own PCR-match policy exists for this target.
#[derive(Debug)]
struct CandidatePcrs {
    pcr0: String,
    pcr1: String,
    pcr2: String,
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    config_path: &Path,
    id: &str,
    name: &str,
    attestation_url: &str,
    node_id: Option<&str>,
    replace: bool,
    accept_tofu: bool,
) -> Result<()> {
    let config = preflight_config(config_path, id, name, attestation_url, node_id, replace)?;

    let mut nonce_bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|err| anyhow::anyhow!("OS CSPRNG failed while generating nonce: {err}"))?;
    let nonce_b64 = STANDARD.encode(nonce_bytes);

    let agent = ureq::AgentBuilder::new()
        .https_only(true)
        .redirects(0)
        .timeout(HTTP_TIMEOUT)
        .build();
    let http_response = agent
        .post(attestation_url)
        .set("Content-Type", "application/json")
        .send_json(NonceRequest { nonce: nonce_b64 })
        .with_context(|| format!("POST {attestation_url}"))?;

    let mut response_bytes = Vec::new();
    http_response
        .into_reader()
        .take((MAX_ATTESTATION_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response_bytes)
        .context("reading attestation response")?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX epoch")?;
    enroll_response(
        config_path,
        id,
        attestation_url,
        config,
        &nonce_bytes,
        &response_bytes,
        now,
        accept_tofu,
    )
}

fn preflight_config(
    config_path: &Path,
    id: &str,
    name: &str,
    attestation_url: &str,
    node_id: Option<&str>,
    replace: bool,
) -> Result<Config> {
    validate_attestation_url(id, attestation_url)
        .context("attestation URL failed validation; refusing network request")?;

    // Validate every operator-controlled config field, including replacement
    // semantics, before contacting the target. Candidate PCRs are replaced
    // with the verified values below before anything is written.
    let placeholder_pcr = hex::encode([1u8; 48]);
    let mut config = load_or_create_config(config_path, node_id)?;
    upsert_target(
        &mut config,
        Target {
            id: id.to_string(),
            name: name.to_string(),
            attestation_url: attestation_url.to_string(),
            expected_pcrs: ExpectedPcrs {
                pcr0: placeholder_pcr.clone(),
                pcr1: placeholder_pcr.clone(),
                pcr2: placeholder_pcr,
            },
        },
        replace,
    )?;
    config
        .validate()
        .context("proposed target failed validation; refusing network request")?;

    Ok(config)
}

#[allow(clippy::too_many_arguments)]
fn enroll_response(
    config_path: &Path,
    id: &str,
    attestation_url: &str,
    mut config: Config,
    nonce_bytes: &[u8; 32],
    response_bytes: &[u8],
    now: std::time::Duration,
    accept_tofu: bool,
) -> Result<()> {
    if response_bytes.len() > MAX_ATTESTATION_RESPONSE_BYTES {
        bail!("attestation response exceeds {MAX_ATTESTATION_RESPONSE_BYTES} byte limit");
    }
    let response: AttestationResponse =
        serde_json::from_slice(response_bytes).context("parsing attestation response JSON")?;

    let document_bytes = STANDARD
        .decode(&response.document)
        .context("decoding base64 attestation document")?;

    let candidate = extract_candidate_pcrs(&document_bytes)
        .context("extracting candidate PCR0/1/2 from the signed attestation document")?;

    let expected = pcrs_from_hex(&candidate.pcr0, &candidate.pcr1, &candidate.pcr2)
        .context("building expected-PCR map from candidate values")?;

    let outcome = verify_evidence(&document_bytes, &expected, nonce_bytes, now);
    if !outcome.passed {
        bail!(
            "attestation evidence did not validate against its own candidate PCRs: {}",
            outcome.reason.as_str()
        );
    }

    let enrolled_target = config
        .targets
        .iter_mut()
        .find(|target| target.id == id)
        .context("preflight target disappeared from config")?;
    enrolled_target.expected_pcrs = ExpectedPcrs {
        pcr0: candidate.pcr0.clone(),
        pcr1: candidate.pcr1.clone(),
        pcr2: candidate.pcr2.clone(),
    };
    config
        .validate()
        .context("captured PCR values failed config validation")?;

    println!("Captured candidate PCRs from {attestation_url}:");
    println!("  PCR0: {}", candidate.pcr0);
    println!("  PCR1: {}", candidate.pcr1);
    println!("  PCR2: {}", candidate.pcr2);
    println!();
    println!(
        "This is trust on first use (TOFU). This command verified fresh Bootproof \
         evidence and confirms the chain, signature and nonce are valid for the \
         PCR values shown above. It proves only that future observations continue \
         to match the exact values explicitly enrolled from this live endpoint."
    );
    println!(
        "It does NOT prove that these values match reviewed or independently \
         reproduced source. Run `caution verify --save-pcrs` first and use \
         `canaryctl config add --pcrs-file` for that stronger workflow."
    );

    if !accept_tofu && !confirm_interactively()? {
        bail!("TOFU capture not confirmed; aborting without writing canary.json");
    }

    let digest = validate_and_write(config_path, &config)?;

    println!("Wrote {}", config_path.display());
    println!("config_digest: {digest}");

    Ok(())
}

fn confirm_interactively() -> Result<bool> {
    print!("Enroll these TOFU PCR values into canary.json? [y/N] ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading confirmation from stdin")?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// Decode a COSE_Sign1 document and pull PCR0/1/2 out of its CBOR-encoded
/// payload map, as lowercase hex. This is intentionally local to `capture`:
/// it reads *candidate* values from an unauthenticated-until-verified
/// document, never establishes policy on its own.
fn extract_candidate_pcrs(document: &[u8]) -> Result<CandidatePcrs> {
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
        serde_cbor::Value::Bytes(b) => b.clone(),
        other => bail!("COSE_Sign1: expected byte-string payload, got {other:?}"),
    };

    let payload: serde_cbor::Value =
        serde_cbor::from_slice(&payload_bytes).context("CBOR-decoding attestation payload")?;

    let payload_map = match &payload {
        serde_cbor::Value::Map(m) => m,
        other => bail!("attestation payload: expected a map, got {other:?}"),
    };

    let pcrs_value = payload_map
        .get(&serde_cbor::Value::Text("pcrs".to_string()))
        .context("attestation payload has no \"pcrs\" field")?;
    let pcrs_map = match pcrs_value {
        serde_cbor::Value::Map(m) => m,
        other => bail!("attestation payload \"pcrs\": expected a map, got {other:?}"),
    };

    let pcr_hex = |index: u8| -> Result<String> {
        let key = serde_cbor::Value::Integer(index as i128);
        match pcrs_map.get(&key) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const VALID_TIME: std::time::Duration = std::time::Duration::from_secs(1_766_510_416);
    const NONCE: &str = "d041b23bce8678bbc7c174bd8494c4f9759386eec963ec69bfd45c1452b10636";
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_config_path(label: &str) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "canaryctl-capture-{label}-{}-{n}.json",
            std::process::id()
        ))
    }

    fn fixture_response() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "document": include_str!("../../canary-core/tests/data/aws-test.cbor.b64").trim(),
            "manifest": {},
        }))
        .unwrap()
    }

    fn fixture_nonce() -> [u8; 32] {
        hex::decode(NONCE).unwrap().try_into().unwrap()
    }

    fn build_document(pcrs: &[(i128, Vec<u8>)]) -> Vec<u8> {
        let mut pcr_pairs = Vec::new();
        for (k, v) in pcrs {
            pcr_pairs.push((
                serde_cbor::Value::Integer(*k),
                serde_cbor::Value::Bytes(v.clone()),
            ));
        }
        let pcrs_map = serde_cbor::Value::Map(pcr_pairs.into_iter().collect());
        let payload_map = serde_cbor::Value::Map(
            [(serde_cbor::Value::Text("pcrs".to_string()), pcrs_map)]
                .into_iter()
                .collect(),
        );
        let payload_bytes = serde_cbor::to_vec(&payload_map).unwrap();

        let cose = serde_cbor::Value::Array(vec![
            serde_cbor::Value::Bytes(vec![]),
            serde_cbor::Value::Map(Default::default()),
            serde_cbor::Value::Bytes(payload_bytes),
            serde_cbor::Value::Bytes(vec![0u8; 96]),
        ]);
        serde_cbor::to_vec(&cose).unwrap()
    }

    #[test]
    fn extracts_pcrs_from_well_formed_document() {
        let doc = build_document(&[
            (0, vec![0xaa; 48]),
            (1, vec![0xbb; 48]),
            (2, vec![0xcc; 48]),
            (3, vec![0xdd; 48]),
        ]);
        let candidate = extract_candidate_pcrs(&doc).unwrap();
        assert_eq!(candidate.pcr0, hex::encode([0xaa; 48]));
        assert_eq!(candidate.pcr1, hex::encode([0xbb; 48]));
        assert_eq!(candidate.pcr2, hex::encode([0xcc; 48]));
    }

    #[test]
    fn missing_pcr_errors() {
        let doc = build_document(&[(0, vec![0xaa; 48]), (1, vec![0xbb; 48])]);
        let err = extract_candidate_pcrs(&doc).unwrap_err();
        assert!(err.to_string().contains("PCR2"));
    }

    #[test]
    fn garbage_document_errors_not_panics() {
        let err = extract_candidate_pcrs(&[0xde, 0xad, 0xbe, 0xef]).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn verified_fixture_enrolls_through_accept_tofu_path() {
        let path = temp_config_path("accept");
        let url = "https://payments.example.com/attestation";
        let config = preflight_config(
            &path,
            "payments-prod",
            "Payments production",
            url,
            Some("caution-canary-demo"),
            false,
        )
        .unwrap();

        enroll_response(
            &path,
            "payments-prod",
            url,
            config,
            &fixture_nonce(),
            &fixture_response(),
            VALID_TIME,
            true,
        )
        .unwrap();

        let saved: Config = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved.targets.len(), 1);
        assert_eq!(
            saved.targets[0].expected_pcrs.pcr0,
            "ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn replayed_fixture_does_not_write_tofu_config() {
        let path = temp_config_path("replay");
        let url = "https://payments.example.com/attestation";
        let config = preflight_config(
            &path,
            "payments-prod",
            "Payments production",
            url,
            Some("caution-canary-demo"),
            false,
        )
        .unwrap();
        let wrong_nonce = [0x10; 32];

        let err = enroll_response(
            &path,
            "payments-prod",
            url,
            config,
            &wrong_nonce,
            &fixture_response(),
            VALID_TIME,
            true,
        )
        .unwrap_err();
        assert!(err.to_string().contains("NONCE_MISMATCH"));
        assert!(!path.exists());
    }
}
