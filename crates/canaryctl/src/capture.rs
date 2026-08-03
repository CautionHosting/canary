//! TOFU enrollment backing `canaryctl deployment add --tofu`.
//!
//! Challenges a live target's `/attestation` endpoint, extracts candidate
//! PCR0/1/2 from the signed COSE_Sign1 document, validates the document's
//! chain/signature/nonce against exactly those candidate values, then
//! requires explicit human confirmation (or `--accept-tofu`) before writing
//! them into `canary.json`. This is Trust On First Use: it proves only that
//! future observations keep matching these live-enrolled values, never that
//! they match reviewed or independently reproduced source (spec §4).

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

use crate::attestation::extract_candidate_pcrs;
use crate::config_cmd::{load_or_create_config, upsert_target, validate_and_write};

const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const MAX_ATTESTATION_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub(crate) struct CaptureOutcome {
    pub(crate) config_digest: String,
    pub(crate) pcr0: String,
    pub(crate) pcr1: String,
    pub(crate) pcr2: String,
}

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

#[allow(clippy::too_many_arguments)]
pub fn run(
    config_path: &Path,
    id: &str,
    name: &str,
    attestation_url: &str,
    node_id: Option<&str>,
    replace: bool,
    accept_tofu: bool,
) -> Result<CaptureOutcome> {
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
            e2e_mode: None,
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
        .context("proposed deployment failed validation; refusing network request")?;

    Ok(config)
}

#[allow(clippy::too_many_arguments)]
fn enroll_response(
    config_path: &Path,
    id: &str,
    _attestation_url: &str,
    mut config: Config,
    nonce_bytes: &[u8; 32],
    response_bytes: &[u8],
    now: std::time::Duration,
    accept_tofu: bool,
) -> Result<CaptureOutcome> {
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
        .context("preflight deployment disappeared from config")?;
    enrolled_target.expected_pcrs = ExpectedPcrs {
        pcr0: candidate.pcr0.clone(),
        pcr1: candidate.pcr1.clone(),
        pcr2: candidate.pcr2.clone(),
    };
    config
        .validate()
        .context("captured PCR values failed config validation")?;

    if !accept_tofu {
        println!("Candidate PCRs from the live deployment:");
        println!("  PCR0: {}", candidate.pcr0);
        println!("  PCR1: {}", candidate.pcr1);
        println!("  PCR2: {}", candidate.pcr2);
        println!("WARNING: TOFU verifies fresh Nitro evidence, signatures, and nonce binding, but does not prove these values came from reviewed or reproduced source.");
    }
    if !accept_tofu && !confirm_interactively()? {
        bail!("TOFU capture not confirmed; aborting without writing canary.json");
    }

    Ok(CaptureOutcome {
        config_digest: validate_and_write(config_path, &config)?,
        pcr0: candidate.pcr0,
        pcr1: candidate.pcr1,
        pcr2: candidate.pcr2,
    })
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
