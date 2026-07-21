//! Offline verification of a frozen V0 evidence bundle.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use canary_core::evidence::{pcrs_from_hex, verify_evidence, EvidenceBundle};

use crate::attestation::extract_candidate_pcrs;
use crate::config_cmd::TrustedHashesFile;

pub fn run_offline(evidence_path: &Path, pcrs_path: Option<&Path>, insecure: bool) -> Result<()> {
    let text = std::fs::read_to_string(evidence_path)
        .with_context(|| format!("reading evidence bundle {}", evidence_path.display()))?;
    let bundle: EvidenceBundle = serde_json::from_str(&text)
        .with_context(|| format!("parsing evidence bundle {}", evidence_path.display()))?;
    let decoded = bundle
        .decode_and_validate()
        .context("validating evidence bundle metadata and digests")?;
    let expected = expected_pcrs(pcrs_path, insecure, &decoded.document)?;

    let seconds = decoded.observed_at.timestamp();
    if seconds < 0 {
        bail!("evidence observed_at is before the UNIX epoch");
    }
    let verification_time =
        Duration::new(seconds as u64, decoded.observed_at.timestamp_subsec_nanos());
    let outcome = verify_evidence(
        &decoded.document,
        &expected,
        &decoded.nonce,
        verification_time,
    );
    if !outcome.passed {
        bail!(
            "evidence verification failed: {} ({})",
            outcome.reason.as_str(),
            outcome.evidence_digest
        );
    }

    if insecure {
        println!("PASS: Bootproof evidence is cryptographically valid");
        println!("WARNING: --insecure self-pinned PCR0/1/2 from the same evidence bundle; this does not verify workload identity.");
    } else {
        println!("PASS: Bootproof evidence is valid for the separately trusted PCRs");
    }
    println!("target_id: {}", bundle.target_id);
    println!("observed_at: {}", bundle.observed_at);
    println!("evidence_digest: {}", outcome.evidence_digest);
    println!(
        "Freshness is established only when this digest and observation time are bound by a trusted signed statement."
    );
    Ok(())
}

fn expected_pcrs(
    pcrs_path: Option<&Path>,
    insecure: bool,
    document: &[u8],
) -> Result<std::collections::HashMap<u8, Vec<u8>>> {
    validate_trust_source_selection(pcrs_path, insecure)?;
    match (pcrs_path, insecure) {
        (Some(path), false) => {
            let trusted = TrustedHashesFile::load(path)?.into_expected_pcrs();
            pcrs_from_hex(&trusted.pcr0, &trusted.pcr1, &trusted.pcr2)
                .context("decoding trusted PCR0/1/2")
        }
        (None, true) => {
            let candidate = extract_candidate_pcrs(document)
                .context("extracting candidate PCR0/1/2 for --insecure self-pinning")?;
            pcrs_from_hex(&candidate.pcr0, &candidate.pcr1, &candidate.pcr2)
                .context("decoding candidate PCR0/1/2 for --insecure self-pinning")
        }
        (Some(_), true) => bail!("pass exactly one of --pcrs-file or --insecure"),
        (None, false) => bail!("pass exactly one of --pcrs-file or --insecure"),
    }
}

fn validate_trust_source_selection(pcrs_path: Option<&Path>, insecure: bool) -> Result<()> {
    match (pcrs_path, insecure) {
        (Some(_), false) | (None, true) => Ok(()),
        (Some(_), true) | (None, false) => {
            bail!("pass exactly one of --pcrs-file or --insecure")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_mode_requires_exactly_one_trust_source() {
        let path = Path::new("trusted_hashes.json");
        assert!(validate_trust_source_selection(Some(path), false).is_ok());
        assert!(validate_trust_source_selection(None, true).is_ok());
        assert!(validate_trust_source_selection(Some(path), true)
            .unwrap_err()
            .to_string()
            .contains("exactly one"));
        assert!(validate_trust_source_selection(None, false)
            .unwrap_err()
            .to_string()
            .contains("exactly one"));
    }
}
