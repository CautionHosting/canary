//! Offline verification of a frozen V0 evidence bundle.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use canary_core::evidence::{pcrs_from_hex, verify_evidence, EvidenceBundle};
use serde_json::{json, Value};

use crate::config_cmd::TrustedHashesFile;

pub(crate) struct OfflineEvidenceOutcome {
    target_id: String,
    observed_at: String,
    evidence_digest: String,
}

impl OfflineEvidenceOutcome {
    pub(crate) fn concise_text(&self) -> String {
        format!(
            "PARTIAL CHECK — evidence valid\n{}  observed {}",
            self.target_id, self.observed_at
        )
    }

    pub(crate) fn json_result(&self) -> Value {
        json!({"partial": true, "target_id": self.target_id, "observed_at": self.observed_at, "evidence_digest": self.evidence_digest})
    }
}

pub fn run_offline(evidence_path: &Path, pcrs_path: &Path) -> Result<OfflineEvidenceOutcome> {
    let text = std::fs::read_to_string(evidence_path)
        .with_context(|| format!("reading evidence bundle {}", evidence_path.display()))?;
    let bundle: EvidenceBundle = serde_json::from_str(&text)
        .with_context(|| format!("parsing evidence bundle {}", evidence_path.display()))?;
    let decoded = bundle
        .decode_and_validate()
        .context("validating evidence bundle metadata and digests")?;
    let trusted = TrustedHashesFile::load(pcrs_path)?.into_expected_pcrs();
    let expected = pcrs_from_hex(&trusted.pcr0, &trusted.pcr1, &trusted.pcr2)
        .context("decoding trusted PCR0/1/2")?;

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

    Ok(OfflineEvidenceOutcome {
        target_id: bundle.target_id,
        observed_at: bundle.observed_at,
        evidence_digest: outcome.evidence_digest,
    })
}
