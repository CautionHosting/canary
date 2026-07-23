//! One-shot live verification of a Canary node and its current target claims.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{bail, Context, Result};
use canary_core::{
    canonical::digest,
    config::Target,
    evidence::{pcrs_from_hex, verify_evidence, EvidenceBundle},
    node::{ConfigDocument, IdentityMode},
    state::canonical_target_origin,
    statement::{Statement, Status},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::inspect::{self, InspectedNode, NodeTrust};

const SNAPSHOT_RETRIES: usize = 3;

pub(crate) struct VerificationOutcome {
    pub(crate) ok: bool,
    trust: String,
    identity: String,
    scope: String,
    attempt: Option<i64>,
    /// The identity and measured configuration that authenticated the target
    /// results below. These are intentionally available to in-process
    /// consumers such as the long-running watcher; the existing CLI renderers
    /// retain their stable public output.
    pub(crate) node_id: String,
    pub(crate) config_digest: String,
    pub(crate) deployments: Vec<DeploymentResult>,
    verbose: String,
}

/// A target result whose statement, configuration binding, signatures,
/// freshness, and (when present) evidence have all been verified.
pub(crate) struct VerifiedTargetResult {
    pub(crate) id: String,
    pub(crate) status: Status,
    pub(crate) reason: String,
    pub(crate) statement: Statement,
}

/// A per-target transport, parsing, or consistent-snapshot read failure. This
/// is deliberately distinct from both authenticated non-VERIFIED statements
/// and cryptographic/configuration verification failures.
pub(crate) struct TargetReadError {
    pub(crate) id: String,
    pub(crate) reason: String,
}

/// A target response was fetched, but its signatures, freshness, config
/// binding, or evidence relationship could not be authenticated.
pub(crate) struct TargetVerificationError {
    pub(crate) id: String,
    pub(crate) reason: String,
}

/// The outcome of reading one configured target from an otherwise verified
/// Canary node.
pub(crate) enum DeploymentResult {
    Verified(Box<VerifiedTargetResult>),
    ReadError(TargetReadError),
    VerificationError(TargetVerificationError),
}

impl DeploymentResult {
    fn id(&self) -> &str {
        match self {
            Self::Verified(result) => &result.id,
            Self::ReadError(error) => &error.id,
            Self::VerificationError(error) => &error.id,
        }
    }

    fn status_text(&self) -> &'static str {
        match self {
            Self::Verified(result) => status_text(result.status),
            Self::ReadError(_) | Self::VerificationError(_) => "ERROR",
        }
    }

    fn reason(&self) -> &str {
        match self {
            Self::Verified(result) => &result.reason,
            Self::ReadError(error) => &error.reason,
            Self::VerificationError(error) => &error.reason,
        }
    }
}

impl VerificationOutcome {
    pub(crate) fn concise_text(&self) -> String {
        let verified = self
            .deployments
            .iter()
            .filter(|deployment| deployment.status_text() == "VERIFIED")
            .count();
        let canary = match (self.trust.as_str(), self.identity.as_str()) {
            ("TOFU", _) => {
                "Canary: TOFU — identity/config not independently authenticated".to_owned()
            }
            ("ATTESTED", "ephemeral") => {
                "Canary: ATTESTED (ephemeral identity; re-enroll after restart)".to_owned()
            }
            ("ATTESTED", "stable") => "Canary: ATTESTED (stable identity)".to_owned(),
            _ => format!("Canary: {} ({})", self.trust, self.identity),
        };
        let mut output = format!(
            "{}  {}/{} deployment{}\n{}",
            if self.ok { "VERIFIED" } else { "NOT VERIFIED" },
            verified,
            self.deployments.len(),
            if self.deployments.len() == 1 { "" } else { "s" },
            canary,
        );
        for deployment in &self.deployments {
            let detail = if deployment.status_text() == "VERIFIED" {
                "PCR0/1/2 + signatures"
            } else {
                deployment.reason()
            };
            output.push_str(&format!(
                "\n{}  {}  {}",
                deployment.id(),
                deployment.status_text(),
                detail
            ));
        }
        output
    }

    pub(crate) fn json_result(&self) -> Value {
        json!({
            "trust": self.trust,
            "identity": self.identity,
            "scope": self.scope,
            "attempt": self.attempt,
            "deployments": self.deployments.iter().map(|deployment| json!({
                "id": deployment.id(),
                "status": deployment.status_text(),
                "reason": deployment.reason(),
            })).collect::<Vec<_>>(),
        })
    }

    pub(crate) fn verbose_text(&self) -> String {
        self.verbose.clone()
    }
}

pub fn run(
    base_url: &str,
    pcrs_file: Option<&Path>,
    insecure: bool,
    keys_path: &Path,
    requested_targets: &[String],
) -> Result<VerificationOutcome> {
    let started_at = Utc::now();
    let node = match (pcrs_file, insecure) {
        (Some(path), false) => inspect::inspect(base_url, path)?,
        (None, true) => inspect::inspect_unattested(base_url)?,
        (Some(_), true) | (None, false) => {
            bail!("pass exactly one of --pcrs or --insecure")
        }
    };
    node.verify_pinned_keys(keys_path)?;
    let targets = select_targets(&node.config, requested_targets)?;
    let mut authenticated_negative = false;
    let mut operational_error = false;
    let mut deployments = Vec::with_capacity(targets.len());
    let mut verbose =
        verification_context_text(started_at, requested_targets.is_empty(), targets.len());
    verbose.push_str(&node_report_text(&node, pcrs_file, keys_path));

    for target in targets {
        match fetch_and_verify_target(&node, target) {
            Ok(report) => {
                authenticated_negative |= report.status != Status::Verified;
                verbose.push_str(&target_report_text(target, &report, node.trust));
                deployments.push(DeploymentResult::Verified(Box::new(VerifiedTargetResult {
                    id: target.id.clone(),
                    status: report.status,
                    reason: report.reason.clone(),
                    statement: report.statement,
                })));
            }
            Err(TargetFetchError::Read(error)) => {
                operational_error = true;
                let reason = format!("{error:#}");
                verbose.push_str(&format!("\nDEPLOYMENT {}\n  Verification            ERROR\n  Error                   {}\n", target.id, reason));
                deployments.push(DeploymentResult::ReadError(TargetReadError {
                    id: target.id.clone(),
                    reason,
                }));
            }
            Err(TargetFetchError::Verification(error)) => {
                operational_error = true;
                let reason = format!("{error:#}");
                verbose.push_str(&format!("\nDEPLOYMENT {}\n  Verification            ERROR\n  Error                   {}\n", target.id, reason));
                deployments.push(DeploymentResult::VerificationError(
                    TargetVerificationError {
                        id: target.id.clone(),
                        reason,
                    },
                ));
            }
        }
    }
    Ok(VerificationOutcome {
        ok: !authenticated_negative && !operational_error,
        trust: trust_text(node.trust).to_owned(),
        identity: identity_text(&node),
        scope: "current".to_owned(),
        attempt: None,
        node_id: node.config.config.node_id.clone(),
        config_digest: node.config.config_digest.clone(),
        deployments,
        verbose,
    })
}

#[derive(Debug, Deserialize)]
struct HistoricalAttempt {
    observation: HistoricalObservation,
    statement: Statement,
    evidence: Option<EvidenceBundle>,
}

#[derive(Debug, Deserialize)]
struct HistoricalObservation {
    id: i64,
    target_id: String,
    attempted_at: DateTime<Utc>,
    attempt_reason: String,
    config_digest: String,
}

pub fn run_history(
    base_url: &str,
    pcrs_file: Option<&Path>,
    insecure: bool,
    keys_path: &Path,
    target_id: &str,
    attempt_id: i64,
) -> Result<VerificationOutcome> {
    if attempt_id < 1 {
        bail!("--attempt must be a positive history ID");
    }
    let node = match (pcrs_file, insecure) {
        (Some(path), false) => inspect::inspect(base_url, path)?,
        (None, true) => inspect::inspect_unattested(base_url)?,
        (Some(_), true) | (None, false) => {
            bail!("pass exactly one of --pcrs or --insecure")
        }
    };
    node.verify_pinned_keys(keys_path)?;
    let target = node
        .config
        .config
        .targets
        .iter()
        .find(|target| target.id == target_id)
        .with_context(|| format!("verified Canary config has no deployment {target_id:?}"))?;
    let attempt_segment = attempt_id.to_string();
    let historical: HistoricalAttempt = node
        .get_json(&["targets", target_id, "history", attempt_segment.as_str()])
        .with_context(|| format!("fetching historical attempt {attempt_id} for {target_id}"))?;

    if historical.observation.id != attempt_id
        || historical.observation.target_id != target_id
        || historical.statement.payload.target_id != target_id
    {
        bail!("historical response does not match the requested deployment and attempt");
    }
    if historical.observation.config_digest != historical.statement.payload.config_digest {
        bail!("historical summary config_digest does not match the signed statement");
    }
    let issued_at: DateTime<Utc> = historical
        .statement
        .payload
        .issued_at
        .parse()
        .context("parsing historical statement issued_at")?;
    verify_statement_binding(
        &node.config,
        &node.keys,
        target,
        &historical.statement,
        issued_at,
    )?;
    let report = match historical.evidence.as_ref() {
        Some(evidence) => verify_target_artifacts(
            &node.config,
            &node.keys,
            target,
            &historical.statement,
            Some(evidence),
            issued_at,
        )?,
        None => TargetReport::from_statement(&historical.statement, false, issued_at),
    };

    let mut verbose = node_report_text(&node, pcrs_file, keys_path);
    verbose.push_str(&format!(
        "\nHISTORICAL ATTEMPT {attempt_id}\n  Deployment              {target_id}\n  Attempted at            {}\n  Probe result            {}\n  Statement signatures    PASS\n  Statement validity      PASS AT SIGNED ISSUANCE TIME\n  Config binding          PASS\n  Evidence replay         {}\n  Signed status           {}\n  Signed reason           {}\n  History metadata        UNSIGNED / DIAGNOSTIC",
        historical.observation.attempted_at,
        historical.observation.attempt_reason,
        if report.evidence_replayed { "REPRODUCED" } else { "NOT AVAILABLE" },
        status_text(report.status),
        report.reason,
    ));
    Ok(VerificationOutcome {
        ok: report.status == Status::Verified,
        trust: trust_text(node.trust).to_owned(),
        identity: identity_text(&node),
        scope: "history".to_owned(),
        attempt: Some(attempt_id),
        node_id: node.config.config.node_id.clone(),
        config_digest: node.config.config_digest.clone(),
        deployments: vec![DeploymentResult::Verified(Box::new(VerifiedTargetResult {
            id: target_id.to_owned(),
            status: report.status,
            reason: report.reason.clone(),
            statement: report.statement,
        }))],
        verbose,
    })
}

fn select_targets<'a>(config: &'a ConfigDocument, requested: &[String]) -> Result<Vec<&'a Target>> {
    if requested.is_empty() {
        return Ok(config.config.targets.iter().collect());
    }

    let mut seen = HashSet::with_capacity(requested.len());
    let mut selected = Vec::with_capacity(requested.len());
    for id in requested {
        if !seen.insert(id.as_str()) {
            bail!("--deployment {id:?} was supplied more than once");
        }
        let target = config
            .config
            .targets
            .iter()
            .find(|target| target.id == *id)
            .with_context(|| format!("verified Canary config has no deployment {id:?}"))?;
        selected.push(target);
    }
    Ok(selected)
}

#[derive(Debug)]
struct TargetReport {
    status: Status,
    reason: String,
    statement: Statement,
    evidence_replayed: bool,
    target_origin: String,
    observed_at: Option<String>,
    issued_at: String,
    expires_at: String,
    evidence_digest: Option<String>,
    checked_at: DateTime<Utc>,
}

impl TargetReport {
    fn from_statement(
        statement: &Statement,
        evidence_replayed: bool,
        checked_at: DateTime<Utc>,
    ) -> Self {
        Self {
            status: statement.payload.status,
            reason: statement.payload.reason.clone(),
            statement: statement.clone(),
            evidence_replayed,
            target_origin: statement.payload.target_origin.clone(),
            observed_at: statement.payload.observed_at.clone(),
            issued_at: statement.payload.issued_at.clone(),
            expires_at: statement.payload.expires_at.clone(),
            evidence_digest: statement.payload.evidence_digest.clone(),
            checked_at,
        }
    }
}

#[derive(Debug)]
enum TargetFetchError {
    Read(anyhow::Error),
    Verification(anyhow::Error),
}

type TargetFetchResult<T> = std::result::Result<T, TargetFetchError>;

fn fetch_and_verify_target(
    node: &InspectedNode,
    target: &Target,
) -> TargetFetchResult<TargetReport> {
    fetch_and_verify_target_at(node, target, Utc::now())
}

fn fetch_and_verify_target_at(
    node: &InspectedNode,
    target: &Target,
    now: DateTime<Utc>,
) -> TargetFetchResult<TargetReport> {
    let statement_path = ["targets", target.id.as_str(), "statement"];
    let evidence_path = ["targets", target.id.as_str(), "evidence"];
    fetch_and_verify_target_with(
        &node.config,
        &node.keys,
        target,
        now,
        || {
            node.get_json(&statement_path)
                .with_context(|| format!("fetching signed statement for {}", target.id))
        },
        || {
            node.get_optional_json(&evidence_path)
                .with_context(|| format!("fetching evidence for {}", target.id))
        },
    )
}

fn fetch_and_verify_target_with<GetStatement, GetEvidence>(
    config: &ConfigDocument,
    keys: &canary_core::keys::KeysDocument,
    target: &Target,
    now: DateTime<Utc>,
    mut get_statement: GetStatement,
    mut get_evidence: GetEvidence,
) -> TargetFetchResult<TargetReport>
where
    GetStatement: FnMut() -> Result<Statement>,
    GetEvidence: FnMut() -> Result<Option<EvidenceBundle>>,
{
    for _ in 0..SNAPSHOT_RETRIES {
        let statement = get_statement().map_err(TargetFetchError::Read)?;
        verify_statement_binding(config, keys, target, &statement, now)
            .map_err(TargetFetchError::Verification)?;

        let Some(expected_digest) = statement.payload.evidence_digest.as_deref() else {
            return verify_target_artifacts(config, keys, target, &statement, None, now)
                .map_err(TargetFetchError::Verification);
        };

        let evidence = get_evidence().map_err(TargetFetchError::Read)?;
        let statement_after = get_statement().map_err(TargetFetchError::Read)?;

        if statement != statement_after {
            continue;
        }
        let Some(evidence) = evidence else {
            continue;
        };
        if evidence.evidence_digest != expected_digest
            || statement.payload.observed_at.as_deref() != Some(evidence.observed_at.as_str())
        {
            continue;
        }

        return verify_target_artifacts(config, keys, target, &statement, Some(&evidence), now)
            .map_err(TargetFetchError::Verification);
    }

    Err(TargetFetchError::Read(anyhow::anyhow!(
        "could not obtain a consistent statement/evidence snapshot after {SNAPSHOT_RETRIES} attempts"
    )))
}

fn verify_target_artifacts(
    config: &ConfigDocument,
    keys: &canary_core::keys::KeysDocument,
    target: &Target,
    statement: &Statement,
    evidence: Option<&EvidenceBundle>,
    now: DateTime<Utc>,
) -> Result<TargetReport> {
    verify_statement_binding(config, keys, target, statement, now)?;
    let payload = &statement.payload;

    match (payload.evidence_digest.as_deref(), evidence) {
        (None, None) => Ok(TargetReport::from_statement(statement, false, now)),
        (None, Some(_)) => bail!("statement carries no evidence digest but evidence was returned"),
        (Some(_), None) => bail!("statement references evidence but no evidence was returned"),
        (Some(expected_digest), Some(bundle)) => {
            if bundle.target_id != payload.target_id {
                bail!("evidence target_id does not match signed statement");
            }
            if bundle.evidence_digest != expected_digest {
                bail!("evidence digest does not match signed statement");
            }
            if payload.observed_at.as_deref() != Some(bundle.observed_at.as_str()) {
                bail!("evidence observation time does not match signed statement");
            }
            let decoded = bundle
                .decode_and_validate()
                .context("validating evidence bundle metadata and digests")?;
            let expected = pcrs_from_hex(
                &target.expected_pcrs.pcr0,
                &target.expected_pcrs.pcr1,
                &target.expected_pcrs.pcr2,
            )
            .context("decoding deployment PCR0/1/2 from verified Canary config")?;
            let seconds = decoded.observed_at.timestamp();
            if seconds < 0 {
                bail!("evidence observed_at is before the UNIX epoch");
            }
            let verification_time = std::time::Duration::new(
                seconds as u64,
                decoded.observed_at.timestamp_subsec_nanos(),
            );
            let outcome = verify_evidence(
                &decoded.document,
                &expected,
                &decoded.nonce,
                verification_time,
            );
            if outcome.evidence_digest != expected_digest {
                bail!("verified evidence digest does not match signed statement");
            }
            if outcome.reason.as_str() != payload.reason {
                bail!(
                    "evidence result {} does not match signed reason {}",
                    outcome.reason.as_str(),
                    payload.reason
                );
            }
            match payload.status {
                Status::Verified if !outcome.passed => {
                    bail!("VERIFIED statement is not supported by passing evidence")
                }
                Status::Failed if outcome.passed => {
                    bail!("FAILED statement is contradicted by passing evidence")
                }
                Status::Pending | Status::Unreachable | Status::Stale => {
                    bail!("non-definitive statement must not reference evidence")
                }
                Status::Verified | Status::Failed => {}
            }
            Ok(TargetReport::from_statement(statement, true, now))
        }
    }
}

fn verify_statement_binding(
    config: &ConfigDocument,
    keys: &canary_core::keys::KeysDocument,
    target: &Target,
    statement: &Statement,
    now: DateTime<Utc>,
) -> Result<()> {
    crate::verify::verify_at(statement, keys, now)?;
    let payload = &statement.payload;
    let expected_origin = canonical_target_origin(&target.attestation_url)
        .context("deriving target origin from verified Canary config")?;
    if payload.target_id != target.id {
        bail!("signed target_id does not match verified Canary config");
    }
    if payload.target_origin != expected_origin {
        bail!("signed target_origin does not match verified Canary config");
    }
    if payload.config_digest != config.config_digest {
        bail!("signed config_digest does not match verified Canary config");
    }
    if payload.verifier_id != config.config.node_id {
        bail!("signed verifier_id does not match verified Canary node");
    }
    Ok(())
}

fn verification_context_text(
    started_at: DateTime<Utc>,
    all_targets: bool,
    target_count: usize,
) -> String {
    format!(
        "CANARY VERIFY\n  Scope                   CURRENT PUBLISHED CLAIMS\n  Started at              {}\n  Deployments             {} ({target_count})\n",
        timestamp(started_at),
        if all_targets { "ALL CONFIGURED" } else { "SELECTED" }
    )
}

fn node_report_text(node: &InspectedNode, pcrs_file: Option<&Path>, keys_path: &Path) -> String {
    let mut output = String::from("\nCANARY NODE\n");
    match node.trust {
        NodeTrust::Attested => {
            writeln!(output, "  Trust mode              ATTESTED").unwrap();
            writeln!(output, "  Canary attestation      PASS — FRESH NONCE-BOUND").unwrap();
            writeln!(output, "  Canary workload PCRs    PASS — PCR0/1/2").unwrap();
            writeln!(
                output,
                "  Expected Canary PCRs    {}",
                pcrs_file
                    .expect("attested mode always has a PCR file")
                    .display()
            )
            .unwrap();
            writeln!(output, "  Transport policy        HTTPS ONLY").unwrap();
            writeln!(
                output,
                "  Config authenticity     PASS — MEASURED + ATTESTED"
            )
            .unwrap();
            writeln!(output, "  Signing keys            PASS — ATTESTED KEYSET").unwrap();
            match node
                .metadata
                .as_ref()
                .expect("attested inspection always retains signed metadata")
                .identity_mode
            {
                IdentityMode::Stable => {
                    writeln!(output, "  Identity lifecycle      STABLE — EXTERNAL SEED").unwrap();
                    writeln!(output, "  Pinned key continuity   PASS").unwrap();
                }
                IdentityMode::Ephemeral => {
                    writeln!(
                        output,
                        "  Identity lifecycle      EPHEMERAL — CURRENT PROCESS"
                    )
                    .unwrap();
                    writeln!(output, "  Current-process key pin PASS").unwrap();
                    writeln!(
                        output,
                        "  Restart behavior        NEW KEYS — RE-ENROLL REQUIRED"
                    )
                    .unwrap();
                }
            }
        }
        NodeTrust::UnattestedDev => {
            writeln!(output, "  Trust mode              TOFU").unwrap();
            writeln!(output, "  Canary attestation      SKIPPED — --insecure").unwrap();
            writeln!(output, "  Canary workload PCRs    NOT VERIFIED").unwrap();
            writeln!(output, "  Transport policy        HTTP ALLOWED").unwrap();
            writeln!(
                output,
                "  Config authenticity     NOT VERIFIED — SELF-CONSISTENT ONLY"
            )
            .unwrap();
            writeln!(output, "  Signing keys            NOT ATTESTED — TOFU PIN").unwrap();
            writeln!(output, "  Identity lifecycle      UNKNOWN — UNATTESTED").unwrap();
            writeln!(output, "  Pinned key continuity   PASS").unwrap();
        }
    }
    writeln!(output, "  Pinned keys             {}", keys_path.display()).unwrap();
    writeln!(
        output,
        "  Node ID                 {}",
        node.config.config.node_id
    )
    .unwrap();
    writeln!(
        output,
        "  Config digest           {}",
        node.config.config_digest
    )
    .unwrap();
    writeln!(
        output,
        "  Keyset digest           {}",
        digest(&node.keys_bytes)
    )
    .unwrap();
    output
}

fn trust_text(trust: NodeTrust) -> &'static str {
    match trust {
        NodeTrust::Attested => "ATTESTED",
        NodeTrust::UnattestedDev => "TOFU",
    }
}

fn identity_text(node: &InspectedNode) -> String {
    match node
        .metadata
        .as_ref()
        .map(|metadata| metadata.identity_mode)
    {
        Some(IdentityMode::Stable) => "stable".to_owned(),
        Some(IdentityMode::Ephemeral) => "ephemeral".to_owned(),
        None => "unknown".to_owned(),
    }
}

fn target_report_text(target: &Target, report: &TargetReport, trust: NodeTrust) -> String {
    let mut output = String::new();
    writeln!(output, "\nDEPLOYMENT {}", target.id).unwrap();
    writeln!(output, "  Claim                   CURRENT PUBLISHED").unwrap();
    writeln!(output, "  Deployment origin       {}", report.target_origin).unwrap();
    match trust {
        NodeTrust::Attested => {
            writeln!(
                output,
                "  PCR policy source       MEASURED + ATTESTED CONFIG"
            )
            .unwrap();
        }
        NodeTrust::UnattestedDev => {
            writeln!(
                output,
                "  PCR policy source       UNATTESTED CONFIG — TOFU SIGNER"
            )
            .unwrap();
        }
    }
    writeln!(
        output,
        "  Checked at              {}",
        timestamp(report.checked_at)
    )
    .unwrap();
    writeln!(
        output,
        "  Evidence observed at    {}",
        report.observed_at.as_deref().unwrap_or("—")
    )
    .unwrap();
    writeln!(output, "  Statement issued at     {}", report.issued_at).unwrap();
    writeln!(output, "  Statement expires at    {}", report.expires_at).unwrap();
    writeln!(
        output,
        "  Statement signatures    PASS — ED25519 + ML-DSA-65"
    )
    .unwrap();
    writeln!(output, "  Statement freshness     PASS AT CHECKED TIME").unwrap();
    writeln!(output, "  Statement/config binding PASS").unwrap();
    if report.evidence_replayed {
        let evidence_digest = report
            .evidence_digest
            .as_deref()
            .expect("replayed evidence always has a signed digest");
        writeln!(
            output,
            "  Statement/evidence link PASS — {}",
            evidence_digest
        )
        .unwrap();
        match report.status {
            Status::Verified => {
                writeln!(output, "  Evidence replay         PASS AT OBSERVED TIME").unwrap();
                writeln!(output, "  Deployment Nitro + PCRs PASS").unwrap();
            }
            Status::Failed => {
                writeln!(
                    output,
                    "  Evidence replay         REPRODUCED {} AT OBSERVED TIME",
                    report.reason
                )
                .unwrap();
                writeln!(output, "  Deployment Nitro + PCRs FAILED — AUTHENTICATED").unwrap();
            }
            Status::Pending | Status::Unreachable | Status::Stale => {
                unreachable!("non-definitive states cannot carry replayed evidence")
            }
        }
    } else {
        writeln!(output, "  Statement/evidence link NOT PRESENT").unwrap();
        writeln!(output, "  Evidence replay         NOT AVAILABLE").unwrap();
        writeln!(output, "  Deployment Nitro + PCRs NOT CHECKED").unwrap();
    }
    writeln!(
        output,
        "  Signed status           {}",
        status_text(report.status)
    )
    .unwrap();
    writeln!(output, "  Signed reason           {}", report.reason).unwrap();
    output
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn status_text(status: Status) -> &'static str {
    match status {
        Status::Verified => "VERIFIED",
        Status::Failed => "FAILED",
        Status::Pending => "PENDING",
        Status::Unreachable => "UNREACHABLE",
        Status::Stale => "STALE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use canary_core::{
        config::{Config, ExpectedPcrs},
        keys::{KeySet, MasterSeed},
        statement::{sign_statement, Payload, CLAIM_TYPE},
    };
    use chrono::Duration;

    const PCR_0_AND_1: &str = "ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03";
    const PCR_2: &str = "21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a";

    fn fixture(
        status: Status,
        reason: &str,
        pcr0: &str,
    ) -> (
        ConfigDocument,
        canary_core::keys::KeysDocument,
        Statement,
        EvidenceBundle,
        DateTime<Utc>,
    ) {
        let config = ConfigDocument::new(Config {
            version: 0,
            node_id: "caution-canary-demo".to_owned(),
            probe_interval_seconds: 60,
            history_limit: 1_000,
            targets: vec![Target {
                id: "payments-prod".to_owned(),
                name: "Payments production".to_owned(),
                attestation_url: "https://payments.example.com/attestation".to_owned(),
                expected_pcrs: ExpectedPcrs {
                    pcr0: pcr0.to_owned(),
                    pcr1: PCR_0_AND_1.to_owned(),
                    pcr2: PCR_2.to_owned(),
                },
            }],
        })
        .unwrap();
        let evidence: EvidenceBundle = serde_json::from_str(include_str!(
            "../../canary-core/tests/data/evidence-v0-vector.json"
        ))
        .unwrap();
        let observed: DateTime<Utc> = evidence.observed_at.parse().unwrap();
        let keyset = KeySet::derive(
            &MasterSeed::from_base64(&STANDARD.encode([0x42; 32])).unwrap(),
            &config.config.node_id,
        )
        .unwrap();
        let statement = sign_statement(
            Payload {
                claim_type: CLAIM_TYPE.to_owned(),
                target_id: "payments-prod".to_owned(),
                target_origin: "https://payments.example.com".to_owned(),
                status,
                reason: reason.to_owned(),
                config_digest: config.config_digest.clone(),
                evidence_digest: Some(evidence.evidence_digest.clone()),
                observed_at: Some(evidence.observed_at.clone()),
                issued_at: evidence.observed_at.clone(),
                expires_at: (observed + Duration::seconds(180)).to_rfc3339(),
                verifier_id: config.config.node_id.clone(),
                key_epoch: 0,
            },
            &keyset,
        )
        .unwrap();
        (
            config,
            keyset.keys_document(),
            statement,
            evidence,
            observed + Duration::seconds(1),
        )
    }

    #[test]
    fn verified_statement_and_evidence_validate_end_to_end() {
        let (config, keys, statement, evidence, now) =
            fixture(Status::Verified, "ALL_CHECKS_PASSED", PCR_0_AND_1);
        let report = verify_target_artifacts(
            &config,
            &keys,
            &config.config.targets[0],
            &statement,
            Some(&evidence),
            now,
        )
        .unwrap();
        assert_eq!(report.status, Status::Verified);
        assert!(report.evidence_replayed);

        let development =
            target_report_text(&config.config.targets[0], &report, NodeTrust::UnattestedDev);
        assert!(development.contains("Claim                   CURRENT PUBLISHED"));
        assert!(development.contains("PCR policy source       UNATTESTED CONFIG — TOFU SIGNER"));
        assert!(development.contains("Statement signatures    PASS — ED25519 + ML-DSA-65"));
        assert!(development.contains("Evidence replay         PASS AT OBSERVED TIME"));
        assert!(development.contains("Deployment Nitro + PCRs PASS"));
        assert!(development.contains(&format!("Checked at              {}", timestamp(now))));
        assert!(development.contains(&statement.payload.observed_at.clone().unwrap()));
        assert!(development.contains(&statement.payload.expires_at));

        let attested = target_report_text(&config.config.targets[0], &report, NodeTrust::Attested);
        assert!(attested.contains("PCR policy source       MEASURED + ATTESTED CONFIG"));
    }

    #[test]
    fn authenticated_pcr_mismatch_is_a_valid_negative_report() {
        let wrong_pcr = format!("{}0", &PCR_0_AND_1[..PCR_0_AND_1.len() - 1]);
        let (config, keys, statement, evidence, now) =
            fixture(Status::Failed, "PCR_MISMATCH", &wrong_pcr);
        let report = verify_target_artifacts(
            &config,
            &keys,
            &config.config.targets[0],
            &statement,
            Some(&evidence),
            now,
        )
        .unwrap();
        assert_eq!(report.status, Status::Failed);
        assert!(report.evidence_replayed);
        let output = target_report_text(&config.config.targets[0], &report, NodeTrust::Attested);
        assert!(output.contains("Evidence replay         REPRODUCED PCR_MISMATCH AT OBSERVED TIME"));
        assert!(output.contains("Deployment Nitro + PCRs FAILED — AUTHENTICATED"));
    }

    #[test]
    fn statement_to_evidence_digest_mismatch_is_rejected() {
        let (config, keys, statement, mut evidence, now) =
            fixture(Status::Verified, "ALL_CHECKS_PASSED", PCR_0_AND_1);
        evidence.evidence_digest = format!("sha256:{}", "0".repeat(64));
        let error = verify_target_artifacts(
            &config,
            &keys,
            &config.config.targets[0],
            &statement,
            Some(&evidence),
            now,
        )
        .unwrap_err();
        assert!(error.to_string().contains("evidence digest"));
    }

    #[test]
    fn target_selection_rejects_unknown_and_duplicate_ids() {
        let (config, _, _, _, _) = fixture(Status::Verified, "ALL_CHECKS_PASSED", PCR_0_AND_1);
        assert!(select_targets(&config, &["missing".to_owned()]).is_err());
        assert!(select_targets(
            &config,
            &["payments-prod".to_owned(), "payments-prod".to_owned()]
        )
        .is_err());
    }

    #[test]
    fn concise_and_json_renderers_keep_trust_and_failure_meaning() {
        let (_, _, verified_statement, _, _) =
            fixture(Status::Verified, "ALL_CHECKS_PASSED", PCR_0_AND_1);
        let attested = VerificationOutcome {
            ok: true,
            trust: "ATTESTED".to_owned(),
            identity: "stable".to_owned(),
            scope: "current".to_owned(),
            attempt: None,
            node_id: "canary-main".to_owned(),
            config_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            deployments: vec![DeploymentResult::Verified(Box::new(VerifiedTargetResult {
                id: "payments-prod".to_owned(),
                status: Status::Verified,
                reason: "ALL_CHECKS_PASSED".to_owned(),
                statement: verified_statement,
            }))],
            verbose: String::new(),
        };
        let text = attested.concise_text();
        assert!(text.contains("VERIFIED  1/1 deployment"));
        assert!(text.contains("Canary: ATTESTED (stable identity)"));
        assert!(text.contains("PCR0/1/2 + signatures"));
        match &attested.deployments[0] {
            DeploymentResult::Verified(result) => {
                assert_eq!(result.status, Status::Verified);
                assert_eq!(result.statement.payload.target_id, "payments-prod");
            }
            DeploymentResult::ReadError(_) | DeploymentResult::VerificationError(_) => {
                panic!("authenticated statement became an error")
            }
        }

        let (_, _, failed_statement, _, _) = fixture(Status::Failed, "PCR_MISMATCH", PCR_0_AND_1);
        let tofu_negative = VerificationOutcome {
            ok: false,
            trust: "TOFU".to_owned(),
            identity: "unknown".to_owned(),
            scope: "current".to_owned(),
            attempt: None,
            node_id: "canary-main".to_owned(),
            config_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            deployments: vec![DeploymentResult::Verified(Box::new(VerifiedTargetResult {
                id: "payments-prod".to_owned(),
                status: Status::Failed,
                reason: "PCR_MISMATCH".to_owned(),
                statement: failed_statement,
            }))],
            verbose: String::new(),
        };
        let text = tofu_negative.concise_text();
        assert!(text.contains("NOT VERIFIED  0/1 deployment"));
        assert!(text.contains("identity/config not independently authenticated"));
        assert!(text.contains("payments-prod  FAILED  PCR_MISMATCH"));
        assert_eq!(tofu_negative.json_result()["trust"], "TOFU");
        assert_eq!(
            tofu_negative.json_result()["deployments"][0]["reason"],
            "PCR_MISMATCH"
        );

        let read_error = DeploymentResult::ReadError(TargetReadError {
            id: "payments-prod".to_owned(),
            reason: "fetching signed statement: timeout".to_owned(),
        });
        assert_eq!(read_error.status_text(), "ERROR");
        assert_eq!(read_error.reason(), "fetching signed statement: timeout");

        let verification_error = DeploymentResult::VerificationError(TargetVerificationError {
            id: "payments-prod".to_owned(),
            reason: "statement signature verification failed".to_owned(),
        });
        assert_eq!(verification_error.status_text(), "ERROR");
        assert_eq!(
            verification_error.reason(),
            "statement signature verification failed"
        );
    }

    #[test]
    fn live_fetch_classifies_read_and_verification_errors() {
        let (config, keys, mut statement, _, now) =
            fixture(Status::Verified, "ALL_CHECKS_PASSED", PCR_0_AND_1);
        let target = &config.config.targets[0];

        let read_error = fetch_and_verify_target_with(
            &config,
            &keys,
            target,
            now,
            || Err(anyhow::anyhow!("transport timeout")),
            || Ok(None),
        )
        .unwrap_err();
        assert!(matches!(read_error, TargetFetchError::Read(_)));

        statement.payload.target_id = "substituted-target".to_owned();
        let verification_error = fetch_and_verify_target_with(
            &config,
            &keys,
            target,
            now,
            || Ok(statement.clone()),
            || Ok(None),
        )
        .unwrap_err();
        assert!(matches!(
            verification_error,
            TargetFetchError::Verification(_)
        ));
    }

    #[test]
    fn live_fetch_retries_a_changed_snapshot_and_missing_evidence() {
        let (config, keys, statement_a, evidence, now) =
            fixture(Status::Verified, "ALL_CHECKS_PASSED", PCR_0_AND_1);
        let keyset = KeySet::derive(
            &MasterSeed::from_base64(&STANDARD.encode([0x42; 32])).unwrap(),
            &config.config.node_id,
        )
        .unwrap();
        let mut payload_b = statement_a.payload.clone();
        payload_b.issued_at = now.to_rfc3339();
        let statement_b = sign_statement(payload_b, &keyset).unwrap();
        assert_ne!(statement_a, statement_b);
        let mut statements = VecDeque::from([
            statement_a,
            statement_b.clone(),
            statement_b.clone(),
            statement_b,
        ]);
        let mut evidence_results = VecDeque::from([None, Some(evidence)]);

        let report = fetch_and_verify_target_with(
            &config,
            &keys,
            &config.config.targets[0],
            now + Duration::seconds(1),
            || Ok(statements.pop_front().expect("next statement response")),
            || {
                Ok(evidence_results
                    .pop_front()
                    .expect("next evidence response"))
            },
        )
        .unwrap();

        assert_eq!(report.status, Status::Verified);
        assert!(report.evidence_replayed);
        assert!(statements.is_empty());
        assert!(evidence_results.is_empty());
    }
}
