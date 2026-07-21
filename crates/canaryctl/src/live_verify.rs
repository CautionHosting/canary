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

use crate::inspect::{self, InspectedNode, NodeTrust};

const SNAPSHOT_RETRIES: usize = 3;

pub fn run(
    base_url: &str,
    pcrs_file: Option<&Path>,
    insecure: bool,
    keys_path: &Path,
    requested_targets: &[String],
) -> Result<()> {
    let started_at = Utc::now();
    let node = match (pcrs_file, insecure) {
        (Some(path), false) => inspect::inspect(base_url, path)?,
        (None, true) => inspect::inspect_unattested(base_url)?,
        (Some(_), true) | (None, false) => {
            bail!("pass exactly one of --pcrs-file or --insecure")
        }
    };
    node.verify_pinned_keys(keys_path)?;
    let targets = select_targets(&node.config, requested_targets)?;
    print_verification_context(started_at, requested_targets.is_empty(), targets.len());
    print_node_report(&node, pcrs_file, keys_path);
    let mut authenticated_negative = false;
    let mut errors = Vec::new();

    for target in targets {
        match fetch_and_verify_target(&node, target) {
            Ok(report) => {
                print_target_report(target, &report, node.trust);
                authenticated_negative |= report.status != Status::Verified;
            }
            Err(error) => {
                println!("\nTARGET {}", target.id);
                println!("  Verification            ERROR");
                println!("  Error                   {error:#}");
                errors.push(target.id.clone());
            }
        }
    }

    if !errors.is_empty() {
        println!("\nRESULT: ERROR — VERIFICATION CHAIN INCOMPLETE");
        bail!("verification failed for target(s): {}", errors.join(", "));
    }
    if authenticated_negative {
        match node.trust {
            NodeTrust::Attested => {
                println!("\nRESULT: AUTHENTICATED_NEGATIVE — CHAIN VALID, TARGET NOT VERIFIED")
            }
            NodeTrust::UnattestedDev => {
                println!("\nRESULT: SIGNED_NEGATIVE — TOFU SIGNER VALID, TARGET NOT VERIFIED")
            }
        }
        bail!("one or more targets reported a structurally valid signed state other than VERIFIED");
    }
    match node.trust {
        NodeTrust::Attested => println!("\nRESULT: PASS — FULL ATTESTED CHAIN VERIFIED"),
        NodeTrust::UnattestedDev => {
            println!("\nRESULT: PASS — VERIFIED AGAINST TOFU SIGNER + UNATTESTED CONFIG")
        }
    }
    Ok(())
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
) -> Result<()> {
    if attempt_id < 1 {
        bail!("--attempt must be a positive history ID");
    }
    let node = match (pcrs_file, insecure) {
        (Some(path), false) => inspect::inspect(base_url, path)?,
        (None, true) => inspect::inspect_unattested(base_url)?,
        (Some(_), true) | (None, false) => {
            bail!("pass exactly one of --pcrs-file or --insecure")
        }
    };
    node.verify_pinned_keys(keys_path)?;
    print_node_report(&node, pcrs_file, keys_path);
    let target = node
        .config
        .config
        .targets
        .iter()
        .find(|target| target.id == target_id)
        .with_context(|| format!("verified Canary config has no target {target_id:?}"))?;
    let attempt_segment = attempt_id.to_string();
    let historical: HistoricalAttempt = node
        .get_json(&["targets", target_id, "history", attempt_segment.as_str()])
        .with_context(|| format!("fetching historical attempt {attempt_id} for {target_id}"))?;

    if historical.observation.id != attempt_id
        || historical.observation.target_id != target_id
        || historical.statement.payload.target_id != target_id
    {
        bail!("historical response does not match the requested target and attempt");
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

    println!("\nHISTORICAL ATTEMPT {attempt_id}");
    println!("  Target                  {target_id}");
    println!(
        "  Attempted at            {}",
        historical.observation.attempted_at
    );
    println!(
        "  Probe result            {}",
        historical.observation.attempt_reason
    );
    println!("  Statement signatures    PASS");
    println!("  Statement validity      PASS AT SIGNED ISSUANCE TIME");
    println!("  Config binding          PASS");
    if report.evidence_replayed {
        println!("  Statement/evidence link PASS");
        println!("  Evidence replay         REPRODUCED {}", report.reason);
    } else {
        println!("  Evidence replay         NOT AVAILABLE FOR THIS ATTEMPT");
    }
    println!("  Signed status           {}", status_text(report.status));
    println!("  Signed reason           {}", report.reason);
    println!("  History metadata        UNSIGNED / DIAGNOSTIC");
    match (node.trust, report.evidence_replayed) {
        (NodeTrust::Attested, true) => println!("\nRESULT: HISTORICAL CLAIM REPRODUCED"),
        (NodeTrust::Attested, false) => {
            println!("\nRESULT: HISTORICAL STATEMENT VERIFIED; ATTEMPT EVIDENCE NOT AVAILABLE")
        }
        (NodeTrust::UnattestedDev, true) => println!(
            "\nRESULT: HISTORICAL CLAIM REPRODUCED (DEV MODE: CANARY IDENTITY NOT VERIFIED)"
        ),
        (NodeTrust::UnattestedDev, false) => println!(
            "\nRESULT: HISTORICAL STATEMENT VERIFIED; ATTEMPT EVIDENCE NOT AVAILABLE (DEV MODE: CANARY IDENTITY NOT VERIFIED)"
        ),
    }
    Ok(())
}

fn select_targets<'a>(config: &'a ConfigDocument, requested: &[String]) -> Result<Vec<&'a Target>> {
    if requested.is_empty() {
        return Ok(config.config.targets.iter().collect());
    }

    let mut seen = HashSet::with_capacity(requested.len());
    let mut selected = Vec::with_capacity(requested.len());
    for id in requested {
        if !seen.insert(id.as_str()) {
            bail!("--target {id:?} was supplied more than once");
        }
        let target = config
            .config
            .targets
            .iter()
            .find(|target| target.id == *id)
            .with_context(|| format!("verified Canary config has no target {id:?}"))?;
        selected.push(target);
    }
    Ok(selected)
}

#[derive(Debug)]
struct TargetReport {
    status: Status,
    reason: String,
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

fn fetch_and_verify_target(node: &InspectedNode, target: &Target) -> Result<TargetReport> {
    fetch_and_verify_target_at(node, target, Utc::now())
}

fn fetch_and_verify_target_at(
    node: &InspectedNode,
    target: &Target,
    now: DateTime<Utc>,
) -> Result<TargetReport> {
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
) -> Result<TargetReport>
where
    GetStatement: FnMut() -> Result<Statement>,
    GetEvidence: FnMut() -> Result<Option<EvidenceBundle>>,
{
    for _ in 0..SNAPSHOT_RETRIES {
        let statement = get_statement()?;
        verify_statement_binding(config, keys, target, &statement, now)?;

        let Some(expected_digest) = statement.payload.evidence_digest.as_deref() else {
            return verify_target_artifacts(config, keys, target, &statement, None, now);
        };

        let evidence = get_evidence()?;
        let statement_after = get_statement()?;

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

        return verify_target_artifacts(config, keys, target, &statement, Some(&evidence), now);
    }

    bail!(
        "could not obtain a consistent statement/evidence snapshot after {SNAPSHOT_RETRIES} attempts"
    )
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
            .context("decoding target PCR0/1/2 from verified Canary config")?;
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

fn print_verification_context(started_at: DateTime<Utc>, all_targets: bool, target_count: usize) {
    println!("CANARY VERIFY");
    println!("  Scope                   CURRENT PUBLISHED CLAIMS");
    println!("  Started at              {}", timestamp(started_at));
    if all_targets {
        println!("  Targets                 ALL CONFIGURED ({target_count})");
    } else {
        println!("  Targets                 SELECTED ({target_count})");
    }
}

fn print_node_report(node: &InspectedNode, pcrs_file: Option<&Path>, keys_path: &Path) {
    println!();
    println!("CANARY NODE");
    match node.trust {
        NodeTrust::Attested => {
            println!("  Trust mode              ATTESTED");
            println!("  Canary attestation      PASS — FRESH NONCE-BOUND");
            println!("  Canary workload PCRs    PASS — PCR0/1/2");
            println!(
                "  Expected Canary PCRs    {}",
                pcrs_file
                    .expect("attested mode always has a PCR file")
                    .display()
            );
            println!("  Transport policy        HTTPS ONLY");
            println!("  Config authenticity     PASS — MEASURED + ATTESTED");
            println!("  Signing keys            PASS — ATTESTED KEYSET");
            match node
                .metadata
                .as_ref()
                .expect("attested inspection always retains signed metadata")
                .identity_mode
            {
                IdentityMode::Stable => {
                    println!("  Identity lifecycle      STABLE — EXTERNAL SEED");
                    println!("  Pinned key continuity   PASS");
                }
                IdentityMode::Ephemeral => {
                    println!("  Identity lifecycle      EPHEMERAL — CURRENT PROCESS");
                    println!("  Current-process key pin PASS");
                    println!("  Restart behavior        NEW KEYS — RE-ENROLL REQUIRED");
                }
            }
        }
        NodeTrust::UnattestedDev => {
            println!("  Trust mode              DEVELOPMENT / TOFU");
            println!("  Canary attestation      SKIPPED — --insecure");
            println!("  Canary workload PCRs    NOT VERIFIED");
            println!("  Transport policy        HTTP ALLOWED");
            println!("  Config authenticity     NOT VERIFIED — SELF-CONSISTENT ONLY");
            println!("  Signing keys            NOT ATTESTED — TOFU PIN");
            println!("  Identity lifecycle      UNKNOWN — UNATTESTED");
            println!("  Pinned key continuity   PASS");
        }
    }
    println!("  Pinned keys             {}", keys_path.display());
    println!("  Node ID                 {}", node.config.config.node_id);
    println!("  Config digest           {}", node.config.config_digest);
    println!("  Keyset digest           {}", digest(&node.keys_bytes));
}

fn print_target_report(target: &Target, report: &TargetReport, trust: NodeTrust) {
    print!("{}", target_report_text(target, report, trust));
}

fn target_report_text(target: &Target, report: &TargetReport, trust: NodeTrust) -> String {
    let mut output = String::new();
    writeln!(output, "\nTARGET {}", target.id).unwrap();
    writeln!(output, "  Claim                   CURRENT PUBLISHED").unwrap();
    writeln!(output, "  Target origin           {}", report.target_origin).unwrap();
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
                writeln!(output, "  Target Nitro + PCRs     PASS").unwrap();
            }
            Status::Failed => {
                writeln!(
                    output,
                    "  Evidence replay         REPRODUCED {} AT OBSERVED TIME",
                    report.reason
                )
                .unwrap();
                writeln!(output, "  Target Nitro + PCRs     FAILED — AUTHENTICATED").unwrap();
            }
            Status::Pending | Status::Unreachable | Status::Stale => {
                unreachable!("non-definitive states cannot carry replayed evidence")
            }
        }
    } else {
        writeln!(output, "  Statement/evidence link NOT PRESENT").unwrap();
        writeln!(output, "  Evidence replay         NOT AVAILABLE").unwrap();
        writeln!(output, "  Target Nitro + PCRs     NOT CHECKED").unwrap();
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
        assert!(development.contains("Target Nitro + PCRs     PASS"));
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
        assert!(output.contains("Target Nitro + PCRs     FAILED — AUTHENTICATED"));
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
