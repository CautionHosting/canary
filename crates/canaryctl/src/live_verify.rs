//! One-shot live verification of a Canary node and its current target claims.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context, Result};
use canary_core::{
    config::Target,
    evidence::{pcrs_from_hex, verify_evidence, EvidenceBundle},
    node::ConfigDocument,
    state::canonical_target_origin,
    statement::{Statement, Status},
};
use chrono::{DateTime, Utc};

use crate::inspect::{self, InspectedNode};

const SNAPSHOT_RETRIES: usize = 3;

pub fn run(
    base_url: &str,
    pcrs_file: Option<&Path>,
    insecure: bool,
    requested_targets: &[String],
    keys_out: Option<&Path>,
) -> Result<()> {
    let node = inspect::inspect(base_url, pcrs_file, insecure)?;
    print_node_report(&node);
    let targets = select_targets(&node.config, requested_targets)?;
    let mut authenticated_negative = false;
    let mut errors = Vec::new();

    for target in targets {
        match fetch_and_verify_target(&node, target) {
            Ok(report) => {
                print_target_report(target, &report);
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
        println!("\nRESULT: ERROR");
        bail!("verification failed for target(s): {}", errors.join(", "));
    }
    if authenticated_negative {
        println!("\nRESULT: AUTHENTICATED_NEGATIVE");
        bail!("one or more targets reported a valid signed state other than VERIFIED");
    }
    if let Some(path) = keys_out {
        node.write_keys(path)?;
        println!("\nKeys written: {}", path.display());
    }
    if insecure {
        println!("\nRESULT: PASS (INSECURE NODE IDENTITY)");
    } else {
        println!("\nRESULT: PASS");
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
        (None, None) => Ok(TargetReport {
            status: payload.status,
            reason: payload.reason.clone(),
            evidence_replayed: false,
        }),
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
            Ok(TargetReport {
                status: payload.status,
                reason: payload.reason.clone(),
                evidence_replayed: true,
            })
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

fn print_node_report(node: &InspectedNode) {
    println!("CANARY NODE");
    println!("  Nitro attestation       PASS");
    if node.insecure {
        println!("  Canary PCR identity     INSECURE / SELF-REPORTED");
        println!("  Transport policy        INSECURE / HTTP ALLOWED");
    } else {
        println!("  Canary PCR identity     PASS");
        println!("  Transport policy        HTTPS ONLY");
    }
    println!("  Config binding          PASS");
    println!("  Signing-key binding     PASS");
    println!("  Node ID                 {}", node.metadata.node_id);
    println!("  Config digest           {}", node.metadata.config_digest);
}

fn print_target_report(target: &Target, report: &TargetReport) {
    println!("\nTARGET {}", target.id);
    println!("  Statement signatures    PASS");
    println!("  Statement freshness     PASS");
    println!("  Config binding          PASS");
    if report.evidence_replayed {
        println!("  Evidence replay         PASS");
        match report.status {
            Status::Verified => println!("  Target PCR policy       PASS"),
            Status::Failed => println!("  Target PCR policy       FAILED / AUTHENTICATED"),
            Status::Pending | Status::Unreachable | Status::Stale => {
                unreachable!("non-definitive states cannot carry replayed evidence")
            }
        }
    } else {
        println!("  Evidence replay         NOT AVAILABLE");
        println!("  Target PCR policy       SIGNED STATE ONLY");
    }
    println!("  Status                  {}", status_text(report.status));
    println!("  Reason                  {}", report.reason);
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
