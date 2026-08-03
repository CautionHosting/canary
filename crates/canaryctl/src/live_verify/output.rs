//! Rendering for live and historical verification outcomes.

use std::fmt::Write as _;

use canary_core::{
    config::Target,
    evidence::AuthenticatedPcrClaims,
    statement::{Status, CADDY_CLAIM_TYPE},
    tls_binding::TLS_BINDING_MISMATCH_REASON,
};
use serde_json::{json, Value};

use crate::inspect::NodeTrust;

use super::{
    status_text, timestamp, DeploymentResult, HistoricalObservation, TargetReport,
    VerificationOutcome,
};

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
                match deployment {
                    DeploymentResult::Verified(result)
                        if result.statement.payload.claim_type == CADDY_CLAIM_TYPE =>
                    {
                        "PCR0/1/2 + TLS binding + signatures"
                    }
                    _ => "PCR0/1/2 + signatures",
                }
            } else {
                deployment.reason()
            };
            write!(
                output,
                "\n{}  {}  {}",
                deployment.id(),
                deployment.status_text(),
                detail
            )
            .unwrap();
            match deployment {
                DeploymentResult::Verified(result) => {
                    write_concise_pcrs(&mut output, result.pcr_claims.as_ref());
                    write_concise_tls(&mut output, &result.statement);
                }
                DeploymentResult::ReadError(_) | DeploymentResult::VerificationError(_) => {
                    write!(output, "\n  Authenticated PCRs UNAVAILABLE").unwrap();
                }
            }
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
                "tls": match deployment {
                    DeploymentResult::Verified(result) => serde_json::to_value(&result.statement.payload.tls)
                        .expect("TLS result is serializable"),
                    DeploymentResult::ReadError(_) | DeploymentResult::VerificationError(_) => Value::Null,
                },
                "pcrs": match deployment {
                    DeploymentResult::Verified(result) => pcrs_json(result.pcr_claims.as_ref()),
                    DeploymentResult::ReadError(_) | DeploymentResult::VerificationError(_) => Value::Null,
                },
            })).collect::<Vec<_>>(),
        })
    }

    pub(crate) fn verbose_text(&self) -> String {
        self.verbose.clone()
    }
}

pub(super) fn target_report_text(
    target: &Target,
    report: &TargetReport,
    trust: NodeTrust,
) -> String {
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
                if report.pcr_claims.is_some() {
                    writeln!(output, "  Deployment Nitro + PCRs FAILED — AUTHENTICATED").unwrap();
                } else {
                    writeln!(
                        output,
                        "  Deployment Nitro + PCRs FAILED — EVIDENCE NOT AUTHENTICATED"
                    )
                    .unwrap();
                }
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
    write_verbose_pcrs(&mut output, report.pcr_claims.as_ref());
    write_tls_binding(&mut output, &report.statement);
    writeln!(
        output,
        "  Signed status           {}",
        status_text(report.status)
    )
    .unwrap();
    writeln!(output, "  Signed reason           {}", report.reason).unwrap();
    output
}

pub(super) fn historical_attempt_text(
    attempt_id: i64,
    target_id: &str,
    observation: &HistoricalObservation,
    report: &TargetReport,
) -> String {
    let mut output = String::new();
    writeln!(output, "\nHISTORICAL ATTEMPT {attempt_id}").unwrap();
    writeln!(output, "  Deployment              {target_id}").unwrap();
    writeln!(
        output,
        "  Attempted at            {}",
        observation.attempted_at
    )
    .unwrap();
    writeln!(
        output,
        "  Probe result            {}",
        observation.attempt_reason
    )
    .unwrap();
    writeln!(output, "  Statement signatures    PASS").unwrap();
    writeln!(
        output,
        "  Statement validity      PASS AT SIGNED ISSUANCE TIME"
    )
    .unwrap();
    writeln!(output, "  Config binding          PASS").unwrap();
    writeln!(
        output,
        "  Evidence replay         {}",
        if report.evidence_replayed {
            "REPRODUCED"
        } else {
            "NOT AVAILABLE"
        }
    )
    .unwrap();
    write_verbose_pcrs(&mut output, report.pcr_claims.as_ref());
    write_tls_binding(&mut output, &report.statement);
    writeln!(
        output,
        "  Signed status           {}",
        status_text(report.status)
    )
    .unwrap();
    writeln!(output, "  Signed reason           {}", report.reason).unwrap();
    write!(output, "  History metadata        UNSIGNED / DIAGNOSTIC").unwrap();
    output
}

pub(super) fn target_error_text(target_id: &str, reason: &str) -> String {
    format!(
        "\nDEPLOYMENT {target_id}\n  Verification            ERROR\n  Authenticated PCRs      UNAVAILABLE\n  Error                   {reason}\n"
    )
}

fn write_concise_pcrs(output: &mut String, claims: Option<&AuthenticatedPcrClaims>) {
    let Some(claims) = claims else {
        write!(output, "\n  Authenticated PCRs UNAVAILABLE").unwrap();
        return;
    };
    for (index, observed, expected, matches) in pcr_rows(claims) {
        if matches {
            write!(output, "\n  PCR{index} {}  MATCH", compact_pcr(observed)).unwrap();
        } else {
            write!(
                output,
                "\n  PCR{index} observed={observed} expected={expected}  MISMATCH"
            )
            .unwrap();
        }
    }
}

fn write_concise_tls(output: &mut String, statement: &canary_core::statement::Statement) {
    if statement.payload.claim_type != CADDY_CLAIM_TYPE {
        return;
    }
    let Some(tls) = statement.payload.tls.as_ref() else {
        write!(
            output,
            "\n  TLS binding {}",
            if statement.payload.reason == TLS_BINDING_MISMATCH_REASON {
                "MISMATCH — certificate details unavailable"
            } else {
                "NOT EVALUATED"
            }
        )
        .unwrap();
        return;
    };
    let matched = statement.payload.status == Status::Verified;
    write!(
        output,
        "\n  TLS {} {} {}",
        tls.attested_mode,
        tls.attested_domain,
        if matched { "PASS" } else { "MISMATCH" }
    )
    .unwrap();
    if matched {
        write!(output, "\n    cert sha256:{}", tls.observed_certfp).unwrap();
    } else {
        write!(
            output,
            "\n    attested sha256:{}\n    observed sha256:{}",
            tls.attested_certfp, tls.observed_certfp
        )
        .unwrap();
    }
}

fn write_verbose_pcrs(output: &mut String, claims: Option<&AuthenticatedPcrClaims>) {
    let Some(claims) = claims else {
        writeln!(output, "  Authenticated PCRs      UNAVAILABLE").unwrap();
        return;
    };
    writeln!(output, "  Authenticated PCRs      VERIFIED").unwrap();
    for (index, observed, expected, matches) in pcr_rows(claims) {
        writeln!(output, "  PCR{index} observed           {observed}").unwrap();
        writeln!(output, "  PCR{index} expected           {expected}").unwrap();
        writeln!(
            output,
            "  PCR{index} comparison         {}",
            if matches { "PASS" } else { "FAIL" }
        )
        .unwrap();
    }
}

fn write_tls_binding(output: &mut String, statement: &canary_core::statement::Statement) {
    if statement.payload.claim_type != CADDY_CLAIM_TYPE {
        return;
    }
    if statement.payload.reason != "ALL_CHECKS_PASSED"
        && statement.payload.reason != TLS_BINDING_MISMATCH_REASON
    {
        writeln!(output, "  TLS/attestation binding NOT EVALUATED").unwrap();
        return;
    }
    let Some(tls) = statement.payload.tls.as_ref() else {
        writeln!(
            output,
            "  TLS/attestation binding MISMATCH — NO USABLE COMPARISON"
        )
        .unwrap();
        return;
    };
    writeln!(
        output,
        "  TLS/attestation binding {}",
        if statement.payload.status == Status::Verified {
            "PASS"
        } else {
            "MISMATCH"
        }
    )
    .unwrap();
    writeln!(output, "  Attested mode           {}", tls.attested_mode).unwrap();
    writeln!(output, "  Attested domain         {}", tls.attested_domain).unwrap();
    writeln!(output, "  Attested certfp         {}", tls.attested_certfp).unwrap();
    writeln!(output, "  Observed certfp         {}", tls.observed_certfp).unwrap();
}

fn pcrs_json(claims: Option<&AuthenticatedPcrClaims>) -> Value {
    let Some(claims) = claims else {
        return Value::Null;
    };
    json!({
        "evidence_authentication": "verified",
        "observed": {
            "0": claims.observed.pcr0,
            "1": claims.observed.pcr1,
            "2": claims.observed.pcr2,
        },
        "expected": {
            "0": claims.expected.pcr0,
            "1": claims.expected.pcr1,
            "2": claims.expected.pcr2,
        },
        "matches": {
            "0": claims.matches.pcr0,
            "1": claims.matches.pcr1,
            "2": claims.matches.pcr2,
        },
    })
}

fn pcr_rows(claims: &AuthenticatedPcrClaims) -> [(u8, &str, &str, bool); 3] {
    [
        (
            0,
            claims.observed.pcr0.as_str(),
            claims.expected.pcr0.as_str(),
            claims.matches.pcr0,
        ),
        (
            1,
            claims.observed.pcr1.as_str(),
            claims.expected.pcr1.as_str(),
            claims.matches.pcr1,
        ),
        (
            2,
            claims.observed.pcr2.as_str(),
            claims.expected.pcr2.as_str(),
            claims.matches.pcr2,
        ),
    ]
}

fn compact_pcr(value: &str) -> String {
    format!("{}...{}", &value[..4], &value[value.len() - 4..])
}
