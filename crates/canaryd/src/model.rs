//! Shared immutable runtime and persistence models for `canaryd`.
//!
//! These types intentionally keep the Phase 1 `Statement` and
//! `EvidenceBundle` intact.  They are snapshots copied out of the scheduler;
//! SQLite records them transactionally but never supplies initial runtime
//! state after a restart.

use canary_core::{
    evidence::EvidenceBundle,
    node::IdentityMode,
    statement::{Statement, Status},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Local execution-environment hint reported by `canaryd`.
///
/// This is presentation metadata, not remote-attestation evidence. An
/// untrusted process can lie about it; external verifiers must still use the
/// fresh Canary attestation flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEnvironment {
    NitroEnclave,
    NonEnclave,
}

/// Immutable identity details for this exact daemon process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeIdentity {
    pub environment: ExecutionEnvironment,
    pub binary_digest: String,
    pub identity_mode: IdentityMode,
}

/// The immutable per-target view consumed by the public API.
///
/// `statement` is the frozen Phase 1 envelope.  `evidence` is kept separate
/// so callers can serve the exact raw bundle only from its dedicated endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetSnapshot {
    pub id: String,
    pub name: String,
    pub target_origin: String,
    pub status: Status,
    pub reason: String,
    pub observed_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub transport_warning: Option<String>,
    pub statement: Statement,
    pub evidence: Option<EvidenceBundle>,
}

/// Atomically published process-local state.  A scheduler replaces the whole
/// value only after [`crate::store::Store::commit`] succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSnapshot {
    pub protocol: String,
    pub node_id: String,
    pub config_digest: String,
    pub runtime: RuntimeIdentity,
    pub generated_at: DateTime<Utc>,
    pub targets: Vec<TargetSnapshot>,
}

/// One completed probe and the signed/current snapshot it produced.
///
/// All nullable fields are intentional: transport failures and malformed
/// response bodies can have no decoded evidence, nonce, or manifest digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptWrite {
    /// Post-reduction current state. This can retain older fresh verified
    /// evidence when this specific attempt was a transport failure.
    pub target: TargetSnapshot,
    pub attempted_at: DateTime<Utc>,
    /// Cause returned by this one probe.  The attempt's `state` and `reason`
    /// remain those of the post-reduction target snapshot, so one timeout
    /// cannot be misreported as `UNREACHABLE` before the reducer threshold.
    pub attempt_reason: String,
    /// Response observation time for this attempt only.
    pub attempt_observed_at: Option<DateTime<Utc>>,
    /// Raw evidence returned by this attempt only. Transport attempts that
    /// retain current evidence must leave this `None`.
    pub attempt_evidence: Option<EvidenceBundle>,
    pub attempt_transport_warning: Option<String>,
    pub latency_ms: Option<u64>,
    pub config_digest: String,
}

/// A signed current-state publication with no completed network attempt.
///
/// Startup `PENDING` and timer-derived `STALE`/`UNREACHABLE` use this path so
/// they cannot manufacture an observation-history row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentWrite {
    pub target: TargetSnapshot,
    pub config_digest: String,
}

impl AttemptWrite {
    /// Build a history-safe summary.  It intentionally excludes raw evidence,
    /// nonce, and the signed envelope (spec §13 history contract).
    pub fn history_entry(&self, id: i64) -> HistoryEntry {
        HistoryEntry {
            id,
            target_id: self.target.id.clone(),
            attempted_at: self.attempted_at,
            observed_at: self.attempt_observed_at,
            status: self.target.status,
            reason: self.target.reason.clone(),
            attempt_reason: self.attempt_reason.clone(),
            latency_ms: self.latency_ms,
            evidence_digest: self
                .attempt_evidence
                .as_ref()
                .map(|e| e.evidence_digest.clone()),
            manifest_digest: self
                .attempt_evidence
                .as_ref()
                .map(|e| e.manifest_digest.clone()),
            config_digest: self.config_digest.clone(),
            transport_warning: self.attempt_transport_warning.clone(),
        }
    }
}

/// A bounded, newest-first API/history record.  It contains no raw attestation
/// material, nonce, or signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: i64,
    pub target_id: String,
    pub attempted_at: DateTime<Utc>,
    pub observed_at: Option<DateTime<Utc>>,
    pub status: Status,
    pub reason: String,
    pub attempt_reason: String,
    pub latency_ms: Option<u64>,
    pub evidence_digest: Option<String>,
    pub manifest_digest: Option<String>,
    pub config_digest: String,
    pub transport_warning: Option<String>,
}

/// Exact artifacts retained for one completed probe attempt.
///
/// `observation` is unsigned diagnostic metadata. `statement` is the signed
/// post-attempt Canary claim, while `evidence` is the exact nonce-bound target
/// attestation bundle received by that attempt when one could be decoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalAttempt {
    pub observation: HistoryEntry,
    pub statement: Statement,
    pub evidence: Option<EvidenceBundle>,
}
