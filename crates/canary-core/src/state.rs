//! Pure per-target monitoring state (spec §9 and §10).
//!
//! This module deliberately has no clock, I/O, storage, or signing dependency.
//! Callers inject the observation time into events and ask the reducer to derive
//! a view at their selected time.  That makes expiry boundaries testable and
//! prevents an HTTP read from silently changing monitor state.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::evidence::ProbeReason;
use crate::statement::Status;
use crate::tls_binding::TlsBindingResult;

/// Fixed V0 statement/result lifetime (spec §6, §9, §10).
pub const RESULT_TTL: Duration = Duration::seconds(180);

/// Stable signed/current-state reasons.  This is the total Phase 2 mapping:
/// Phase 1 verifier reasons plus the two derived state reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StateReason {
    Pending,
    Stale,
    AllChecksPassed,
    PcrMismatch,
    DebugOrZeroPcr,
    InvalidCertificateChain,
    InvalidSignature,
    NonceMismatch,
    MalformedEvidence,
    TlsBindingMismatch,
    HttpError,
    Timeout,
    Unreachable,
    InternalError,
}

impl StateReason {
    /// Exact stable wire string used by the existing `Payload.reason` field.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Stale => "STALE",
            Self::AllChecksPassed => "ALL_CHECKS_PASSED",
            Self::PcrMismatch => "PCR_MISMATCH",
            Self::DebugOrZeroPcr => "DEBUG_OR_ZERO_PCR",
            Self::InvalidCertificateChain => "INVALID_CERTIFICATE_CHAIN",
            Self::InvalidSignature => "INVALID_SIGNATURE",
            Self::NonceMismatch => "NONCE_MISMATCH",
            Self::MalformedEvidence => "MALFORMED_EVIDENCE",
            Self::TlsBindingMismatch => "TLS_BINDING_MISMATCH",
            Self::HttpError => "HTTP_ERROR",
            Self::Timeout => "TIMEOUT",
            Self::Unreachable => "UNREACHABLE",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }

    /// Whether this reason is a transport attempt rather than a definitive
    /// evidence-verification result.
    pub const fn is_transport(self) -> bool {
        matches!(self, Self::HttpError | Self::Timeout | Self::Unreachable)
    }

    /// Whether this reason can represent a reachable definitive result.
    pub const fn is_definitive(self) -> bool {
        !matches!(self, Self::Pending | Self::Stale) && !self.is_transport()
    }
}

impl From<ProbeReason> for StateReason {
    fn from(reason: ProbeReason) -> Self {
        match reason {
            ProbeReason::AllChecksPassed => Self::AllChecksPassed,
            ProbeReason::PcrMismatch => Self::PcrMismatch,
            ProbeReason::DebugOrZeroPcr => Self::DebugOrZeroPcr,
            ProbeReason::InvalidCertificateChain => Self::InvalidCertificateChain,
            ProbeReason::InvalidSignature => Self::InvalidSignature,
            ProbeReason::NonceMismatch => Self::NonceMismatch,
            ProbeReason::MalformedEvidence => Self::MalformedEvidence,
            ProbeReason::TlsBindingMismatch => Self::TlsBindingMismatch,
            ProbeReason::HttpError => Self::HttpError,
            ProbeReason::Timeout => Self::Timeout,
            ProbeReason::Unreachable => Self::Unreachable,
            ProbeReason::InternalError => Self::InternalError,
        }
    }
}

/// A completed, reachable probe result.  `VERIFIED` is represented only by
/// `ALL_CHECKS_PASSED`; every other Phase 1 verification reason is `FAILED`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinitiveObservation {
    pub reason: StateReason,
    pub observed_at: DateTime<Utc>,
    /// The decoded-document digest, when document bytes were available.
    pub evidence_digest: Option<String>,
    pub tls: Option<TlsBindingResult>,
}

impl DefinitiveObservation {
    pub fn new(
        reason: StateReason,
        observed_at: DateTime<Utc>,
        evidence_digest: Option<String>,
    ) -> Result<Self, StateError> {
        Self::new_with_tls(reason, observed_at, evidence_digest, None)
    }

    pub fn new_with_tls(
        reason: StateReason,
        observed_at: DateTime<Utc>,
        evidence_digest: Option<String>,
        tls: Option<TlsBindingResult>,
    ) -> Result<Self, StateError> {
        if !reason.is_definitive() {
            return Err(StateError::NotDefinitiveReason(reason));
        }
        if reason == StateReason::AllChecksPassed && evidence_digest.is_none() {
            return Err(StateError::VerifiedWithoutEvidence);
        }
        if reason == StateReason::TlsBindingMismatch && evidence_digest.is_none() {
            return Err(StateError::TlsBindingWithoutEvidence);
        }
        if tls.is_some()
            && !matches!(
                reason,
                StateReason::AllChecksPassed | StateReason::TlsBindingMismatch
            )
        {
            return Err(StateError::TlsBindingWithWrongReason(reason));
        }
        Ok(Self {
            reason,
            observed_at,
            evidence_digest,
            tls,
        })
    }

    pub fn status(&self) -> Status {
        if self.reason == StateReason::AllChecksPassed {
            Status::Verified
        } else {
            Status::Failed
        }
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.observed_at + RESULT_TTL
    }
}

/// A no-response transport result.  These never replace fresh definitive
/// evidence; they only accumulate a warning/outage count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportFailure {
    pub reason: StateReason,
}

impl TransportFailure {
    pub fn new(reason: StateReason) -> Result<Self, StateError> {
        if !reason.is_transport() {
            return Err(StateError::NotTransportReason(reason));
        }
        Ok(Self { reason })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateError {
    #[error("{0:?} is not a definitive evidence reason")]
    NotDefinitiveReason(StateReason),
    #[error("{0:?} is not a transport reason")]
    NotTransportReason(StateReason),
    #[error("a verified observation requires an evidence digest")]
    VerifiedWithoutEvidence,
    #[error("a TLS binding mismatch requires verified evidence")]
    TlsBindingWithoutEvidence,
    #[error("TLS binding result cannot accompany {0:?}")]
    TlsBindingWithWrongReason(StateReason),
    #[error("invalid configured attestation URL: {0}")]
    InvalidTargetUrl(#[from] url::ParseError),
    #[error("target origin must be an HTTPS URL without credentials")]
    InvalidTargetOrigin,
}

/// Canonical serialized HTTPS origin for a configured attestation URL.
///
/// `url` performs IDNA normalization, lower-cases the host, and elides the
/// default port.  Paths, queries and fragments intentionally do not enter the
/// origin or any signed statement bytes.
pub fn canonical_target_origin(attestation_url: &str) -> Result<String, StateError> {
    let url = Url::parse(attestation_url)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(StateError::InvalidTargetOrigin);
    }
    let origin = url.origin().ascii_serialization();
    if origin == "null" {
        return Err(StateError::InvalidTargetOrigin);
    }
    Ok(origin)
}

/// The pure result of evaluating one target at an injected instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedTargetState {
    pub status: Status,
    pub reason: StateReason,
    pub evidence_digest: Option<String>,
    pub tls: Option<TlsBindingResult>,
    pub observed_at: Option<DateTime<Utc>>,
    /// Present only while a definitive result is current.  The scheduler uses
    /// this deadline to enqueue the active expiry transition exactly on time.
    pub definitive_expires_at: Option<DateTime<Utc>>,
    /// A non-definitive transport failure while fresh evidence remains current.
    pub transport_warning: Option<StateReason>,
}

/// Per-target reducer.  Each instance is independent; callers must use one
/// reducer per configured target and publish any signed snapshot atomically.
#[derive(Debug, Default, Clone)]
pub struct TargetReducer {
    definitive: Option<DefinitiveObservation>,
    completed_probe: bool,
    consecutive_transport_failures: u32,
    transport_warning: Option<StateReason>,
}

impl TargetReducer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a completed definitive observation.  An older late-arriving
    /// observation cannot displace a newer one.  Equal timestamps are accepted
    /// as a later completion because they cannot be ordered more precisely in
    /// the frozen whole-second evidence format.
    pub fn apply_definitive(&mut self, observation: DefinitiveObservation) -> bool {
        self.completed_probe = true;
        if self
            .definitive
            .as_ref()
            .is_some_and(|current| current.observed_at > observation.observed_at)
        {
            return false;
        }
        self.definitive = Some(observation);
        self.consecutive_transport_failures = 0;
        self.transport_warning = None;
        true
    }

    /// Record a completed transport failure.  It never changes a fresh
    /// definitive state, but is retained as a public warning and determines
    /// whether expiry derives `UNREACHABLE` instead of `STALE`.
    pub fn apply_transport_failure(&mut self, failure: TransportFailure) {
        self.completed_probe = true;
        self.consecutive_transport_failures = self.consecutive_transport_failures.saturating_add(1);
        self.transport_warning = Some(failure.reason);
    }

    pub fn definitive_expiry(&self) -> Option<DateTime<Utc>> {
        self.definitive
            .as_ref()
            .map(DefinitiveObservation::expires_at)
    }

    pub fn consecutive_transport_failures(&self) -> u32 {
        self.consecutive_transport_failures
    }

    /// Derive the current state without mutation.  At the exact expiry instant
    /// (`now >= expires_at`), the definitive observation is no longer current;
    /// schedulers must sign and publish this derived negative state immediately.
    pub fn derive_at(&self, now: DateTime<Utc>) -> DerivedTargetState {
        if !self.completed_probe {
            return DerivedTargetState {
                status: Status::Pending,
                reason: StateReason::Pending,
                evidence_digest: None,
                tls: None,
                observed_at: None,
                definitive_expires_at: None,
                transport_warning: None,
            };
        }

        if let Some(observation) = &self.definitive {
            let expires_at = observation.expires_at();
            if now < expires_at {
                return DerivedTargetState {
                    status: observation.status(),
                    reason: observation.reason,
                    evidence_digest: observation.evidence_digest.clone(),
                    tls: observation.tls.clone(),
                    observed_at: Some(observation.observed_at),
                    definitive_expires_at: Some(expires_at),
                    transport_warning: self.transport_warning,
                };
            }
        }

        let (status, reason) = if self.consecutive_transport_failures >= 3 {
            (
                Status::Unreachable,
                self.transport_warning.unwrap_or(StateReason::Unreachable),
            )
        } else {
            (Status::Stale, StateReason::Stale)
        };
        DerivedTargetState {
            status,
            reason,
            evidence_digest: None,
            tls: None,
            observed_at: None,
            definitive_expires_at: None,
            transport_warning: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(second: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(second, 0).single().unwrap()
    }

    fn valid() -> DefinitiveObservation {
        DefinitiveObservation::new(
            StateReason::AllChecksPassed,
            at(1_000),
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
        )
        .unwrap()
    }

    #[test]
    fn startup_is_pending() {
        let state = TargetReducer::new().derive_at(at(1_000));
        assert_eq!(state.status, Status::Pending);
        assert_eq!(state.reason, StateReason::Pending);
        assert_eq!(state.evidence_digest, None);
    }

    #[test]
    fn match_is_verified_until_exact_expiry_then_stale() {
        let mut reducer = TargetReducer::new();
        reducer.apply_definitive(valid());
        assert_eq!(reducer.derive_at(at(1_179)).status, Status::Verified);
        let expired = reducer.derive_at(at(1_180));
        assert_eq!(expired.status, Status::Stale);
        assert_eq!(expired.reason, StateReason::Stale);
        assert_eq!(expired.evidence_digest, None);
        assert_eq!(
            reducer
                .derive_at(at(1_180) + Duration::nanoseconds(1))
                .status,
            Status::Stale
        );
    }

    #[test]
    fn validation_failure_replaces_success_and_success_recovers() {
        let mut reducer = TargetReducer::new();
        reducer.apply_definitive(valid());
        reducer.apply_definitive(
            DefinitiveObservation::new(
                StateReason::PcrMismatch,
                at(1_001),
                Some("sha256:bb".into()),
            )
            .unwrap(),
        );
        assert_eq!(reducer.derive_at(at(1_001)).status, Status::Failed);
        reducer.apply_definitive(
            DefinitiveObservation::new(
                StateReason::AllChecksPassed,
                at(1_002),
                Some("sha256:cc".into()),
            )
            .unwrap(),
        );
        assert_eq!(reducer.derive_at(at(1_002)).status, Status::Verified);
    }

    #[test]
    fn tls_mismatch_immediately_replaces_fresh_success_with_diagnostics() {
        let mut reducer = TargetReducer::new();
        reducer.apply_definitive(valid());
        let tls = TlsBindingResult {
            attested_mode: "caddy".to_owned(),
            attested_domain: "app.example.com".to_owned(),
            attested_certfp: "a".repeat(64),
            observed_certfp: "b".repeat(64),
        };
        reducer.apply_definitive(
            DefinitiveObservation::new_with_tls(
                StateReason::TlsBindingMismatch,
                at(1_001),
                Some(format!("sha256:{}", "b".repeat(64))),
                Some(tls.clone()),
            )
            .unwrap(),
        );
        let failed = reducer.derive_at(at(1_001));
        assert_eq!(failed.status, Status::Failed);
        assert_eq!(failed.reason, StateReason::TlsBindingMismatch);
        assert_eq!(failed.tls, Some(tls));
        assert_eq!(
            DefinitiveObservation::new_with_tls(
                StateReason::TlsBindingMismatch,
                at(1_002),
                None,
                None,
            )
            .unwrap_err(),
            StateError::TlsBindingWithoutEvidence
        );
    }

    #[test]
    fn expired_validation_failure_is_not_preserved_forever() {
        let mut reducer = TargetReducer::new();
        reducer.apply_definitive(
            DefinitiveObservation::new(StateReason::InvalidSignature, at(1_000), None).unwrap(),
        );
        assert_eq!(reducer.derive_at(at(1_179)).status, Status::Failed);
        assert_eq!(reducer.derive_at(at(1_180)).status, Status::Stale);
    }

    #[test]
    fn transport_warning_preserves_fresh_statement_state() {
        let mut reducer = TargetReducer::new();
        reducer.apply_definitive(valid());
        reducer.apply_transport_failure(TransportFailure::new(StateReason::Timeout).unwrap());
        let state = reducer.derive_at(at(1_001));
        assert_eq!(state.status, Status::Verified);
        assert_eq!(state.transport_warning, Some(StateReason::Timeout));
        assert_eq!(reducer.consecutive_transport_failures(), 1);
    }

    #[test]
    fn three_transport_failures_derive_unreachable_after_expiry() {
        let mut reducer = TargetReducer::new();
        reducer.apply_definitive(valid());
        for reason in [
            StateReason::Unreachable,
            StateReason::HttpError,
            StateReason::Timeout,
        ] {
            reducer.apply_transport_failure(TransportFailure::new(reason).unwrap());
        }
        let state = reducer.derive_at(at(1_180));
        assert_eq!(state.status, Status::Unreachable);
        assert_eq!(state.reason, StateReason::Timeout);
    }

    #[test]
    fn transport_only_completion_is_stale_then_unreachable() {
        let mut reducer = TargetReducer::new();
        reducer.apply_transport_failure(TransportFailure::new(StateReason::Timeout).unwrap());
        assert_eq!(reducer.derive_at(at(1)).status, Status::Stale);
        reducer.apply_transport_failure(TransportFailure::new(StateReason::Timeout).unwrap());
        reducer.apply_transport_failure(TransportFailure::new(StateReason::Unreachable).unwrap());
        assert_eq!(reducer.derive_at(at(1)).status, Status::Unreachable);
    }

    #[test]
    fn old_definitive_completion_cannot_roll_back_state() {
        let mut reducer = TargetReducer::new();
        assert!(reducer.apply_definitive(valid()));
        assert!(!reducer.apply_definitive(
            DefinitiveObservation::new(StateReason::PcrMismatch, at(999), None).unwrap()
        ));
        assert_eq!(reducer.derive_at(at(1_001)).status, Status::Verified);
    }

    #[test]
    fn reason_mapping_is_total_and_exact() {
        for reason in [
            ProbeReason::AllChecksPassed,
            ProbeReason::PcrMismatch,
            ProbeReason::DebugOrZeroPcr,
            ProbeReason::InvalidCertificateChain,
            ProbeReason::InvalidSignature,
            ProbeReason::NonceMismatch,
            ProbeReason::MalformedEvidence,
            ProbeReason::TlsBindingMismatch,
            ProbeReason::HttpError,
            ProbeReason::Timeout,
            ProbeReason::Unreachable,
            ProbeReason::InternalError,
        ] {
            assert_eq!(StateReason::from(reason).as_str(), reason.as_str());
        }
        assert_eq!(StateReason::Pending.as_str(), "PENDING");
        assert_eq!(StateReason::Stale.as_str(), "STALE");
    }

    #[test]
    fn target_origin_is_canonical_and_discards_path() {
        assert_eq!(
            canonical_target_origin("https://B\u{00dc}CHER.example:443/attestation?x=1").unwrap(),
            "https://xn--bcher-kva.example"
        );
        assert!(canonical_target_origin("http://example.com").is_err());
        assert!(canonical_target_origin("https://user@example.com").is_err());
        assert!(canonical_target_origin("https://example.com/#fragment").is_err());
    }
}
