//! One bounded, DNS-pinned Bootproof target probe (spec §§7, 10 and 11).
//!
//! This module owns transport policy and response parsing only.  Attestation
//! verification remains in `canary_core::evidence`; in particular it never
//! reads the unsigned Bootproof manifest as policy and never talks to NSM.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use canary_core::canonical::digest_canonical;
use canary_core::config::Target;
use canary_core::evidence::{
    evidence_digest, pcrs_from_hex, verify_evidence, AuthenticatedPcrClaims, EvidenceBundle,
    ProbeReason, EVIDENCE_PROTOCOL,
};
use chrono::{DateTime, SecondsFormat, Utc};
use rand::RngCore;
use serde::Deserialize;
use thiserror::Error;

use crate::network::{resolve_and_pin, PinnedTarget, Resolver};

/// Fixed V0 network limits. They are deliberately code constants, never live
/// configuration (approved Phase 2 decision 4).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Whether an attempt may replace current definitive state, or is merely a
/// transport warning while prior evidence is still fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeClassification {
    Definitive,
    Transport,
}

/// Complete outcome required by the state reducer and SQLite history writer.
#[derive(Debug, Clone)]
pub struct ProbeAttempt {
    pub target_id: String,
    pub attempted_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    /// Present only for a reachable response with a decodable document.
    pub observed_at: Option<DateTime<Utc>>,
    pub latency: Duration,
    pub classification: ProbeClassification,
    pub reason: ProbeReason,
    pub evidence: Option<EvidenceBundle>,
    pub evidence_claims: Option<AuthenticatedPcrClaims>,
    pub evidence_digest: Option<String>,
    pub manifest_digest: Option<String>,
}

impl ProbeAttempt {
    fn transport(
        target_id: &str,
        attempted_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
        latency: Duration,
        reason: ProbeReason,
    ) -> Self {
        Self {
            target_id: target_id.to_owned(),
            attempted_at,
            completed_at,
            observed_at: None,
            latency,
            classification: ProbeClassification::Transport,
            reason,
            evidence: None,
            evidence_claims: None,
            evidence_digest: None,
            manifest_digest: None,
        }
    }

    fn definitive(
        target_id: &str,
        attempted_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
        latency: Duration,
        reason: ProbeReason,
        evidence: EvidenceBundle,
        evidence_claims: Option<AuthenticatedPcrClaims>,
    ) -> Self {
        Self {
            target_id: target_id.to_owned(),
            attempted_at,
            completed_at,
            observed_at: Some(completed_at),
            latency,
            classification: ProbeClassification::Definitive,
            reason,
            evidence_digest: Some(evidence.evidence_digest.clone()),
            manifest_digest: Some(evidence.manifest_digest.clone()),
            evidence: Some(evidence),
            evidence_claims,
        }
    }

    fn malformed(
        target_id: &str,
        attempted_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
        latency: Duration,
    ) -> Self {
        Self {
            target_id: target_id.to_owned(),
            attempted_at,
            completed_at,
            // A reachable malformed response is still a definitive observation
            // made at this instant; only its evidence digest is absent.
            observed_at: Some(completed_at),
            latency,
            classification: ProbeClassification::Definitive,
            reason: ProbeReason::MalformedEvidence,
            evidence: None,
            evidence_claims: None,
            evidence_digest: None,
            manifest_digest: None,
        }
    }

    fn without_evidence(
        target_id: &str,
        attempted_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
        latency: Duration,
        reason: ProbeReason,
    ) -> Self {
        if matches!(
            reason,
            ProbeReason::HttpError | ProbeReason::Timeout | ProbeReason::Unreachable
        ) {
            return Self::transport(target_id, attempted_at, completed_at, latency, reason);
        }
        Self {
            target_id: target_id.to_owned(),
            attempted_at,
            completed_at,
            observed_at: Some(completed_at),
            latency,
            classification: ProbeClassification::Definitive,
            reason,
            evidence: None,
            evidence_claims: None,
            evidence_digest: None,
            manifest_digest: None,
        }
    }
}

/// Bounded successful HTTP response. Non-2xx and redirects are represented as
/// transport errors before the body reaches Bootproof parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub body: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("request timed out")]
    Timeout,
    #[error("target returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("target response exceeds {MAX_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,
    #[error("request failed: {0}")]
    Request(#[source] reqwest::Error),
    #[error("HTTP client setup failed: {0}")]
    Client(#[source] reqwest::Error),
}

impl TransportError {
    fn reason(&self) -> ProbeReason {
        match self {
            Self::Timeout => ProbeReason::Timeout,
            Self::HttpStatus(_) | Self::ResponseTooLarge => ProbeReason::HttpError,
            Self::Request(error) if error.is_timeout() => ProbeReason::Timeout,
            Self::Request(_) => ProbeReason::Unreachable,
            Self::Client(_) => ProbeReason::InternalError,
        }
    }
}

/// HTTP boundary for deterministic response-parser tests. Production uses
/// [`ReqwestTransport`], which builds one client per pinned attempt.
#[async_trait::async_trait]
pub trait ProbeTransport: Send + Sync {
    async fn post_bootproof(
        &self,
        target: &PinnedTarget,
        nonce_base64: &str,
    ) -> Result<HttpResponse, TransportError>;
}

/// Rustls HTTP transport that preserves URL hostname/SNI while pinning TCP to
/// the selected DNS result. Redirects are surfaced as `HTTP_ERROR`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReqwestTransport;

#[async_trait::async_trait]
impl ProbeTransport for ReqwestTransport {
    async fn post_bootproof(
        &self,
        target: &PinnedTarget,
        nonce_base64: &str,
    ) -> Result<HttpResponse, TransportError> {
        let client = pinned_client(target)?;

        let mut response = client
            .post(target.url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({ "nonce": nonce_base64 }))
            .send()
            .await
            .map_err(TransportError::Request)?;
        if !response.status().is_success() {
            return Err(TransportError::HttpStatus(response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(TransportError::ResponseTooLarge);
        }

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(TransportError::Request)? {
            append_bounded(&mut body, &chunk)?;
        }
        Ok(HttpResponse { body })
    }
}

fn append_bounded(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), TransportError> {
    if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
        return Err(TransportError::ResponseTooLarge);
    }
    body.extend_from_slice(chunk);
    Ok(())
}

/// Build an attempt-scoped client with exactly one permitted TCP destination.
///
/// `no_proxy` is a security boundary, not merely a deployment preference:
/// environment-controlled HTTP(S) proxy settings would otherwise let the
/// request bypass `resolve` and invalidate the DNS-pinning guarantee.
fn pinned_client(target: &PinnedTarget) -> Result<reqwest::Client, TransportError> {
    reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(ATTEMPT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        // The URL remains host-based, so reqwest uses `hostname` for Host and
        // TLS SNI; only the actual TCP peer is pinned to this socket.
        .resolve(&target.hostname, target.socket)
        .build()
        .map_err(TransportError::Client)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootproofResponse {
    document: String,
    manifest: serde_json::Value,
}

/// Generate a fresh OS-CSPRNG nonce and make one complete probe attempt.
pub async fn probe_target<R: Resolver, T: ProbeTransport>(
    resolver: &R,
    transport: &T,
    target: &Target,
    attempted_at: DateTime<Utc>,
) -> ProbeAttempt {
    let mut nonce = [0u8; 32];
    let mut os_rng = rand::rngs::OsRng;
    if os_rng.try_fill_bytes(&mut nonce).is_err() {
        return ProbeAttempt::without_evidence(
            &target.id,
            attempted_at,
            Utc::now(),
            Duration::ZERO,
            ProbeReason::InternalError,
        );
    }
    probe_with_nonce(resolver, transport, target, attempted_at, nonce).await
}

/// Probe using a supplied nonce. This is public solely to permit deterministic
/// hermetic tests; production must call [`probe_target`].
pub async fn probe_with_nonce<R: Resolver, T: ProbeTransport>(
    resolver: &R,
    transport: &T,
    target: &Target,
    attempted_at: DateTime<Utc>,
    nonce: [u8; 32],
) -> ProbeAttempt {
    probe_with_nonce_inner(resolver, transport, target, attempted_at, nonce, None).await
}

/// Deterministic-time form used only by hermetic conformance tests.
///
/// Production callers must use [`probe_target`] or [`probe_with_nonce`]. This
/// function is deliberately absent from runtime, environment and CLI wiring.
#[doc(hidden)]
pub async fn probe_with_nonce_at<R: Resolver, T: ProbeTransport>(
    resolver: &R,
    transport: &T,
    target: &Target,
    attempted_at: DateTime<Utc>,
    nonce: [u8; 32],
    observation_time: DateTime<Utc>,
) -> ProbeAttempt {
    probe_with_nonce_inner(
        resolver,
        transport,
        target,
        attempted_at,
        nonce,
        Some(observation_time),
    )
    .await
}

async fn probe_with_nonce_inner<R: Resolver, T: ProbeTransport>(
    resolver: &R,
    transport: &T,
    target: &Target,
    attempted_at: DateTime<Utc>,
    nonce: [u8; 32],
    fixed_observation_time: Option<DateTime<Utc>>,
) -> ProbeAttempt {
    let started = Instant::now();
    let nonce_base64 = STANDARD.encode(nonce);
    let result = tokio::time::timeout(ATTEMPT_TIMEOUT, async {
        let url =
            url::Url::parse(&target.attestation_url).map_err(|_| ProbeReason::InternalError)?;
        let pinned = resolve_and_pin(resolver, &url)
            .await
            .map_err(|_| ProbeReason::Unreachable)?;
        transport
            .post_bootproof(&pinned, &nonce_base64)
            .await
            .map_err(|error| error.reason())
    })
    .await;
    let latency = started.elapsed();
    // Production obtains the observation/completion time only after the
    // response (or transport outcome) is known. The fixed value exists solely
    // for historical-fixture conformance tests.
    let completed_at = fixed_observation_time.unwrap_or_else(Utc::now);

    let response = match result {
        Err(_) => {
            return ProbeAttempt::transport(
                &target.id,
                attempted_at,
                completed_at,
                latency,
                ProbeReason::Timeout,
            )
        }
        Ok(Err(reason)) => {
            return ProbeAttempt::without_evidence(
                &target.id,
                attempted_at,
                completed_at,
                latency,
                reason,
            )
        }
        Ok(Ok(response)) => response,
    };

    let response = match serde_json::from_slice::<BootproofResponse>(&response.body) {
        Ok(response) => response,
        Err(_) => return ProbeAttempt::malformed(&target.id, attempted_at, completed_at, latency),
    };
    let document = match decode_canonical_document(&response.document) {
        Ok(document) => document,
        Err(()) => return ProbeAttempt::malformed(&target.id, attempted_at, completed_at, latency),
    };
    let manifest_digest = match digest_canonical(&response.manifest) {
        Ok(digest) => digest,
        Err(_) => return ProbeAttempt::malformed(&target.id, attempted_at, completed_at, latency),
    };
    let evidence = EvidenceBundle {
        protocol: EVIDENCE_PROTOCOL.to_owned(),
        target_id: target.id.clone(),
        document: response.document,
        nonce: nonce_base64,
        observed_at: completed_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        evidence_digest: evidence_digest(&document),
        manifest: response.manifest,
        manifest_digest,
    };

    let expected_pcrs = match pcrs_from_hex(
        &target.expected_pcrs.pcr0,
        &target.expected_pcrs.pcr1,
        &target.expected_pcrs.pcr2,
    ) {
        Ok(pcrs) => pcrs,
        Err(_) => {
            // Config validation makes this unreachable in production. Keep the
            // decoded document nevertheless: reachable evidence must stay
            // inspectable even when a local invariant has failed.
            return ProbeAttempt::definitive(
                &target.id,
                attempted_at,
                completed_at,
                latency,
                ProbeReason::InternalError,
                evidence,
                None,
            );
        }
    };
    let now = completed_at
        .timestamp()
        .try_into()
        .map(Duration::from_secs)
        .unwrap_or(Duration::ZERO);
    let verification = verify_evidence(&document, &expected_pcrs, &nonce, now);
    ProbeAttempt::definitive(
        &target.id,
        attempted_at,
        completed_at,
        latency,
        verification.reason,
        evidence,
        verification.pcr_claims,
    )
}

fn decode_canonical_document(document: &str) -> Result<Vec<u8>, ()> {
    let bytes = STANDARD.decode(document).map_err(|_| ())?;
    if bytes.is_empty() || STANDARD.encode(&bytes) != document {
        return Err(());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{ResolveError, Resolver};
    use chrono::TimeZone;
    use std::net::SocketAddr;

    const FIXTURE_NONCE_HEX: &str =
        "d041b23bce8678bbc7c174bd8494c4f9759386eec963ec69bfd45c1452b10636";
    const FIXTURE_PCR_0_AND_1: &str = "ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03";
    const FIXTURE_PCR_2: &str = "21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a";
    const FIXTURE_TIME_SECONDS: i64 = 1_766_510_416;

    #[derive(Clone)]
    struct FakeResolver(Result<Vec<SocketAddr>, &'static str>);

    impl Resolver for FakeResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, ResolveError> {
            self.0.clone().map_err(|_| ResolveError::EmptyAnswer {
                host: "target.example".to_owned(),
                port: 443,
            })
        }
    }

    struct FakeTransport(Result<HttpResponse, ProbeReason>);

    #[async_trait::async_trait]
    impl ProbeTransport for FakeTransport {
        async fn post_bootproof(
            &self,
            _target: &PinnedTarget,
            _nonce_base64: &str,
        ) -> Result<HttpResponse, TransportError> {
            match &self.0 {
                Ok(response) => Ok(response.clone()),
                Err(ProbeReason::Timeout) => Err(TransportError::Timeout),
                Err(ProbeReason::HttpError) => Err(TransportError::HttpStatus(302)),
                Err(_) => Err(TransportError::ResponseTooLarge),
            }
        }
    }

    fn target() -> Target {
        Target {
            id: "payments-prod".to_owned(),
            name: "Payments".to_owned(),
            attestation_url: "https://target.example/attestation".to_owned(),
            expected_pcrs: canary_core::config::ExpectedPcrs {
                pcr0: "aa".repeat(48),
                pcr1: "bb".repeat(48),
                pcr2: "cc".repeat(48),
            },
        }
    }

    fn fixture_target() -> Target {
        Target {
            id: "aws-test".to_owned(),
            name: "AWS test fixture".to_owned(),
            attestation_url: "https://target.example/attestation".to_owned(),
            expected_pcrs: canary_core::config::ExpectedPcrs {
                pcr0: FIXTURE_PCR_0_AND_1.to_owned(),
                pcr1: FIXTURE_PCR_0_AND_1.to_owned(),
                pcr2: FIXTURE_PCR_2.to_owned(),
            },
        }
    }

    fn fixture_response() -> HttpResponse {
        HttpResponse {
            body: serde_json::to_vec(&serde_json::json!({
                "document": include_str!("../../canary-core/tests/data/aws-test.cbor.b64").trim(),
                "manifest": {},
            }))
            .unwrap(),
        }
    }

    fn fixture_nonce() -> [u8; 32] {
        hex::decode(FIXTURE_NONCE_HEX).unwrap().try_into().unwrap()
    }

    #[tokio::test]
    async fn redirects_and_timeouts_are_transport_results_without_evidence() {
        let resolver = FakeResolver(Ok(vec!["8.8.8.8:443".parse().unwrap()]));
        let attempt = probe_with_nonce(
            &resolver,
            &FakeTransport(Err(ProbeReason::HttpError)),
            &target(),
            Utc::now(),
            [7; 32],
        )
        .await;
        assert_eq!(attempt.classification, ProbeClassification::Transport);
        assert_eq!(attempt.reason, ProbeReason::HttpError);
        assert!(attempt.evidence.is_none());

        let attempt = probe_with_nonce(
            &resolver,
            &FakeTransport(Err(ProbeReason::Timeout)),
            &target(),
            Utc::now(),
            [7; 32],
        )
        .await;
        assert_eq!(attempt.reason, ProbeReason::Timeout);
    }

    #[tokio::test]
    async fn malformed_response_is_definitive_and_has_no_evidence() {
        let resolver = FakeResolver(Ok(vec!["8.8.8.8:443".parse().unwrap()]));
        let attempt = probe_with_nonce(
            &resolver,
            &FakeTransport(Ok(HttpResponse {
                body: br#"{"document":"not base64","manifest":{}}"#.to_vec(),
            })),
            &target(),
            Utc::now(),
            [7; 32],
        )
        .await;
        assert_eq!(attempt.classification, ProbeClassification::Definitive);
        assert_eq!(attempt.reason, ProbeReason::MalformedEvidence);
        assert!(attempt.evidence_digest.is_none());
    }

    #[tokio::test]
    async fn fixed_time_fixture_verifies_and_preserves_exact_historical_time() {
        let resolver = FakeResolver(Ok(vec!["8.8.8.8:443".parse().unwrap()]));
        let observation_time = Utc.timestamp_opt(FIXTURE_TIME_SECONDS, 0).single().unwrap();
        let attempt = probe_with_nonce_at(
            &resolver,
            &FakeTransport(Ok(fixture_response())),
            &fixture_target(),
            observation_time,
            fixture_nonce(),
            observation_time,
        )
        .await;

        assert_eq!(attempt.reason, ProbeReason::AllChecksPassed);
        assert_eq!(attempt.observed_at, Some(observation_time));
        assert_eq!(attempt.completed_at, observation_time);
        assert_eq!(
            attempt.evidence.unwrap().observed_at,
            "2025-12-23T17:20:16Z"
        );
    }

    #[tokio::test]
    async fn production_nonce_helper_timestamps_after_the_response() {
        let resolver = FakeResolver(Ok(vec!["8.8.8.8:443".parse().unwrap()]));
        let before = Utc::now();
        let attempt = probe_with_nonce(
            &resolver,
            &FakeTransport(Ok(fixture_response())),
            &fixture_target(),
            before,
            fixture_nonce(),
        )
        .await;
        let after = Utc::now();

        assert!(attempt.completed_at >= before);
        assert!(attempt.completed_at <= after);
        assert_eq!(attempt.observed_at, Some(attempt.completed_at));
    }

    #[test]
    fn canonical_document_parser_rejects_unpadded_or_empty_base64() {
        assert!(decode_canonical_document("YQ").is_err());
        assert!(decode_canonical_document("").is_err());
        assert_eq!(decode_canonical_document("YQ==").unwrap(), b"a");
    }

    #[test]
    fn response_body_limit_accepts_exact_boundary_and_rejects_one_more_byte() {
        let mut body = Vec::new();
        let exact = vec![0_u8; MAX_RESPONSE_BYTES];
        append_bounded(&mut body, &exact).unwrap();
        assert_eq!(body.len(), MAX_RESPONSE_BYTES);
        assert!(matches!(
            append_bounded(&mut body, &[0]),
            Err(TransportError::ResponseTooLarge)
        ));
        assert_eq!(body.len(), MAX_RESPONSE_BYTES);
    }
}
