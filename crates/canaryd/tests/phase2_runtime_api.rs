//! Hermetic end-to-end Phase 2 checks using only the public Runtime and API.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use canary_core::{
    config::{Config, ExpectedPcrs, Target},
    evidence::{pcrs_from_hex, verify_evidence},
    keys::KeysDocument,
    statement::{verify_statement, Statement, Status},
};
use canaryd::{
    api::router,
    network::{ResolveError, Resolver},
    probe::{probe_with_nonce_at, HttpResponse, ProbeAttempt, ProbeClassification, ProbeTransport},
    runtime::{IdentitySource, ProbeRunner, Runtime, RuntimeClock, RuntimeOptions},
};
use chrono::TimeZone as _;
use http_body_util::BodyExt as _;
use tempfile::TempDir;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;
use zeroize::Zeroizing;

fn test_config() -> Config {
    Config {
        version: 0,
        node_id: "node-integration".to_owned(),
        probe_interval_seconds: 60,
        history_limit: 1_000,
        targets: vec![
            Target {
                id: "loopback-v4".to_owned(),
                name: "Loopback v4".to_owned(),
                // A literal local IP makes Tokio resolution hermetic. The
                // monitor's address policy rejects it before any TCP/TLS I/O.
                attestation_url: "https://127.0.0.1/attestation".to_owned(),
                e2e_mode: None,
                expected_pcrs: expected_pcrs(),
            },
            Target {
                id: "loopback-v6".to_owned(),
                name: "Loopback v6".to_owned(),
                attestation_url: "https://[::1]/attestation".to_owned(),
                e2e_mode: None,
                expected_pcrs: expected_pcrs(),
            },
        ],
    }
}

fn expected_pcrs() -> ExpectedPcrs {
    ExpectedPcrs {
        pcr0: "a".repeat(96),
        pcr1: "b".repeat(96),
        pcr2: "c".repeat(96),
    }
}

const FIXTURE_NONCE_HEX: &str = "d041b23bce8678bbc7c174bd8494c4f9759386eec963ec69bfd45c1452b10636";
const FIXTURE_PCR_0_AND_1: &str = "ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03";
const FIXTURE_PCR_2: &str = "21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a";
const FIXTURE_VERIFICATION_TIME: Duration = Duration::from_secs(1_766_510_416);

fn fixture_time() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc
        .timestamp_opt(FIXTURE_VERIFICATION_TIME.as_secs() as i64, 0)
        .single()
        .unwrap()
}

struct FixedRuntimeClock(chrono::DateTime<chrono::Utc>);

impl RuntimeClock for FixedRuntimeClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.0
    }
}

fn fixture_config() -> Config {
    Config {
        version: 0,
        node_id: "node-fixture".to_owned(),
        probe_interval_seconds: 60,
        history_limit: 1_000,
        targets: vec![Target {
            id: "aws-test".to_owned(),
            name: "AWS test fixture".to_owned(),
            attestation_url: "https://fixture.example/attestation".to_owned(),
            e2e_mode: None,
            expected_pcrs: ExpectedPcrs {
                pcr0: FIXTURE_PCR_0_AND_1.to_owned(),
                pcr1: FIXTURE_PCR_0_AND_1.to_owned(),
                pcr2: FIXTURE_PCR_2.to_owned(),
            },
        }],
    }
}

#[derive(Clone, Copy)]
struct FixtureResolver;

impl Resolver for FixtureResolver {
    async fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, ResolveError> {
        Ok(vec![SocketAddr::new(
            Ipv4Addr::new(1, 1, 1, 1).into(),
            port,
        )])
    }
}

#[derive(Clone, Copy)]
struct FixtureTransport;

#[async_trait::async_trait]
impl ProbeTransport for FixtureTransport {
    async fn post_bootproof(
        &self,
        _target: &canaryd::network::PinnedTarget,
        _nonce_base64: &str,
    ) -> Result<HttpResponse, canaryd::probe::TransportError> {
        Ok(HttpResponse {
            body: serde_json::to_vec(&serde_json::json!({
                "document": include_str!("../../canary-core/tests/data/aws-test.cbor.b64").trim(),
                "manifest": {},
            }))
            .unwrap(),
            peer_certificate_der: None,
        })
    }
}

struct FixtureProbeRunner;

#[async_trait::async_trait]
impl ProbeRunner for FixtureProbeRunner {
    async fn probe(
        &self,
        target: &Target,
        attempted_at: chrono::DateTime<chrono::Utc>,
    ) -> ProbeAttempt {
        let nonce: [u8; 32] = hex::decode(FIXTURE_NONCE_HEX).unwrap().try_into().unwrap();
        probe_with_nonce_at(
            &FixtureResolver,
            &FixtureTransport,
            target,
            attempted_at,
            nonce,
            fixture_time(),
        )
        .await
    }
}

struct BlockingRunner {
    entered: AtomicUsize,
    release: Semaphore,
}

impl BlockingRunner {
    fn new() -> Self {
        Self {
            entered: AtomicUsize::new(0),
            release: Semaphore::new(0),
        }
    }

    fn entered(&self) -> usize {
        self.entered.load(Ordering::Acquire)
    }

    fn release_one(&self) {
        self.release.add_permits(1);
    }
}

#[async_trait::async_trait]
impl ProbeRunner for BlockingRunner {
    async fn probe(
        &self,
        target: &Target,
        attempted_at: chrono::DateTime<chrono::Utc>,
    ) -> ProbeAttempt {
        self.entered.fetch_add(1, Ordering::AcqRel);
        let permit = self.release.acquire().await.unwrap();
        drop(permit);
        ProbeAttempt {
            target_id: target.id.clone(),
            attempted_at,
            completed_at: attempted_at,
            observed_at: None,
            latency: Duration::ZERO,
            classification: ProbeClassification::Transport,
            reason: canary_core::evidence::ProbeReason::Timeout,
            evidence: None,
            evidence_claims: None,
            evidence_digest: None,
            manifest_digest: None,
            tls: None,
        }
    }
}

fn options(temp: &TempDir) -> RuntimeOptions {
    RuntimeOptions {
        config_path: temp.path().join("canary.json"),
        database_path: temp.path().join("state.sqlite"),
        metadata_path: temp.path().join("metadata.json"),
        identity_source: IdentitySource::Stable(Zeroizing::new(STANDARD.encode([0x42_u8; 32]))),
    }
}

async fn request(app: axum::Router, path: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes().to_vec();
    (parts.status, parts.headers, bytes)
}

async fn wait_for_initial_attempts(runtime: &Runtime) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let v4 = runtime.store().history("loopback-v4").await.unwrap();
            let v6 = runtime.store().history("loopback-v6").await.unwrap();
            if v4.len() == 1 && v6.len() == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both immediate prohibited-address probes must complete");
}

fn decoded_public_keys(keys: &KeysDocument) -> (Vec<u8>, Vec<u8>) {
    let ed = keys.keys.iter().find(|key| key.alg == "Ed25519").unwrap();
    let ml = keys.keys.iter().find(|key| key.alg == "ML-DSA-65").unwrap();
    (
        URL_SAFE_NO_PAD.decode(&ed.public_key).unwrap(),
        URL_SAFE_NO_PAD.decode(&ml.public_key).unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_lifecycle_api_and_restart_are_process_local_and_hermetic() {
    let temp = TempDir::new().unwrap();
    let opts = options(&temp);
    let runtime = Runtime::initialize_with_config(test_config(), opts.clone())
        .await
        .unwrap();

    // Initialization signs/persists every PENDING target but never creates a
    // synthetic observation, and public data remains not-ready until workers.
    assert!(!runtime.is_ready());
    let initial = runtime.snapshot().await;
    assert_eq!(initial.targets.len(), 2);
    assert!(initial
        .targets
        .iter()
        .all(|target| target.status == Status::Pending));
    for id in ["loopback-v4", "loopback-v6"] {
        assert!(runtime.store().history(id).await.unwrap().is_empty());
    }
    let (status, headers, body) = request(router(runtime.api_state()), "/health").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(body, br#"{"status":"starting"}"#);
    assert_eq!(
        request(router(runtime.api_state()), "/status.json").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );

    // The initial signed bytes are already independently verifiable from the
    // published key document before the scheduler becomes ready.
    let (ed_key, ml_key) = decoded_public_keys(runtime.keys_document());
    for target in &initial.targets {
        verify_statement(&target.statement, &ed_key, &ml_key, chrono::Utc::now()).unwrap();
        assert_eq!(target.statement.payload.status, Status::Pending);
        assert_eq!(target.statement.payload.observed_at, None);
        assert_eq!(target.statement.payload.evidence_digest, None);
    }

    let cancellation = CancellationToken::new();
    let worker = tokio::spawn({
        let runtime = runtime.clone();
        let cancellation = cancellation.clone();
        async move { runtime.run_until_cancelled(cancellation).await }
    });
    wait_for_initial_attempts(&runtime).await;
    assert!(runtime.is_ready());

    let after = runtime.snapshot().await;
    for target in &after.targets {
        assert_eq!(target.status, Status::Stale);
        assert_eq!(target.reason, "STALE");
        assert_eq!(target.evidence, None);
        assert_eq!(target.transport_warning, None);
        let history = runtime.store().history(&target.id).await.unwrap();
        assert_eq!(
            history.len(),
            1,
            "{} must keep independent history",
            target.id
        );
        assert_eq!(history[0].attempt_reason, "UNREACHABLE");
        assert_eq!(history[0].status, Status::Stale);
        assert_eq!(history[0].evidence_digest, None);
    }

    // Exercise every documented read route in-process, including signed
    // statement retrieval and exact canonical key bytes.
    let app = router(runtime.api_state());
    let (status, headers, status_body) = request(app.clone(), "/status.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let status_json: serde_json::Value = serde_json::from_slice(&status_body).unwrap();
    assert_eq!(status_json["targets"].as_array().unwrap().len(), 2);
    for id in ["loopback-v4", "loopback-v6"] {
        let (status, headers, statement_bytes) =
            request(app.clone(), &format!("/targets/{id}/statement")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        let statement: Statement = serde_json::from_slice(&statement_bytes).unwrap();
        verify_statement(&statement, &ed_key, &ml_key, chrono::Utc::now()).unwrap();
        assert_eq!(statement.payload.target_id, id);
        assert_eq!(statement.payload.status, Status::Stale);

        let (status, _, body) = request(app.clone(), &format!("/targets/{id}/evidence")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, br#"{"error":"no_evidence"}"#);

        let (status, _, history) = request(app.clone(), &format!("/targets/{id}/history")).await;
        assert_eq!(status, StatusCode::OK);
        let history: serde_json::Value = serde_json::from_slice(&history).unwrap();
        assert_eq!(history["target_id"], id);
        assert_eq!(history["observations"].as_array().unwrap().len(), 1);
        assert!(history["observations"][0].get("statement_json").is_none());
        assert!(history["observations"][0].get("nonce").is_none());
    }
    let (status, _, config) = request(app.clone(), "/config.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&config).unwrap()["config"]["targets"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let (status, _, keys_bytes) = request(app.clone(), "/keys.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        keys_bytes,
        canary_core::canonical::canonicalize(runtime.keys_document()).unwrap()
    );
    let (status, _, html) = request(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(html).unwrap().contains("Canary status"));

    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("scheduler must stop on cancellation")
        .unwrap()
        .unwrap();
    assert!(
        !runtime.is_ready(),
        "cancellation closes the readiness gate"
    );

    // A database with history must not restore signed prior process state.
    drop(runtime);
    let restarted = Runtime::initialize_with_config(test_config(), opts)
        .await
        .unwrap();
    let restarted_snapshot = restarted.snapshot().await;
    assert!(restarted_snapshot
        .targets
        .iter()
        .all(|target| target.status == Status::Pending));
    for id in ["loopback-v4", "loopback-v6"] {
        assert_eq!(restarted.store().history(id).await.unwrap().len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_fixture_is_parsed_verified_signed_and_served_with_linked_raw_evidence() {
    let temp = TempDir::new().unwrap();
    let fixed_time = fixture_time();
    let fixed_timestamp = "2025-12-23T17:20:16Z";
    let runtime = Runtime::initialize_with_config_and_probe_runner_and_clock(
        fixture_config(),
        options(&temp),
        Arc::new(FixtureProbeRunner),
        Arc::new(FixedRuntimeClock(fixed_time)),
    )
    .await
    .unwrap();
    let cancellation = CancellationToken::new();
    let worker = tokio::spawn({
        let runtime = runtime.clone();
        let cancellation = cancellation.clone();
        async move { runtime.run_until_cancelled(cancellation).await }
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if runtime.store().history("aws-test").await.unwrap().len() == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fixture probe must complete");

    let snapshot = runtime.snapshot().await;
    let target = snapshot
        .targets
        .iter()
        .find(|target| target.id == "aws-test")
        .unwrap();
    assert_eq!(target.status, Status::Verified);
    assert_eq!(target.reason, "ALL_CHECKS_PASSED");
    assert_eq!(target.observed_at, Some(fixed_time));
    assert_eq!(snapshot.generated_at, fixed_time);
    let evidence = target
        .evidence
        .as_ref()
        .expect("verified result retains raw evidence");
    assert_eq!(evidence.observed_at, fixed_timestamp);
    assert_eq!(
        target.statement.payload.evidence_digest.as_deref(),
        Some(evidence.evidence_digest.as_str())
    );
    assert_eq!(
        evidence.document,
        include_str!("../../canary-core/tests/data/aws-test.cbor.b64").trim()
    );
    assert_eq!(
        evidence.nonce,
        STANDARD.encode(hex::decode(FIXTURE_NONCE_HEX).unwrap())
    );
    let claims = target
        .evidence_claims
        .as_ref()
        .expect("verified result retains authenticated PCR claims");
    assert_eq!(claims.observed.pcr0, FIXTURE_PCR_0_AND_1);
    assert_eq!(claims.observed.pcr1, FIXTURE_PCR_0_AND_1);
    assert_eq!(claims.observed.pcr2, FIXTURE_PCR_2);
    assert!(claims.matches.pcr0 && claims.matches.pcr1 && claims.matches.pcr2);
    let decoded = evidence.decode_and_validate().unwrap();
    let outcome = verify_evidence(
        &decoded.document,
        &pcrs_from_hex(FIXTURE_PCR_0_AND_1, FIXTURE_PCR_0_AND_1, FIXTURE_PCR_2).unwrap(),
        &decoded.nonce,
        FIXTURE_VERIFICATION_TIME,
    );
    assert!(outcome.passed);
    assert_eq!(outcome.evidence_digest, evidence.evidence_digest);

    let (ed_key, ml_key) = decoded_public_keys(runtime.keys_document());
    assert_eq!(
        target.statement.payload.observed_at.as_deref(),
        Some(fixed_timestamp)
    );
    assert_eq!(target.statement.payload.issued_at, fixed_timestamp);
    verify_statement(&target.statement, &ed_key, &ml_key, fixed_time).unwrap();
    let app = router(runtime.api_state());
    let (status, _, statement) = request(app.clone(), "/targets/aws-test/statement").await;
    assert_eq!(status, StatusCode::OK);
    let statement: Statement = serde_json::from_slice(&statement).unwrap();
    assert_eq!(
        statement.payload.observed_at.as_deref(),
        Some(fixed_timestamp)
    );
    assert_eq!(statement.payload.issued_at, fixed_timestamp);
    verify_statement(&statement, &ed_key, &ml_key, fixed_time).unwrap();
    let (status, _, evidence_response) = request(app.clone(), "/targets/aws-test/evidence").await;
    assert_eq!(status, StatusCode::OK);
    let served_evidence: serde_json::Value = serde_json::from_slice(&evidence_response).unwrap();
    assert_eq!(served_evidence["evidence_digest"], evidence.evidence_digest);
    assert_eq!(served_evidence["document"], evidence.document);
    assert_eq!(served_evidence["nonce"], evidence.nonce);
    let (status, _, claims_response) = request(app, "/targets/aws-test/evidence/claims").await;
    assert_eq!(status, StatusCode::OK);
    let served_claims: serde_json::Value = serde_json::from_slice(&claims_response).unwrap();
    assert_eq!(served_claims["authentication"]["status"], "verified");
    assert_eq!(served_claims["authentication"]["nonce_status"], "verified");
    assert_eq!(served_claims["observed_pcrs"]["0"], FIXTURE_PCR_0_AND_1);
    assert_eq!(served_claims["observed_pcrs"]["1"], FIXTURE_PCR_0_AND_1);
    assert_eq!(served_claims["observed_pcrs"]["2"], FIXTURE_PCR_2);
    assert_eq!(served_claims["pcr_matches"]["0"], true);
    assert_eq!(served_claims["pcr_matches"]["1"], true);
    assert_eq!(served_claims["pcr_matches"]["2"], true);

    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("cancelling fixture scheduler must stop worker")
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn runtime_admits_exactly_eight_blocking_probe_runners_before_the_ninth() {
    let temp = TempDir::new().unwrap();
    let mut config = fixture_config();
    config.targets = (0..9)
        .map(|number| Target {
            id: format!("target-{number}"),
            name: format!("Target {number}"),
            attestation_url: format!("https://target-{number}.example/attestation"),
            e2e_mode: None,
            expected_pcrs: expected_pcrs(),
        })
        .collect();
    let runner = Arc::new(BlockingRunner::new());
    let runtime =
        Runtime::initialize_with_config_and_probe_runner(config, options(&temp), runner.clone())
            .await
            .unwrap();
    let cancellation = CancellationToken::new();
    let worker = tokio::spawn({
        let runtime = runtime.clone();
        let cancellation = cancellation.clone();
        async move { runtime.run_until_cancelled(cancellation).await }
    });

    tokio::time::timeout(Duration::from_secs(3), async {
        while runner.entered() < 8 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("eight runner calls must enter under the fixed probe permit cap");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(runner.entered(), 8, "the ninth runner waits for a permit");

    runner.release_one();
    tokio::time::timeout(Duration::from_secs(3), async {
        while runner.entered() < 9 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("releasing a permit must admit exactly the queued ninth target");
    assert_eq!(runner.entered(), 9);

    // The scheduler's cancellation select drops all runner futures blocked on
    // the test semaphore; no permit release or external timeout is required.
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("cancellation must unblock all blocking runner tasks")
        .unwrap()
        .unwrap();
    assert!(!runtime.is_ready());
}
