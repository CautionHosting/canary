//! Public, read-only Phase 2 HTTP interface (spec §13).
//!
//! `ApiState` is intentionally the sole runtime/API boundary: the scheduler
//! atomically replaces its snapshot after persistence succeeds, and this
//! module never signs, probes, mutates policy, or restores SQLite state.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use canary_core::{
    canonical::{canonicalize, CanonicalError},
    keys::KeysDocument,
    node::ConfigDocument,
};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::{
    html::{render_status_page, UI_SCRIPT},
    model::{HistoryEntry, RuntimeIdentity, RuntimeSnapshot, TargetSnapshot},
    store::Store,
};

/// Runtime-owned state that backs only the public read-only routes.
///
/// Construction canonicalizes `/keys.json` once. The same bytes must be used
/// by the runtime when calculating the metadata `keyset_digest`; handlers
/// return them verbatim and never reserialize the key document.
#[derive(Clone)]
pub struct ApiState {
    ready: Arc<AtomicBool>,
    snapshot: Arc<RwLock<RuntimeSnapshot>>,
    config: Arc<ConfigDocument>,
    canonical_keys: Arc<[u8]>,
    store: Arc<Store>,
}

impl ApiState {
    /// Build an initially-not-ready API state from verified public documents.
    pub fn new(
        snapshot: RuntimeSnapshot,
        config: ConfigDocument,
        keys: KeysDocument,
        store: Arc<Store>,
    ) -> Result<Self, ApiStateError> {
        config.validate().map_err(ApiStateError::Config)?;
        let canonical_keys = canonicalize(&keys).map_err(ApiStateError::Canonical)?;
        Ok(Self {
            ready: Arc::new(AtomicBool::new(false)),
            snapshot: Arc::new(RwLock::new(snapshot)),
            config: Arc::new(config),
            canonical_keys: Arc::from(canonical_keys),
            store,
        })
    }

    /// Publish the latest fully-committed scheduler snapshot.
    pub async fn publish(&self, snapshot: RuntimeSnapshot) {
        *self.snapshot.write().await = snapshot;
    }

    /// Return the exact canonical `/keys.json` bytes used for metadata binding.
    pub fn canonical_keys(&self) -> &[u8] {
        &self.canonical_keys
    }

    /// Set the readiness gate only after metadata, migrations and scheduler init.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    async fn snapshot(&self) -> RuntimeSnapshot {
        self.snapshot.read().await.clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiStateError {
    #[error("invalid config document: {0}")]
    Config(#[source] canary_core::node::NodeError),
    #[error("could not canonicalize keys document: {0}")]
    Canonical(#[source] CanonicalError),
}

/// Construct the complete public application router. It contains no mutable,
/// administrative, attestation, auth, STEVE, or webhook routes.
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/ui.js", get(ui_script))
        .route("/health", get(health))
        .route("/status.json", get(status))
        .route("/targets/{id}/statement", get(statement))
        .route("/targets/{id}/evidence", get(evidence))
        .route("/targets/{id}/history", get(history))
        .route(
            "/targets/{id}/history/{attempt_id}",
            get(historical_attempt),
        )
        .route("/config.json", get(config))
        .route("/keys.json", get(keys))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn(no_store))
        .with_state(state)
}

async fn no_store(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn health(State(state): State<ApiState>) -> Response {
    if state.is_ready() {
        json_response(StatusCode::OK, StatusBody { status: "ok" })
    } else {
        json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            StatusBody { status: "starting" },
        )
    }
}

async fn index(State(state): State<ApiState>) -> Response {
    if let Some(response) = not_ready(&state) {
        return response;
    }
    let snapshot = state.snapshot().await;
    html_response(render_status_page(&snapshot))
}

async fn ui_script() -> Response {
    let mut response = Response::new(Body::from(UI_SCRIPT));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/javascript; charset=utf-8"),
    );
    response
}

async fn status(State(state): State<ApiState>) -> Response {
    if let Some(response) = not_ready(&state) {
        return response;
    }
    let snapshot = state.snapshot().await;
    let body = StatusResponse::from(snapshot);
    json_response(StatusCode::OK, body)
}

async fn statement(Path(id): Path<String>, State(state): State<ApiState>) -> Response {
    if let Some(response) = not_ready(&state) {
        return response;
    }
    let snapshot = state.snapshot().await;
    match target(&snapshot, &id) {
        Some(target) => json_response(StatusCode::OK, target.statement.clone()),
        None => not_found_response(),
    }
}

async fn evidence(Path(id): Path<String>, State(state): State<ApiState>) -> Response {
    if let Some(response) = not_ready(&state) {
        return response;
    }
    let snapshot = state.snapshot().await;
    match target(&snapshot, &id) {
        Some(target) => match &target.evidence {
            Some(evidence) => json_response(StatusCode::OK, evidence.clone()),
            None => json_response(
                StatusCode::NOT_FOUND,
                ErrorBody {
                    error: "no_evidence",
                },
            ),
        },
        None => not_found_response(),
    }
}

async fn history(Path(id): Path<String>, State(state): State<ApiState>) -> Response {
    if let Some(response) = not_ready(&state) {
        return response;
    }
    let snapshot = state.snapshot().await;
    if target(&snapshot, &id).is_none() {
        return not_found_response();
    }
    match state.store.history(&id).await {
        Ok(history) => json_response(
            StatusCode::OK,
            HistoryResponse {
                target_id: id,
                observations: history,
            },
        ),
        Err(error) => {
            tracing::error!(
                target_id = %id,
                error = %error,
                "failed to load target history"
            );
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "internal_error",
                },
            )
        }
    }
}

async fn historical_attempt(
    Path((id, attempt_id)): Path<(String, i64)>,
    State(state): State<ApiState>,
) -> Response {
    if let Some(response) = not_ready(&state) {
        return response;
    }
    let snapshot = state.snapshot().await;
    if target(&snapshot, &id).is_none() {
        return not_found_response();
    }
    match state.store.historical_attempt(&id, attempt_id).await {
        Ok(Some(attempt)) => json_response(StatusCode::OK, attempt),
        Ok(None) => not_found_response(),
        Err(error) => {
            tracing::error!(
                target_id = %id,
                attempt_id,
                error = %error,
                "failed to load historical attempt"
            );
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "internal_error",
                },
            )
        }
    }
}

async fn config(State(state): State<ApiState>) -> Response {
    if let Some(response) = not_ready(&state) {
        return response;
    }
    json_response(StatusCode::OK, state.config.as_ref().clone())
}

async fn keys(State(state): State<ApiState>) -> Response {
    if let Some(response) = not_ready(&state) {
        return response;
    }
    let mut response = Response::new(Body::from(state.canonical_keys.as_ref().to_vec()));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

async fn not_found() -> Response {
    not_found_response()
}

async fn method_not_allowed() -> Response {
    json_response(
        StatusCode::METHOD_NOT_ALLOWED,
        ErrorBody {
            error: "method_not_allowed",
        },
    )
}

fn target<'a>(snapshot: &'a RuntimeSnapshot, id: &str) -> Option<&'a TargetSnapshot> {
    snapshot.targets.iter().find(|target| target.id == id)
}

fn not_ready(state: &ApiState) -> Option<Response> {
    (!state.is_ready()).then(|| {
        json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorBody { error: "not_ready" },
        )
    })
}

fn not_found_response() -> Response {
    json_response(StatusCode::NOT_FOUND, ErrorBody { error: "not_found" })
}

fn json_response<T: Serialize>(status: StatusCode, value: T) -> Response {
    (status, Json(value)).into_response()
}

fn html_response(value: String) -> Response {
    let mut response = Response::new(Body::from(value));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        ),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[derive(Serialize)]
struct StatusBody {
    status: &'static str,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

#[derive(Serialize)]
struct StatusResponse {
    protocol: String,
    node_id: String,
    config_digest: String,
    runtime: RuntimeIdentity,
    generated_at: chrono::DateTime<chrono::Utc>,
    targets: Vec<TargetSummary>,
}

impl From<RuntimeSnapshot> for StatusResponse {
    fn from(snapshot: RuntimeSnapshot) -> Self {
        Self {
            protocol: snapshot.protocol,
            node_id: snapshot.node_id,
            config_digest: snapshot.config_digest,
            runtime: snapshot.runtime,
            generated_at: snapshot.generated_at,
            targets: snapshot.targets.iter().map(TargetSummary::from).collect(),
        }
    }
}

#[derive(Serialize)]
struct TargetSummary {
    id: String,
    name: String,
    target_origin: String,
    status: canary_core::statement::Status,
    reason: String,
    observed_at: Option<chrono::DateTime<chrono::Utc>>,
    expires_at: chrono::DateTime<chrono::Utc>,
    transport_warning: Option<String>,
}

impl From<&TargetSnapshot> for TargetSummary {
    fn from(target: &TargetSnapshot) -> Self {
        Self {
            id: target.id.clone(),
            name: target.name.clone(),
            target_origin: target.target_origin.clone(),
            status: target.status,
            reason: target.reason.clone(),
            observed_at: target.observed_at,
            expires_at: target.expires_at,
            transport_warning: target.transport_warning.clone(),
        }
    }
}

#[derive(Serialize)]
struct HistoryResponse {
    target_id: String,
    observations: Vec<HistoryEntry>,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
    };
    use canary_core::{
        config::{Config, ExpectedPcrs, Target},
        evidence::EvidenceBundle,
        keys::{KeyEntry, KeysDocument},
        node::ConfigDocument,
        statement::{Payload, Signature, Signer, Statement, Status},
    };
    use chrono::{Duration, TimeZone, Utc};
    use http_body_util::BodyExt as _;
    use serde_json::{json, Value};
    use tower::ServiceExt as _;

    use crate::{
        model::{
            AttemptWrite, ExecutionEnvironment, RuntimeIdentity, RuntimeSnapshot, TargetSnapshot,
        },
        store::Store,
    };

    use super::{router, ApiState};

    fn at(second: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + second, 0)
            .single()
            .unwrap()
    }

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn config() -> ConfigDocument {
        ConfigDocument::new(Config {
            version: 0,
            node_id: "node-a".to_owned(),
            probe_interval_seconds: 60,
            history_limit: 1_000,
            targets: vec![Target {
                id: "target-a".to_owned(),
                name: "Target A".to_owned(),
                attestation_url: "https://example.test/attestation".to_owned(),
                expected_pcrs: ExpectedPcrs {
                    pcr0: "a".repeat(96),
                    pcr1: "b".repeat(96),
                    pcr2: "c".repeat(96),
                },
            }],
        })
        .unwrap()
    }

    fn keys() -> KeysDocument {
        KeysDocument {
            protocol: "caution-canary-v0".to_owned(),
            node_id: "node-a".to_owned(),
            key_epoch: 0,
            keys: vec![KeyEntry {
                alg: "Ed25519".to_owned(),
                encoding: "base64url".to_owned(),
                public_key: "public-key".to_owned(),
            }],
        }
    }

    fn statement(status: Status) -> Statement {
        Statement {
            payload: Payload {
                claim_type: "caution.canary.pcr-match.v0".to_owned(),
                target_id: "target-a".to_owned(),
                target_origin: "https://example.test".to_owned(),
                status,
                reason: "ALL_CHECKS_PASSED".to_owned(),
                config_digest: digest('a'),
                evidence_digest: Some(digest('b')),
                observed_at: Some("2023-11-14T22:13:20Z".to_owned()),
                issued_at: "2023-11-14T22:13:20Z".to_owned(),
                expires_at: "2023-11-14T22:16:20Z".to_owned(),
                verifier_id: "node-a".to_owned(),
                key_epoch: 0,
            },
            signers: vec![Signer {
                verifier_id: "node-a".to_owned(),
                key_epoch: 0,
                signatures: vec![Signature {
                    alg: "Ed25519".to_owned(),
                    sig: "signature".to_owned(),
                }],
            }],
        }
    }

    fn evidence() -> EvidenceBundle {
        EvidenceBundle {
            protocol: "caution-canary-evidence-v0".to_owned(),
            target_id: "target-a".to_owned(),
            document: "AA==".to_owned(),
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            observed_at: "2023-11-14T22:13:20Z".to_owned(),
            evidence_digest: digest('b'),
            manifest: json!({}),
            manifest_digest: digest('c'),
        }
    }

    fn target(evidence: Option<EvidenceBundle>) -> TargetSnapshot {
        TargetSnapshot {
            id: "target-a".to_owned(),
            name: "Target A".to_owned(),
            target_origin: "https://example.test".to_owned(),
            status: Status::Verified,
            reason: "ALL_CHECKS_PASSED".to_owned(),
            observed_at: Some(at(0)),
            expires_at: at(180),
            transport_warning: None,
            statement: statement(Status::Verified),
            evidence,
        }
    }

    fn snapshot(target: TargetSnapshot) -> RuntimeSnapshot {
        snapshot_with_environment(target, ExecutionEnvironment::NonEnclave)
    }

    fn snapshot_with_environment(
        target: TargetSnapshot,
        environment: ExecutionEnvironment,
    ) -> RuntimeSnapshot {
        RuntimeSnapshot {
            protocol: "caution-canary-v0".to_owned(),
            node_id: "node-a".to_owned(),
            config_digest: config().config_digest,
            runtime: RuntimeIdentity {
                environment,
                binary_digest: digest('d'),
                identity_mode: canary_core::node::IdentityMode::Stable,
            },
            generated_at: at(0),
            targets: vec![target],
        }
    }

    async fn state(with_evidence: bool) -> ApiState {
        let store = Arc::new(Store::connect("sqlite::memory:").await.unwrap());
        ApiState::new(
            snapshot(target(with_evidence.then(evidence))),
            config(),
            keys(),
            store,
        )
        .unwrap()
    }

    async fn response(
        app: axum::Router,
        uri: &str,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, headers, body)
    }

    #[tokio::test]
    async fn readiness_gate_has_exact_health_and_blocks_application_routes() {
        let state = state(true).await;
        let (status, headers, body) = response(router(state.clone()), "/health").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, br#"{"status":"starting"}"#);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");

        let (status, _, body) = response(router(state), "/status.json").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, br#"{"error":"not_ready"}"#);
    }

    #[tokio::test]
    async fn serves_read_only_documents_and_summary_without_signed_material() {
        let state = state(true).await;
        state.set_ready(true);

        let (status, headers, body) = response(router(state.clone()), "/status.json").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        let status_json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(status_json["runtime"]["environment"], "non_enclave");
        assert_eq!(status_json["runtime"]["binary_digest"], digest('d'));
        assert_eq!(status_json["runtime"]["identity_mode"], "stable");
        assert!(status_json["targets"][0].get("statement").is_none());
        assert!(status_json["targets"][0].get("evidence").is_none());

        let (status, _, body) =
            response(router(state.clone()), "/targets/target-a/statement").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<Statement>(&body).unwrap(),
            statement(Status::Verified)
        );

        let (status, _, body) = response(router(state.clone()), "/targets/target-a/evidence").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<EvidenceBundle>(&body).unwrap(),
            evidence()
        );

        let (status, _, body) = response(router(state.clone()), "/config.json").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<ConfigDocument>(&body).unwrap(),
            config()
        );

        let expected_keys = state.canonical_keys().to_vec();
        let (status, _, body) = response(router(state.clone()), "/keys.json").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, expected_keys);

        let (status, headers, body) = response(router(state.clone()), "/ui.js").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers[header::CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
        let script = String::from_utf8(body).unwrap();
        assert!(script.contains("canaryctl verify"));
        assert!(script.contains("canaryctl verify-history"));
        assert!(script.contains("--insecure"));
        assert!(script.contains("runtimeEnvironment"));
        assert!(!script.contains("window.location.protocol"));
        assert!(script.contains("requestJson(targetPath(name))"));
        assert!(!script.contains("innerHTML"));

        let (status, _, body) = response(router(state), "/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, br#"{"status":"ok"}"#);
    }

    #[tokio::test]
    async fn evidence_unknown_and_forbidden_routes_are_bounded() {
        let state = state(false).await;
        state.set_ready(true);
        let (status, headers, body) =
            response(router(state.clone()), "/targets/target-a/evidence").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(body, br#"{"error":"no_evidence"}"#);

        let (status, headers, body) =
            response(router(state.clone()), "/targets/missing/statement").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(body, br#"{"error":"not_found"}"#);

        let app = router(state.clone());
        let method_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/status.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(method_response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(method_response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            method_response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            br#"{"error":"method_not_allowed"}"#
        );

        let (status, headers, body) = response(router(state), "/admin").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(body, br#"{"error":"not_found"}"#);
    }

    #[tokio::test]
    async fn history_is_newest_first_bounded_and_excludes_raw_material() {
        let state = state(true).await;
        for second in 0..1_002 {
            let target = target(Some(evidence()));
            state
                .store
                .commit(AttemptWrite {
                    target,
                    attempted_at: at(second),
                    attempt_reason: "ALL_CHECKS_PASSED".to_owned(),
                    attempt_observed_at: Some(at(second)),
                    attempt_evidence: Some(evidence()),
                    attempt_transport_warning: None,
                    latency_ms: Some(1),
                    config_digest: config().config_digest,
                })
                .await
                .unwrap();
        }
        state.set_ready(true);
        let (status, _, body) = response(router(state), "/targets/target-a/history").await;
        assert_eq!(status, StatusCode::OK);
        let value: Value = serde_json::from_slice(&body).unwrap();
        let history = value["observations"].as_array().unwrap();
        assert_eq!(history.len(), 1_000);
        assert!(
            history[0]["attempted_at"].as_str() > history[1]["attempted_at"].as_str(),
            "history must be newest first"
        );
        assert!(history[0].get("evidence").is_none());
        assert!(history[0].get("nonce").is_none());
        assert!(history[0].get("statement").is_none());
    }

    #[tokio::test]
    async fn historical_attempt_exposes_exact_replayable_artifacts() {
        let state = state(true).await;
        let exact_evidence = evidence();
        let exact_statement = target(Some(exact_evidence.clone())).statement;
        let receipt = state
            .store
            .commit(AttemptWrite {
                target: target(Some(exact_evidence.clone())),
                attempted_at: at(0),
                attempt_reason: "INVALID_SIGNATURE".to_owned(),
                attempt_observed_at: Some(at(0)),
                attempt_evidence: Some(exact_evidence.clone()),
                attempt_transport_warning: None,
                latency_ms: Some(1),
                config_digest: config().config_digest,
            })
            .await
            .unwrap();
        state.set_ready(true);

        let uri = format!("/targets/target-a/history/{}", receipt.attempt_id);
        let (status, _, body) = response(router(state.clone()), &uri).await;
        assert_eq!(status, StatusCode::OK);
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["observation"]["attempt_reason"], "INVALID_SIGNATURE");
        assert_eq!(
            serde_json::from_value::<Statement>(value["statement"].clone()).unwrap(),
            exact_statement
        );
        assert_eq!(
            serde_json::from_value::<EvidenceBundle>(value["evidence"].clone()).unwrap(),
            exact_evidence
        );

        let (status, _, body) = response(router(state), "/targets/target-a/history/999999").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, br#"{"error":"not_found"}"#);
    }

    #[tokio::test]
    async fn html_escapes_configuration_derived_strings_and_shows_warning() {
        let state = state(true).await;
        let mut injected = target(Some(evidence()));
        injected.name = "<img src=x onerror=alert(1)>".to_owned();
        injected.target_origin = "https://example.test/?q=\"<&'".to_owned();
        injected.reason = "<script>alert(1)</script>".to_owned();
        state.publish(snapshot(injected)).await;
        state.set_ready(true);

        let (status, headers, body) = response(router(state), "/").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert!(headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("script-src 'self'"));
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        let page = String::from_utf8(body).unwrap();
        assert!(!page.contains("<img src=x"));
        assert!(!page.contains("<script>alert"));
        assert!(page.contains("<meta name=\"viewport\""));
        assert!(page.contains("<script src=\"/ui.js\" defer></script>"));
        assert!(page.contains("id=\"target-inspector\""));
        assert!(page.contains("Canary’s signed claim"));
        assert!(page.contains("The underlying proof material"));
        assert!(page.contains("unsigned diagnostic data"));
        assert!(page.contains("canaryctl verify"));
        assert!(page.contains("canaryctl inspect-node"));
        assert!(page.contains("data-runtime-environment=\"non_enclave\""));
        assert!(page.contains("data-identity-mode=\"stable\""));
        assert!(page.contains("Non-enclave runtime detected"));
        assert!(page.contains("initial signing-key enrollment explicit trust on first use"));
        assert!(
            page.find("Monitored targets").unwrap() < page.find("Verify independently").unwrap()
        );
        assert!(!page.contains("Continuity monitor / V0"));
        assert!(page.contains("--success: #5cff9d"));
        assert!(page.contains("class=\"target-card status-verified\""));
        assert!(page.contains("class=\"status-badge\""));
        assert!(page.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(page.contains("Raw Nitro evidence can expose infrastructure metadata"));
        assert!(page.contains("&quot;&lt;&amp;&#x27;"));
    }

    #[tokio::test]
    async fn html_uses_attested_workflow_when_nitro_is_detected() {
        let state = state(true).await;
        state
            .publish(snapshot_with_environment(
                target(Some(evidence())),
                ExecutionEnvironment::NitroEnclave,
            ))
            .await;
        state.set_ready(true);

        let (status, _, body) = response(router(state), "/").await;
        assert_eq!(status, StatusCode::OK);
        let page = String::from_utf8(body).unwrap();
        assert!(page.contains("data-runtime-environment=\"nitro_enclave\""));
        assert!(page.contains("Nitro enclave detected"));
        assert!(page.contains("caution verify --save-pcrs"));
        assert!(page.contains("--pcrs-file .caution/trusted_hashes.json"));
        assert!(page.contains("canaryd / sha256:"));
        assert!(!page.contains("No Nitro device is visible"));
    }

    #[tokio::test]
    async fn html_labels_ephemeral_identity_and_restart_semantics() {
        let state = state(true).await;
        let mut snapshot =
            snapshot_with_environment(target(Some(evidence())), ExecutionEnvironment::NitroEnclave);
        snapshot.runtime.identity_mode = canary_core::node::IdentityMode::Ephemeral;
        state.publish(snapshot).await;
        state.set_ready(true);

        let (status, _, body) = response(router(state), "/").await;
        assert_eq!(status, StatusCode::OK);
        let page = String::from_utf8(body).unwrap();
        assert!(page.contains("data-identity-mode=\"ephemeral\""));
        assert!(page.contains("Ephemeral identity"));
        assert!(page.contains("change on restart"));
        assert!(page.contains("re-enroll a new key file"));
    }

    #[test]
    fn test_fixture_ttl_is_the_v0_lifetime() {
        assert_eq!(at(180) - at(0), Duration::seconds(180));
    }
}
