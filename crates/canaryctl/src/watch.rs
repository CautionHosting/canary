//! External, stateful webhook watcher for verified Canary target results.
//!
//! This module intentionally runs outside `canaryd`: it first reuses the
//! normal live verifier, then only forwards the authenticated outcome to the
//! configured webhook routes.  Webhook delivery is therefore never part of
//! the measured Canary configuration or its availability boundary.

use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use hmac::{Hmac, Mac as _};
use rand::rngs::OsRng;
use rand::RngCore as _;
use serde_json::{json, Value};
use sha2::Sha256;
use url::Url;
use zeroize::Zeroizing;

use canary_core::statement::Status;

use crate::live_verify::{self, DeploymentResult, VerificationOutcome};
use crate::watch_config::WatchConfig;

const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(5),
    Duration::from_secs(30),
];
const DELIVERY_QUEUE_CAPACITY: usize = 64;

type HmacSha256 = Hmac<Sha256>;

/// Local-only controls supplied by the CLI command.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct WatchOptions {
    pub(crate) insecure_canary: bool,
}

/// Run the watcher until interrupted.
pub(crate) fn run(config: &WatchConfig, options: WatchOptions) -> Result<()> {
    let canary_url = config.canary_url(options.insecure_canary)?.as_str();
    validate_trust_mode(config.canary.pcrs.as_deref(), options.insecure_canary)?;
    let target_ids = config
        .targets
        .iter()
        .map(|target| target.id.clone())
        .collect::<Vec<_>>();
    let initial = live_verify::run(
        canary_url,
        config.canary.pcrs.as_deref(),
        options.insecure_canary,
        &config.canary.keys,
        &target_ids,
    )
    .context("validating watcher config against remote Canary")?;
    let mut machine = WatchMachine::new(config);
    let deliveries = DeliveryManager::new(config)?;
    let mut next_poll = Instant::now();
    eprintln!(
        "watching {} target{} through {}",
        target_ids.len(),
        if target_ids.len() == 1 { "" } else { "s" },
        canary_url
    );
    deliveries.enqueue_events(machine.observe_verified(initial));

    loop {
        next_poll = next_poll
            .checked_add(Duration::from_secs(config.poll_interval_seconds))
            .unwrap_or_else(Instant::now);
        let now = Instant::now();
        if next_poll > now {
            thread::sleep(next_poll.duration_since(now));
        } else {
            next_poll = now;
        }

        let events = match live_verify::run(
            canary_url,
            config.canary.pcrs.as_deref(),
            options.insecure_canary,
            &config.canary.keys,
            &target_ids,
        ) {
            Ok(outcome) => machine.observe_verified(outcome),
            Err(error) => machine.observe_canary_failure(classify_canary_failure(&error)),
        };
        deliveries.enqueue_events(events);

        let heartbeat_events = machine.heartbeat_if_due();
        deliveries.enqueue_events(heartbeat_events);
    }
}

fn validate_trust_mode(pcrs: Option<&std::path::Path>, insecure_canary: bool) -> Result<()> {
    match (pcrs, insecure_canary) {
        (Some(_), false) | (None, true) => {}
        (Some(_), true) => {
            bail!("canary.pcrs must be omitted when an HTTP Canary uses --insecure")
        }
        (None, false) => {
            bail!("canary.pcrs is required unless --insecure is used")
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CanaryFailure {
    Unavailable(String),
    VerificationFailed(String),
}

/// `live_verify::run` turns per-target read failures into structured results;
/// an error here is therefore a failure to read or authenticate Canary itself.
fn classify_canary_failure(error: &anyhow::Error) -> CanaryFailure {
    let unavailable = error.chain().any(|cause| {
        cause
            .downcast_ref::<ureq::Error>()
            .is_some_and(|http_error| match http_error {
                ureq::Error::Transport(_) => true,
                ureq::Error::Status(status, _) => *status == 429 || *status >= 500,
            })
    });
    if unavailable {
        CanaryFailure::Unavailable(format!("{error:#}"))
    } else {
        CanaryFailure::VerificationFailed(format!("{error:#}"))
    }
}

#[derive(Clone, Debug, PartialEq)]
struct TargetObservation {
    status: String,
    reason: String,
    statement: Value,
}

#[derive(Default)]
struct TargetState {
    last: Option<TargetObservation>,
    read_failures: u32,
    read_failure_reported: bool,
}

/// An event before it is given an event ID/timestamp and delivered.  Endpoint
/// IDs are retained rather than secrets or URLs, so events can safely be
/// formatted in tests and delivery remains the sole secret-using code path.
#[derive(Clone, Debug, PartialEq)]
struct PendingEvent {
    name: &'static str,
    endpoint_ids: Vec<String>,
    canary: Value,
    body: Value,
}

struct WatchMachine {
    target_states: HashMap<String, TargetState>,
    target_endpoints: HashMap<String, Vec<String>>,
    endpoint_targets: HashMap<String, Vec<String>>,
    global_endpoints: Vec<String>,
    failure_threshold: u32,
    canary_failures: u32,
    canary_failure_reported: bool,
    canary_verification_failure_reported: bool,
    last_heartbeat: Instant,
    heartbeat_interval: Duration,
    node_id: Option<String>,
    config_digest: Option<String>,
}

impl WatchMachine {
    fn new(config: &WatchConfig) -> Self {
        let mut target_states = HashMap::with_capacity(config.targets.len());
        let mut target_endpoints = HashMap::with_capacity(config.targets.len());
        let mut endpoint_targets: HashMap<String, Vec<String>> = HashMap::new();
        let mut global_seen = HashSet::new();
        let mut global_endpoints = Vec::new();

        for target in &config.targets {
            target_states.insert(target.id.clone(), TargetState::default());
            let endpoints = target
                .webhooks
                .iter()
                .map(|webhook| webhook.id.clone())
                .collect::<Vec<_>>();
            for webhook in &target.webhooks {
                endpoint_targets
                    .entry(webhook.id.clone())
                    .or_default()
                    .push(target.id.clone());
                // Global failures must not be duplicated merely because a
                // receiver is configured for several targets.
                if global_seen.insert((webhook.url.as_str().to_owned(), webhook.secret_env.clone()))
                {
                    global_endpoints.push(webhook.id.clone());
                }
            }
            target_endpoints.insert(target.id.clone(), endpoints);
        }

        Self {
            target_states,
            target_endpoints,
            endpoint_targets,
            global_endpoints,
            failure_threshold: config.failure_threshold,
            canary_failures: 0,
            canary_failure_reported: false,
            canary_verification_failure_reported: false,
            last_heartbeat: Instant::now(),
            heartbeat_interval: Duration::from_secs(config.heartbeat_interval_seconds),
            node_id: None,
            config_digest: None,
        }
    }

    fn observe_verified(&mut self, outcome: VerificationOutcome) -> Vec<PendingEvent> {
        self.node_id = Some(outcome.node_id.clone());
        self.config_digest = Some(outcome.config_digest.clone());
        let mut target_events = Vec::new();
        let mut verification_errors = Vec::new();
        let mut seen = HashSet::new();
        for deployment in outcome.deployments {
            match deployment {
                DeploymentResult::Verified(result) => {
                    seen.insert(result.id.clone());
                    let observation = TargetObservation {
                        status: status_name(result.status).to_owned(),
                        reason: result.reason,
                        statement: serde_json::to_value(result.statement)
                            .expect("Statement is serializable"),
                    };
                    target_events.extend(self.observe_target(result.id, observation));
                }
                DeploymentResult::ReadError(error) => {
                    seen.insert(error.id.clone());
                    target_events.extend(self.observe_target_read_failure(error.id, error.reason));
                }
                DeploymentResult::VerificationError(error) => {
                    seen.insert(error.id.clone());
                    verification_errors.push(format!("target {:?}: {}", error.id, error.reason));
                }
            }
        }
        // A verifier bug or a response that omits a selected target cannot be
        // mistaken for a healthy target result.
        let missing = self
            .target_states
            .keys()
            .filter(|id| !seen.contains(*id))
            .cloned()
            .collect::<Vec<_>>();
        for id in missing {
            target_events.extend(self.observe_target_read_failure(
                id,
                "Canary verification returned no result for configured target".to_owned(),
            ));
        }
        let mut events = if verification_errors.is_empty() {
            self.recover_canary()
        } else {
            self.observe_canary_failure(CanaryFailure::VerificationFailed(
                verification_errors.join("; "),
            ))
        };
        events.extend(target_events);
        events
    }

    fn recover_canary(&mut self) -> Vec<PendingEvent> {
        let recovered = self.canary_failure_reported;
        self.canary_failures = 0;
        self.canary_failure_reported = false;
        self.canary_verification_failure_reported = false;
        if recovered {
            vec![self.global_event(
                "canary.recovered",
                json!({"reason": "CANARY_VERIFICATION_RECOVERED"}),
            )]
        } else {
            Vec::new()
        }
    }

    fn observe_target(
        &mut self,
        target_id: String,
        current: TargetObservation,
    ) -> Vec<PendingEvent> {
        let (prior, was_read_failed) = {
            let Some(state) = self.target_states.get_mut(&target_id) else {
                return Vec::new();
            };
            let prior = state.last.clone();
            let was_read_failed = state.read_failure_reported;
            state.read_failures = 0;
            state.read_failure_reported = false;
            state.last = Some(current.clone());
            (prior, was_read_failed)
        };

        let mut events = Vec::new();
        if was_read_failed {
            events.push(self.target_event(
                "target.read_recovered",
                &target_id,
                json!({
                    "status": current.status,
                    "reason": current.reason,
                    "statement": current.statement,
                }),
            ));
        }
        // At startup a verified target is intentionally silent.  Any other
        // authenticated state is an actionable initial condition.
        if prior.as_ref().is_none_or(|previous| {
            previous.status != current.status || previous.reason != current.reason
        }) && (prior.is_some() || current.status != "VERIFIED")
        {
            events.push(self.target_event(
                "target.status_changed",
                &target_id,
                json!({
                    "status": current.status,
                    "reason": current.reason,
                    "statement": current.statement,
                }),
            ));
        }
        events
    }

    fn observe_target_read_failure(
        &mut self,
        target_id: String,
        reason: String,
    ) -> Vec<PendingEvent> {
        let (failures, last_statement) = {
            let Some(state) = self.target_states.get_mut(&target_id) else {
                return Vec::new();
            };
            state.read_failures = state.read_failures.saturating_add(1);
            if state.read_failures < self.failure_threshold || state.read_failure_reported {
                return Vec::new();
            }
            state.read_failure_reported = true;
            (
                state.read_failures,
                state.last.as_ref().map(|last| last.statement.clone()),
            )
        };
        if failures < self.failure_threshold {
            return Vec::new();
        }
        vec![self.target_event(
            "target.read_failed",
            &target_id,
            json!({
                "reason": reason,
                "consecutive_failures": failures,
                "last_verified_statement": last_statement,
            }),
        )]
    }

    fn observe_canary_failure(&mut self, failure: CanaryFailure) -> Vec<PendingEvent> {
        match failure {
            CanaryFailure::VerificationFailed(reason) => {
                if self.canary_verification_failure_reported {
                    return Vec::new();
                }
                self.canary_failure_reported = true;
                self.canary_verification_failure_reported = true;
                vec![self.global_event("canary.verification_failed", json!({"reason": reason}))]
            }
            CanaryFailure::Unavailable(reason) => {
                self.canary_failures = self.canary_failures.saturating_add(1);
                if self.canary_failures < self.failure_threshold || self.canary_failure_reported {
                    return Vec::new();
                }
                self.canary_failure_reported = true;
                vec![self.global_event(
                    "canary.unavailable",
                    json!({
                        "reason": reason,
                        "consecutive_failures": self.canary_failures,
                    }),
                )]
            }
        }
    }

    fn heartbeat_if_due(&mut self) -> Vec<PendingEvent> {
        if self.last_heartbeat.elapsed() < self.heartbeat_interval {
            return Vec::new();
        }
        self.last_heartbeat = Instant::now();
        let mut events = Vec::new();
        for (endpoint_id, target_ids) in &self.endpoint_targets {
            let targets = target_ids
                .iter()
                .map(|target_id| {
                    let state = self
                        .target_states
                        .get(target_id)
                        .expect("configured target");
                    match &state.last {
                        Some(last) => json!({
                            "id": target_id,
                            "status": last.status,
                            "reason": last.reason,
                        }),
                        None => json!({"id": target_id, "status": "UNKNOWN"}),
                    }
                })
                .collect::<Vec<_>>();
            events.push(PendingEvent {
                name: "watcher.heartbeat",
                endpoint_ids: vec![endpoint_id.clone()],
                canary: self.canary_json(),
                body: json!({"targets": targets}),
            });
        }
        events
    }

    fn target_event(&self, name: &'static str, target_id: &str, body: Value) -> PendingEvent {
        PendingEvent {
            name,
            endpoint_ids: self
                .target_endpoints
                .get(target_id)
                .cloned()
                .unwrap_or_default(),
            canary: self.canary_json(),
            body: json!({"target": {"id": target_id}, "result": body}),
        }
    }

    fn global_event(&self, name: &'static str, body: Value) -> PendingEvent {
        let mut affected_target_ids = self.target_states.keys().cloned().collect::<Vec<_>>();
        affected_target_ids.sort();
        PendingEvent {
            name,
            endpoint_ids: self.global_endpoints.clone(),
            canary: self.canary_json(),
            body: json!({
                "affected_target_ids": affected_target_ids,
                "failure": body,
            }),
        }
    }

    fn canary_json(&self) -> Value {
        json!({
            "node_id": self.node_id,
            "config_digest": self.config_digest,
            "status": self.canary_status(),
        })
    }

    fn canary_status(&self) -> &'static str {
        if self.canary_verification_failure_reported {
            "VERIFICATION_FAILED"
        } else if self.canary_failure_reported {
            "UNAVAILABLE"
        } else if self.canary_failures > 0 {
            "DEGRADED"
        } else if self.node_id.is_some() {
            "VERIFIED"
        } else {
            "UNKNOWN"
        }
    }
}

fn status_name(status: Status) -> &'static str {
    match status {
        Status::Verified => "VERIFIED",
        Status::Failed => "FAILED",
        Status::Pending => "PENDING",
        Status::Unreachable => "UNREACHABLE",
        Status::Stale => "STALE",
    }
}

struct DeliveryManager {
    routes: HashMap<String, SyncSender<PreparedEvent>>,
}

impl DeliveryManager {
    fn new(config: &WatchConfig) -> Result<Self> {
        let mut routes = HashMap::new();
        for webhook in config
            .targets
            .iter()
            .flat_map(|target| target.webhooks.iter())
        {
            let route = DeliveryRoute {
                id: webhook.id.clone(),
                url: webhook.url.clone(),
                secret: webhook.secret.clone(),
            };
            let (sender, receiver) = sync_channel(DELIVERY_QUEUE_CAPACITY);
            thread::Builder::new()
                .name(format!("canary-webhook-{}", webhook.id))
                .spawn(move || {
                    while let Ok(event) = receiver.recv() {
                        if let Err(error) = deliver_one(&route, &event) {
                            eprintln!(
                                "webhook delivery failed for endpoint {:?}: {error:#}",
                                route.id
                            );
                        }
                    }
                })
                .with_context(|| {
                    format!("starting webhook delivery worker for {:?}", webhook.id)
                })?;
            routes.insert(webhook.id.clone(), sender);
        }
        Ok(Self { routes })
    }

    fn enqueue_events(&self, events: Vec<PendingEvent>) {
        for event in events {
            let prepared = match PreparedEvent::new(&event) {
                Ok(prepared) => prepared,
                Err(error) => {
                    eprintln!("could not prepare webhook event: {error}");
                    continue;
                }
            };
            for endpoint_id in &event.endpoint_ids {
                let Some(sender) = self.routes.get(endpoint_id) else {
                    eprintln!("watcher event referenced unknown webhook {endpoint_id:?}");
                    continue;
                };
                match sender.try_send(prepared.clone()) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        eprintln!(
                            "webhook delivery queue is full for endpoint {endpoint_id:?}; dropping event {}",
                            prepared.id
                        );
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        eprintln!(
                            "webhook delivery worker stopped for endpoint {endpoint_id:?}; dropping event {}",
                            prepared.id
                        );
                    }
                }
            }
        }
    }
}

struct DeliveryRoute {
    id: String,
    url: Url,
    secret: Zeroizing<[u8; 32]>,
}

#[derive(Clone)]
struct PreparedEvent {
    id: String,
    timestamp: String,
    body: Vec<u8>,
}

impl PreparedEvent {
    fn new(event: &PendingEvent) -> Result<Self> {
        let id = random_event_id()?;
        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let body_value = json!({
            "schema_version": 1,
            "event": event.name,
            "event_id": id,
            "timestamp": timestamp,
            "canary": event.canary,
            "data": event.body,
        });
        let body = serde_json::to_vec(&body_value).expect("event value is serializable");
        Ok(Self {
            id,
            timestamp,
            body,
        })
    }
}

fn random_event_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| anyhow!("OS CSPRNG failed while generating webhook event ID: {error}"))?;
    Ok(hex::encode(bytes))
}

fn deliver_one(route: &DeliveryRoute, event: &PreparedEvent) -> Result<()> {
    let signature = hmac_header(&route.secret[..], &event.timestamp, &event.body);
    let agent = ureq::AgentBuilder::new()
        .https_only(route.url.scheme() == "https")
        .redirects(0)
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build();
    let mut last_error = None;
    for attempt in 0..=RETRY_DELAYS.len() {
        match agent
            .post(route.url.as_str())
            .set("Content-Type", "application/json")
            .set("X-Canary-Event-Id", &event.id)
            .set("X-Canary-Timestamp", &event.timestamp)
            .set("X-Canary-Signature", &signature)
            .send_bytes(&event.body)
        {
            Ok(response) if (200..300).contains(&response.status()) => return Ok(()),
            Ok(response) => {
                last_error = Some(format!(
                    "receiver returned HTTP status {}",
                    response.status()
                ));
            }
            Err(error) => last_error = Some(redacted_delivery_error(&error)),
        }
        if let Some(delay) = RETRY_DELAYS.get(attempt) {
            thread::sleep(*delay);
        }
    }
    Err(anyhow!(
        "{}",
        last_error.unwrap_or_else(|| "webhook delivery failed".to_owned())
    ))
    .context("posting signed webhook event")
}

fn redacted_delivery_error(error: &ureq::Error) -> String {
    match error {
        ureq::Error::Status(status, _) => format!("receiver returned HTTP status {status}"),
        ureq::Error::Transport(transport) => {
            format!("webhook transport failed: {:?}", transport.kind())
        }
    }
}

fn hmac_header(secret: &[u8], timestamp: &str, body: &[u8]) -> String {
    let mut message = Vec::with_capacity(timestamp.len() + 1 + body.len());
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);
    format!("v1={}", hmac_hex(secret, &message))
}

fn hmac_hex(secret: &[u8], message: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watch_config::{WatchCanary, WatchTarget, Webhook};

    fn machine() -> WatchMachine {
        WatchMachine {
            target_states: HashMap::from([
                ("alpha".to_owned(), TargetState::default()),
                ("beta".to_owned(), TargetState::default()),
            ]),
            target_endpoints: HashMap::from([
                (
                    "alpha".to_owned(),
                    vec!["alpha-a".to_owned(), "alpha-b".to_owned()],
                ),
                ("beta".to_owned(), vec!["beta-a".to_owned()]),
            ]),
            endpoint_targets: HashMap::from([
                ("alpha-a".to_owned(), vec!["alpha".to_owned()]),
                ("alpha-b".to_owned(), vec!["alpha".to_owned()]),
                ("beta-a".to_owned(), vec!["beta".to_owned()]),
            ]),
            global_endpoints: vec!["alpha-a".to_owned(), "beta-a".to_owned()],
            failure_threshold: 3,
            canary_failures: 0,
            canary_failure_reported: false,
            canary_verification_failure_reported: false,
            last_heartbeat: Instant::now(),
            heartbeat_interval: Duration::from_secs(1),
            node_id: None,
            config_digest: None,
        }
    }

    fn routing_config(second_secret_env: &str) -> WatchConfig {
        WatchConfig {
            canary: WatchCanary {
                url: Url::parse("https://canary.example.test").unwrap(),
                pcrs: Some("canary-pcrs.json".into()),
                keys: "canary-keys.json".into(),
            },
            poll_interval_seconds: 30,
            heartbeat_interval_seconds: 300,
            failure_threshold: 3,
            targets: vec![
                WatchTarget {
                    id: "alpha".to_owned(),
                    webhooks: vec![Webhook {
                        id: "alpha-ops".to_owned(),
                        url: Url::parse("https://alerts.example.test/hook").unwrap(),
                        secret_env: "SHARED_SECRET".to_owned(),
                        secret: Zeroizing::new([1_u8; 32]),
                    }],
                },
                WatchTarget {
                    id: "beta".to_owned(),
                    webhooks: vec![Webhook {
                        id: "beta-ops".to_owned(),
                        url: Url::parse("https://alerts.example.test/hook").unwrap(),
                        secret_env: second_secret_env.to_owned(),
                        secret: Zeroizing::new([1_u8; 32]),
                    }],
                },
            ],
        }
    }

    fn observation(status: &str) -> TargetObservation {
        TargetObservation {
            status: status.to_owned(),
            reason: "TEST".to_owned(),
            statement: json!({"payload": {"status": status}}),
        }
    }

    #[test]
    fn startup_verified_is_silent_but_unhealthy_is_announced_to_all_target_routes() {
        let mut machine = machine();
        assert!(machine
            .observe_target("alpha".to_owned(), observation("VERIFIED"))
            .is_empty());
        let events = machine.observe_target("beta".to_owned(), observation("FAILED"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name, "target.status_changed");
        assert_eq!(events[0].endpoint_ids, vec!["beta-a"]);
        assert_eq!(
            events[0].body["result"]["statement"]["payload"]["status"],
            "FAILED"
        );
    }

    #[test]
    fn status_event_includes_reason_changes_without_repeating_unchanged_results() {
        let mut machine = machine();
        machine.observe_target("alpha".to_owned(), observation("FAILED"));
        assert!(machine
            .observe_target("alpha".to_owned(), observation("FAILED"))
            .is_empty());
        let mut changed = observation("FAILED");
        changed.reason = "DIFFERENT_FAILURE".to_owned();
        assert_eq!(
            machine.observe_target("alpha".to_owned(), changed)[0].name,
            "target.status_changed"
        );
    }

    #[test]
    fn status_change_and_read_recovery_are_separate_events() {
        let mut machine = machine();
        machine.observe_target("alpha".to_owned(), observation("VERIFIED"));
        assert!(machine
            .observe_target_read_failure("alpha".to_owned(), "read failed".to_owned())
            .is_empty());
        assert!(machine
            .observe_target_read_failure("alpha".to_owned(), "read failed".to_owned())
            .is_empty());
        let read_failed =
            machine.observe_target_read_failure("alpha".to_owned(), "read failed".to_owned());
        assert_eq!(read_failed.len(), 1);
        assert_eq!(
            read_failed[0].body["result"]["last_verified_statement"]["payload"]["status"],
            "VERIFIED"
        );
        let events = machine.observe_target("alpha".to_owned(), observation("FAILED"));
        assert_eq!(
            events.iter().map(|event| event.name).collect::<Vec<_>>(),
            vec!["target.read_recovered", "target.status_changed"]
        );
    }

    #[test]
    fn global_unavailable_threshold_and_recovery_do_not_duplicate_endpoints() {
        let mut machine = machine();
        for _ in 0..2 {
            assert!(machine
                .observe_canary_failure(CanaryFailure::Unavailable("down".to_owned()))
                .is_empty());
        }
        let events = machine.observe_canary_failure(CanaryFailure::Unavailable("down".to_owned()));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name, "canary.unavailable");
        assert_eq!(events[0].endpoint_ids, vec!["alpha-a", "beta-a"]);
        assert!(machine
            .observe_canary_failure(CanaryFailure::Unavailable("down".to_owned()))
            .is_empty());
    }

    #[test]
    fn global_routes_dedupe_only_the_same_url_and_secret_reference() {
        let shared = WatchMachine::new(&routing_config("SHARED_SECRET"));
        assert_eq!(shared.global_endpoints, ["alpha-ops"]);

        let distinct = WatchMachine::new(&routing_config("OTHER_SECRET"));
        assert_eq!(distinct.global_endpoints, ["alpha-ops", "beta-ops"]);
    }

    #[test]
    fn verification_failure_alerts_immediately() {
        let mut machine = machine();
        let events = machine.observe_canary_failure(CanaryFailure::VerificationFailed(
            "bad signature".to_owned(),
        ));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name, "canary.verification_failed");
    }

    #[test]
    fn canary_failure_recovers_once_after_a_verified_poll() {
        let mut machine = machine();
        machine.observe_canary_failure(CanaryFailure::VerificationFailed(
            "bad signature".to_owned(),
        ));
        machine.node_id = Some("canary-main".to_owned());
        let events = machine.recover_canary();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name, "canary.recovered");
        assert_eq!(events[0].canary["status"], "VERIFIED");
        assert!(machine.recover_canary().is_empty());
    }

    #[test]
    fn hmac_matches_sha256_test_vector() {
        let expected = "v1=b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        assert_eq!(hmac_hex(&[0x0b; 20], b"Hi There"), &expected[3..]);
    }

    #[test]
    fn trust_mode_requires_exactly_one_secure_or_local_input() {
        let pcrs = std::path::Path::new("canary-pcrs.json");
        assert!(validate_trust_mode(Some(pcrs), false).is_ok());
        assert!(validate_trust_mode(None, true).is_ok());
        assert!(validate_trust_mode(Some(pcrs), true).is_err());
        assert!(validate_trust_mode(None, false).is_err());
    }

    #[test]
    fn prepared_event_is_retry_stable() {
        let event = PendingEvent {
            name: "target.status_changed",
            endpoint_ids: vec!["alpha-a".to_owned()],
            canary: json!({"node_id": "test"}),
            body: json!({"test": true}),
        };
        let prepared = PreparedEvent::new(&event).unwrap();
        let first = hmac_header(&[7_u8; 32], &prepared.timestamp, &prepared.body);
        let second = hmac_header(&[7_u8; 32], &prepared.timestamp, &prepared.body);
        assert_eq!(first, second);
        assert!(!prepared.id.is_empty());
    }

    #[test]
    fn heartbeat_is_routed_per_endpoint_with_last_target_state() {
        let mut machine = machine();
        machine.observe_target("alpha".to_owned(), observation("VERIFIED"));
        machine.last_heartbeat = Instant::now() - Duration::from_secs(2);
        let events = machine.heartbeat_if_due();
        assert_eq!(events.len(), 3);
        let alpha = events
            .iter()
            .find(|event| event.endpoint_ids == ["alpha-a"])
            .expect("alpha route heartbeat");
        assert_eq!(alpha.name, "watcher.heartbeat");
        assert_eq!(alpha.body["targets"][0]["status"], "VERIFIED");
        assert_eq!(alpha.canary["status"], "UNKNOWN");
    }
}
