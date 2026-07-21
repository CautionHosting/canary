//! Runtime orchestration for Canary V0 monitoring.
//!
//! This module deliberately keeps HTTP routing outside the monitor.  It owns
//! the only mutable state, publishes whole snapshots after SQLite commits,
//! and never reconstructs runtime state from a prior database on restart.

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    time::Duration,
};

use canary_core::{
    canonical::digest,
    config::{parse_and_validate, Config, Target},
    keys::{KeySet, KeysDocument, MasterSeed},
    node::{ConfigDocument, IdentityMode, NodeMetadata},
    state::{
        canonical_target_origin, DefinitiveObservation, StateReason, TargetReducer,
        TransportFailure, RESULT_TTL,
    },
    statement::{sign_statement, Payload, Statement, Status, CLAIM_TYPE},
};
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use rand::Rng;
use tokio::{
    sync::{Mutex, RwLock, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    api::ApiState,
    metadata::write_metadata_atomic,
    model::{
        AttemptWrite, CurrentWrite, ExecutionEnvironment, RuntimeIdentity, RuntimeSnapshot,
        TargetSnapshot,
    },
    network::SystemResolver,
    probe::{probe_target, ProbeAttempt, ProbeClassification, ReqwestTransport},
    scheduler::{scheduled_offset, MAX_CONCURRENT_PROBES},
    store::Store,
};

const CONFIG_PATH: &str = "/app/canary.json";
const DATABASE_PATH: &str = "/tmp/canary/canary.sqlite3";
const METADATA_PATH: &str = "/metadata.json";
const NSM_DEVICE_PATH: &str = "/dev/nsm";
const SIGNING_PARALLELISM: usize = 2;

static PROCESS_IDENTITY: OnceLock<Result<ProcessIdentity, String>> = OnceLock::new();

#[derive(Clone)]
struct ProcessIdentity {
    environment: ExecutionEnvironment,
    binary_digest: String,
}

/// Probe execution boundary used only to make monitor integration tests
/// deterministic. Production construction always installs
/// [`ProductionProbeRunner`], which retains fresh OS nonces and DNS pinning.
#[async_trait::async_trait]
pub trait ProbeRunner: Send + Sync {
    async fn probe(&self, target: &Target, attempted_at: DateTime<Utc>) -> ProbeAttempt;
}

/// The only probe runner selected by the normal daemon constructors.
#[derive(Debug, Default)]
pub struct ProductionProbeRunner;

#[async_trait::async_trait]
impl ProbeRunner for ProductionProbeRunner {
    async fn probe(&self, target: &Target, attempted_at: DateTime<Utc>) -> ProbeAttempt {
        probe_target(&SystemResolver, &ReqwestTransport, target, attempted_at).await
    }
}

/// Clock boundary for deterministic lifecycle tests. Production constructors
/// always install [`SystemRuntimeClock`].
pub trait RuntimeClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Default)]
pub struct SystemRuntimeClock;

impl RuntimeClock for SystemRuntimeClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Clone)]
pub struct RuntimeOptions {
    pub config_path: PathBuf,
    pub database_path: PathBuf,
    pub metadata_path: PathBuf,
    pub identity_source: IdentitySource,
}

/// Source and lifecycle of the signing identity. Deliberately has no `Debug`
/// implementation so a stable seed cannot be logged accidentally.
#[derive(Clone)]
pub enum IdentitySource {
    Stable(Zeroizing<String>),
    Ephemeral,
}

impl IdentitySource {
    fn mode(&self) -> IdentityMode {
        match self {
            Self::Stable(_) => IdentityMode::Stable,
            Self::Ephemeral => IdentityMode::Ephemeral,
        }
    }
}

impl RuntimeOptions {
    /// Production paths are fixed. Stable mode requires
    /// `CANARY_MASTER_SEED`; ephemeral mode refuses it to avoid ambiguous key
    /// lifecycle semantics.
    pub fn from_environment(ephemeral_identity: bool) -> Result<Self, RuntimeError> {
        let identity_source = if ephemeral_identity {
            if std::env::var_os("CANARY_MASTER_SEED").is_some() {
                return Err(RuntimeError::ConflictingIdentityInputs);
            }
            select_identity_source(true, None)?
        } else {
            let master_seed_base64 =
                std::env::var("CANARY_MASTER_SEED").map_err(|_| RuntimeError::MissingMasterSeed)?;
            select_identity_source(false, Some(master_seed_base64))?
        };
        Ok(Self {
            config_path: PathBuf::from(CONFIG_PATH),
            database_path: PathBuf::from(DATABASE_PATH),
            metadata_path: PathBuf::from(METADATA_PATH),
            identity_source,
        })
    }
}

fn select_identity_source(
    ephemeral_identity: bool,
    master_seed_base64: Option<String>,
) -> Result<IdentitySource, RuntimeError> {
    match (ephemeral_identity, master_seed_base64) {
        (true, Some(_)) => Err(RuntimeError::ConflictingIdentityInputs),
        (true, None) => Ok(IdentitySource::Ephemeral),
        (false, Some(seed)) => Ok(IdentitySource::Stable(Zeroizing::new(seed))),
        (false, None) => Err(RuntimeError::MissingMasterSeed),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("CANARY_MASTER_SEED is required")]
    MissingMasterSeed,
    #[error("--ephemeral-identity conflicts with CANARY_MASTER_SEED; choose one identity source")]
    ConflictingIdentityInputs,
    #[error("could not read canary config: {0}")]
    ConfigRead(#[source] std::io::Error),
    #[error("invalid canary config: {0}")]
    Config(#[from] canary_core::config::ConfigParseError),
    #[error("key initialization failed: {0}")]
    Keys(#[from] canary_core::keys::KeyError),
    #[error("node metadata initialization failed: {0}")]
    Node(#[from] canary_core::node::NodeError),
    #[error("canonicalization failed: {0}")]
    Canonical(#[from] canary_core::canonical::CanonicalError),
    #[error("target origin failed validation: {0}")]
    State(#[from] canary_core::state::StateError),
    #[error("statement signing failed: {0}")]
    Statement(#[from] canary_core::statement::StatementError),
    #[error("metadata write failed: {0}")]
    Metadata(#[from] crate::metadata::MetadataError),
    #[error("SQLite operation failed: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("ML-DSA signing task failed: {0}")]
    SigningTask(#[from] tokio::task::JoinError),
    #[error("public API state initialization failed: {0}")]
    Api(#[source] Box<crate::api::ApiStateError>),
    #[error("could not identify the running canaryd binary: {0}")]
    RuntimeIdentity(String),
    #[error("monitor worker {worker} exited before cancellation")]
    WorkerExited { worker: String },
    #[error("monitor worker {worker} failed: {source}")]
    WorkerFailed {
        worker: String,
        #[source]
        source: Box<RuntimeError>,
    },
    #[error("monitor worker {worker} panicked or was cancelled unexpectedly: {source}")]
    WorkerTask {
        worker: String,
        #[source]
        source: tokio::task::JoinError,
    },
}

struct ManagedTarget {
    target: Target,
    origin: String,
    reducer: TargetReducer,
    snapshot: TargetSnapshot,
}

/// In-process monitor and immutable publication surface for the HTTP layer.
#[derive(Clone)]
pub struct Runtime {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    config: ConfigDocument,
    keys: KeysDocument,
    keyset: Arc<KeySet>,
    store: Arc<Store>,
    api: ApiState,
    probe_runner: Arc<dyn ProbeRunner>,
    clock: Arc<dyn RuntimeClock>,
    targets: Mutex<Vec<ManagedTarget>>,
    snapshot: RwLock<RuntimeSnapshot>,
    signing: Arc<Semaphore>,
    probes: Arc<Semaphore>,
    ready: AtomicBool,
    healthy: AtomicBool,
}

type WorkerOutcome = (String, Result<(), RuntimeError>);

async fn wait_for_start(start: Arc<tokio::sync::Barrier>, cancel: CancellationToken) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => false,
        _ = start.wait() => true,
    }
}

async fn drain_workers(workers: &mut JoinSet<WorkerOutcome>) {
    while workers.join_next().await.is_some() {}
}

impl Runtime {
    /// Build fresh signed `PENDING` state and persist all of it before the
    /// first in-memory publication.  No call reads `current_targets`, so a
    /// restart can never resurrect stale process state.
    pub async fn initialize(options: RuntimeOptions) -> Result<Self, RuntimeError> {
        let text = tokio::fs::read_to_string(&options.config_path)
            .await
            .map_err(RuntimeError::ConfigRead)?;
        let config = parse_and_validate(&text)?;
        Self::initialize_with_config(config, options).await
    }

    pub async fn initialize_with_config(
        config: Config,
        options: RuntimeOptions,
    ) -> Result<Self, RuntimeError> {
        Self::initialize_with_config_and_probe_runner(
            config,
            options,
            Arc::new(ProductionProbeRunner),
        )
        .await
    }

    /// Test-only dependency injection for deterministic monitor integration
    /// tests. No environment variable or CLI option can select this path;
    /// production startup always uses [`ProductionProbeRunner`].
    #[doc(hidden)]
    pub async fn initialize_with_config_and_probe_runner(
        config: Config,
        options: RuntimeOptions,
        probe_runner: Arc<dyn ProbeRunner>,
    ) -> Result<Self, RuntimeError> {
        Self::initialize_with_config_and_probe_runner_and_clock(
            config,
            options,
            probe_runner,
            Arc::new(SystemRuntimeClock),
        )
        .await
    }

    /// Test-only dependency injection for deterministic probe and clock
    /// integration tests. No environment variable or CLI option selects this
    /// path; every normal constructor installs the system clock.
    #[doc(hidden)]
    pub async fn initialize_with_config_and_probe_runner_and_clock(
        config: Config,
        options: RuntimeOptions,
        probe_runner: Arc<dyn ProbeRunner>,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, RuntimeError> {
        config
            .validate()
            .map_err(canary_core::config::ConfigParseError::Invalid)?;
        let config = ConfigDocument::new(config)?;
        let identity_mode = options.identity_source.mode();
        let keyset = Arc::new(match &options.identity_source {
            IdentitySource::Stable(master_seed_base64) => {
                let seed = MasterSeed::from_base64(master_seed_base64.as_str())?;
                KeySet::derive(&seed, &config.config.node_id)?
            }
            IdentitySource::Ephemeral => KeySet::generate_ephemeral(&config.config.node_id)?,
        });
        let keys = keyset.keys_document();
        if let Some(parent) = options.database_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(RuntimeError::ConfigRead)?;
        }
        let store = Arc::new(
            Store::open_with_history_limit(
                &options.database_path,
                i64::from(config.config.history_limit),
            )
            .await?,
        );
        let now = canonical_second(clock.now());
        let runtime_identity = runtime_identity(identity_mode)?;
        let signing = Arc::new(Semaphore::new(SIGNING_PARALLELISM));
        let mut targets = Vec::with_capacity(config.config.targets.len());
        let mut published = Vec::with_capacity(config.config.targets.len());

        // Sign and durably write every initial state before exposing one of
        // them.  This makes a signing/DB fault fail closed rather than publish
        // a partial target set.
        for target in &config.config.targets {
            let origin = canonical_target_origin(&target.attestation_url)?;
            let statement = sign_with_limit(
                Arc::clone(&keyset),
                Arc::clone(&signing),
                pending_payload(
                    target,
                    &origin,
                    &config.config.node_id,
                    &config.config_digest,
                    now,
                ),
            )
            .await?;
            let snapshot = snapshot_from_statement(target, origin.clone(), statement, None, None)?;
            store
                .publish_current(CurrentWrite {
                    target: snapshot.clone(),
                    config_digest: config.config_digest.clone(),
                })
                .await?;
            published.push(snapshot.clone());
            targets.push(ManagedTarget {
                target: target.clone(),
                origin,
                reducer: TargetReducer::new(),
                snapshot,
            });
        }

        let initial_snapshot = RuntimeSnapshot {
            protocol: canary_core::node::NODE_PROTOCOL.to_owned(),
            node_id: config.config.node_id.clone(),
            config_digest: config.config_digest.clone(),
            runtime: runtime_identity,
            generated_at: now,
            targets: published,
        };
        let api = ApiState::new(
            initial_snapshot.clone(),
            config.clone(),
            keys.clone(),
            Arc::clone(&store),
        )
        .map_err(|error| RuntimeError::Api(Box::new(error)))?;
        // `/keys.json` is served as these exact canonical bytes.  Bind those
        // exact bytes into Bootproof metadata rather than relying on an
        // equivalent reserialization elsewhere in the process.
        let metadata = NodeMetadata::new(
            config.config.node_id.clone(),
            config.config_digest.clone(),
            digest(api.canonical_keys()),
            identity_mode,
        )?;
        write_metadata_atomic(&options.metadata_path, &metadata).await?;
        let runtime = Self {
            inner: Arc::new(RuntimeInner {
                config: config.clone(),
                keys,
                keyset,
                store,
                api,
                probe_runner,
                clock,
                targets: Mutex::new(targets),
                snapshot: RwLock::new(initial_snapshot),
                signing,
                probes: Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES)),
                // The public API remains unavailable until `run_until_cancelled`
                // has installed every monitor worker.
                ready: AtomicBool::new(false),
                healthy: AtomicBool::new(true),
            }),
        };
        Ok(runtime)
    }

    pub fn is_ready(&self) -> bool {
        self.inner.ready.load(Ordering::Acquire)
    }
    pub fn is_healthy(&self) -> bool {
        self.inner.healthy.load(Ordering::Acquire)
    }

    fn mark_unhealthy(&self) {
        self.inner.healthy.store(false, Ordering::Release);
        self.inner.ready.store(false, Ordering::Release);
        self.inner.api.set_ready(false);
    }
    pub fn config_document(&self) -> &ConfigDocument {
        &self.inner.config
    }
    pub fn keys_document(&self) -> &KeysDocument {
        &self.inner.keys
    }
    pub fn api_state(&self) -> ApiState {
        self.inner.api.clone()
    }
    pub async fn snapshot(&self) -> RuntimeSnapshot {
        self.inner.snapshot.read().await.clone()
    }
    pub fn store(&self) -> Arc<Store> {
        Arc::clone(&self.inner.store)
    }

    /// Run immediate and fixed-cadence probes until cancellation.  Each target
    /// owns one schedule, all of which remain anchored to this invocation's
    /// startup instant.  The shared semaphore permits at most eight network
    /// probes across all targets.
    pub async fn run_until_cancelled(&self, cancel: CancellationToken) -> Result<(), RuntimeError> {
        // Do not briefly report ready when shutdown won the startup race.
        if cancel.is_cancelled() {
            return Ok(());
        }
        let started = tokio::time::Instant::now();
        let target_count = self.inner.targets.lock().await.len();
        // Do not let a worker execute (and potentially fail) between spawn
        // and readiness publication.  The parent joins this barrier only
        // after it has made readiness visible, so a failed worker can never
        // be followed by a stale `ready = true` write.
        let start = Arc::new(tokio::sync::Barrier::new(target_count + 2));
        let mut workers = JoinSet::new();
        for index in 0..target_count {
            let runtime = self.clone();
            let token = cancel.child_token();
            let start = Arc::clone(&start);
            workers.spawn(async move {
                if !wait_for_start(start, token.clone()).await {
                    return (format!("target[{index}]"), Ok(()));
                }
                (
                    format!("target[{index}]"),
                    runtime.target_loop(index, started, token).await,
                )
            });
        }
        let expiry_runtime = self.clone();
        let expiry_token = cancel.child_token();
        let expiry_start = Arc::clone(&start);
        workers.spawn(async move {
            if !wait_for_start(expiry_start, expiry_token.clone()).await {
                return ("expiry".to_owned(), Ok(()));
            }
            (
                "expiry".to_owned(),
                expiry_runtime.expiry_loop(expiry_token).await,
            )
        });
        // Spawning is synchronous; only now can the health endpoint assert
        // that the full monitor worker set has been installed.  Workers are
        // still blocked at `start`, preventing a startup failure from racing
        // this publication.
        if cancel.is_cancelled() {
            drain_workers(&mut workers).await;
            return Ok(());
        }
        self.inner.ready.store(true, Ordering::Release);
        self.inner.api.set_ready(true);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                self.set_not_ready();
                drain_workers(&mut workers).await;
                return Ok(());
            }
            _ = start.wait() => {}
        }
        tracing::info!(target_count, "monitor workers started; service is ready");

        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                self.set_not_ready();
                tracing::info!("monitor cancellation requested; service is not ready");
                drain_workers(&mut workers).await;
                Ok(())
            }
            completed = workers.join_next() => {
                // Cancellation can make a worker complete at the same instant
                // as this branch becomes ready.  Treat that as a requested
                // shutdown, including join errors caused by teardown.
                if cancel.is_cancelled() {
                    self.set_not_ready();
                    drain_workers(&mut workers).await;
                    return Ok(());
                }
                match completed {
                    Some(Ok((worker, Ok(())))) => {
                        tracing::error!(%worker, "monitor worker exited unexpectedly");
                        self.mark_unhealthy();
                        cancel.cancel();
                        drain_workers(&mut workers).await;
                        Err(RuntimeError::WorkerExited { worker })
                    }
                    Some(Ok((worker, Err(source)))) => {
                        tracing::error!(%worker, error = %source, "monitor worker failed");
                        self.mark_unhealthy();
                        cancel.cancel();
                        drain_workers(&mut workers).await;
                        Err(RuntimeError::WorkerFailed {
                            worker,
                            source: Box::new(source),
                        })
                    }
                    Some(Err(source)) => {
                        tracing::error!(error = %source, "monitor worker task failed");
                        self.mark_unhealthy();
                        cancel.cancel();
                        drain_workers(&mut workers).await;
                        Err(RuntimeError::WorkerTask {
                            worker: "unknown".to_owned(),
                            source,
                        })
                    }
                    None => {
                        tracing::error!("all monitor workers exited unexpectedly");
                        self.mark_unhealthy();
                        cancel.cancel();
                        Err(RuntimeError::WorkerExited {
                            worker: "all workers".to_owned(),
                        })
                    }
                }
            }
        }
    }

    fn set_not_ready(&self) {
        self.inner.ready.store(false, Ordering::Release);
        self.inner.api.set_ready(false);
    }

    async fn target_loop(
        &self,
        index: usize,
        started: tokio::time::Instant,
        cancel: CancellationToken,
    ) -> Result<(), RuntimeError> {
        // Required immediate startup probe.
        self.probe_index(index, &cancel).await?;
        let mut number = 1u64;
        let period = Duration::from_secs(self.inner.config.config.probe_interval_seconds);
        loop {
            let jitter = rand::thread_rng().gen_range(0..=5);
            let due = started + scheduled_offset(period, number, jitter);
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = tokio::time::sleep_until(due) => {}
            }
            self.probe_index(index, &cancel).await?;
            number = number.saturating_add(1);
        }
    }

    async fn expiry_loop(&self, cancel: CancellationToken) -> Result<(), RuntimeError> {
        loop {
            // Check before calculating the next wake-up so a scheduling delay
            // cannot skip an already-expired definitive observation.
            self.publish_expired(canonical_second(self.inner.clock.now()))
                .await?;
            let next = {
                let targets = self.inner.targets.lock().await;
                let now = self.inner.clock.now();
                targets
                    .iter()
                    .filter_map(|target| target.reducer.definitive_expiry())
                    .filter(|expiry| *expiry > now)
                    .min()
            };
            let Some(next) = next else {
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
                }
            };
            let delay = (next - self.inner.clock.now())
                .to_std()
                .unwrap_or(Duration::ZERO);
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    async fn probe_index(
        &self,
        index: usize,
        cancel: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        let target = {
            let targets = self.inner.targets.lock().await;
            match targets.get(index) {
                Some(value) => value.target.clone(),
                None => return Ok(()),
            }
        };
        let runner = Arc::clone(&self.inner.probe_runner);
        let permit = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = self.inner.probes.clone().acquire_owned() => result.expect("semaphore is never closed"),
        };
        let attempt = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            attempt = runner.probe(&target, canonical_second(self.inner.clock.now())) => attempt,
        };
        drop(permit);
        let target_id = attempt.target_id.clone();
        let reason = attempt.reason.as_str();
        let classification = attempt.classification;
        let latency_ms = u64::try_from(attempt.latency.as_millis()).ok();
        tracing::debug!(
            %target_id,
            %reason,
            ?classification,
            ?latency_ms,
            "probe completed"
        );
        self.apply_attempt(index, attempt).await?;
        if reason != canary_core::evidence::ProbeReason::AllChecksPassed.as_str() {
            tracing::warn!(
                %target_id,
                %reason,
                ?classification,
                ?latency_ms,
                "probe did not verify target"
            );
        }
        Ok(())
    }

    async fn apply_attempt(&self, index: usize, attempt: ProbeAttempt) -> Result<(), RuntimeError> {
        let mut targets = self.inner.targets.lock().await;
        let Some(managed) = targets.get_mut(index) else {
            return Ok(());
        };
        let previous_status = managed.snapshot.status;
        let previous_reason = managed.snapshot.reason.clone();
        // Runtime publication time is clock-owned; an injected runner cannot
        // move reducer expiry checks independently of the runtime clock.
        let now = canonical_second(self.inner.clock.now());
        let reason = StateReason::from(attempt.reason);
        let definitive_applied = match attempt.classification {
            ProbeClassification::Definitive => {
                managed.reducer.apply_definitive(DefinitiveObservation::new(
                    reason,
                    canonical_second(attempt.observed_at.unwrap_or(now)),
                    attempt.evidence_digest.clone(),
                )?)
            }
            ProbeClassification::Transport => {
                managed
                    .reducer
                    .apply_transport_failure(TransportFailure::new(reason)?);
                false
            }
        };
        let derived = managed.reducer.derive_at(now);
        let retains_fresh = attempt.classification == ProbeClassification::Transport
            && derived.definitive_expires_at.is_some()
            && managed.snapshot.status == derived.status
            && managed.snapshot.reason == derived.reason.as_str();
        let snapshot = if retains_fresh
            || (!definitive_applied && attempt.classification == ProbeClassification::Definitive)
        {
            let mut existing = managed.snapshot.clone();
            existing.transport_warning = derived
                .transport_warning
                .map(|warning| warning.as_str().to_owned());
            existing
        } else {
            let statement = self
                .sign_derived(&managed.target, &managed.origin, &derived, now)
                .await?;
            snapshot_from_statement(
                &managed.target,
                managed.origin.clone(),
                statement,
                if attempt.classification == ProbeClassification::Definitive {
                    attempt.evidence.clone()
                } else {
                    None
                },
                derived
                    .transport_warning
                    .map(|warning| warning.as_str().to_owned()),
            )?
        };
        self.inner
            .store
            .commit(AttemptWrite {
                target: snapshot.clone(),
                attempted_at: canonical_second(attempt.attempted_at),
                attempt_reason: reason.as_str().to_owned(),
                attempt_observed_at: attempt.observed_at.map(canonical_second),
                attempt_evidence: attempt.evidence,
                attempt_transport_warning: if attempt.classification
                    == ProbeClassification::Transport
                {
                    Some(reason.as_str().to_owned())
                } else {
                    None
                },
                latency_ms: u64::try_from(attempt.latency.as_millis()).ok(),
                config_digest: self.inner.config.config_digest.clone(),
            })
            .await?;
        managed.snapshot = snapshot;
        self.publish_locked(&targets, now).await;
        let current = &targets[index].snapshot;
        if current.status != previous_status || current.reason != previous_reason {
            tracing::info!(
                target_id = %current.id,
                old_status = ?previous_status,
                old_reason = %previous_reason,
                new_status = ?current.status,
                new_reason = %current.reason,
                "target state changed"
            );
        }
        Ok(())
    }

    async fn publish_expired(&self, now: DateTime<Utc>) -> Result<(), RuntimeError> {
        let mut targets = self.inner.targets.lock().await;
        let mut changed = false;
        let mut transitions = Vec::new();
        for managed in targets.iter_mut() {
            let derived = managed.reducer.derive_at(now);
            if derived.definitive_expires_at.is_some()
                || (managed.snapshot.status == derived.status
                    && managed.snapshot.reason == derived.reason.as_str())
            {
                continue;
            }
            let statement = self
                .sign_derived(&managed.target, &managed.origin, &derived, now)
                .await?;
            let snapshot = snapshot_from_statement(
                &managed.target,
                managed.origin.clone(),
                statement,
                None,
                None,
            )?;
            transitions.push((
                managed.target.id.clone(),
                managed.snapshot.status,
                managed.snapshot.reason.clone(),
                snapshot.status,
                snapshot.reason.clone(),
            ));
            self.inner
                .store
                .publish_current(CurrentWrite {
                    target: snapshot.clone(),
                    config_digest: self.inner.config.config_digest.clone(),
                })
                .await?;
            managed.snapshot = snapshot;
            changed = true;
        }
        if changed {
            self.publish_locked(&targets, now).await;
            for (target_id, old_status, old_reason, new_status, new_reason) in transitions {
                tracing::info!(
                    %target_id,
                    ?old_status,
                    %old_reason,
                    ?new_status,
                    %new_reason,
                    "target state changed after evidence expiry"
                );
            }
        }
        Ok(())
    }

    async fn sign_derived(
        &self,
        target: &Target,
        origin: &str,
        derived: &canary_core::state::DerivedTargetState,
        now: DateTime<Utc>,
    ) -> Result<Statement, RuntimeError> {
        let observed_at = derived.observed_at.map(canonical_second);
        let issued_at = now;
        let expires_at = observed_at.unwrap_or(issued_at) + RESULT_TTL;
        sign_with_limit(
            Arc::clone(&self.inner.keyset),
            Arc::clone(&self.inner.signing),
            Payload {
                claim_type: CLAIM_TYPE.to_owned(),
                target_id: target.id.clone(),
                target_origin: origin.to_owned(),
                status: derived.status,
                reason: derived.reason.as_str().to_owned(),
                config_digest: self.inner.config.config_digest.clone(),
                evidence_digest: derived.evidence_digest.clone(),
                observed_at: observed_at.map(timestamp),
                issued_at: timestamp(issued_at),
                expires_at: timestamp(expires_at),
                verifier_id: self.inner.config.config.node_id.clone(),
                key_epoch: canary_core::keys::KEY_EPOCH,
            },
        )
        .await
    }

    async fn publish_locked(&self, targets: &[ManagedTarget], now: DateTime<Utc>) {
        let mut snapshot = self.inner.snapshot.write().await;
        snapshot.generated_at = now;
        snapshot.targets = targets
            .iter()
            .map(|target| target.snapshot.clone())
            .collect();
        self.inner.api.publish(snapshot.clone()).await;
    }
}

fn runtime_identity(identity_mode: IdentityMode) -> Result<RuntimeIdentity, RuntimeError> {
    let process = PROCESS_IDENTITY
        .get_or_init(compute_process_identity)
        .clone()
        .map_err(RuntimeError::RuntimeIdentity)?;
    Ok(RuntimeIdentity {
        environment: process.environment,
        binary_digest: process.binary_digest,
        identity_mode,
    })
}

fn compute_process_identity() -> Result<ProcessIdentity, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolving current executable: {error}"))?;
    let bytes = std::fs::read(&executable)
        .map_err(|error| format!("reading {}: {error}", executable.display()))?;
    Ok(ProcessIdentity {
        environment: detect_execution_environment(Path::new(NSM_DEVICE_PATH)),
        binary_digest: digest(&bytes),
    })
}

fn detect_execution_environment(nsm_device: &Path) -> ExecutionEnvironment {
    if nsm_device.exists() {
        ExecutionEnvironment::NitroEnclave
    } else {
        ExecutionEnvironment::NonEnclave
    }
}

fn pending_payload(
    target: &Target,
    origin: &str,
    node_id: &str,
    config_digest: &str,
    now: DateTime<Utc>,
) -> Payload {
    Payload {
        claim_type: CLAIM_TYPE.to_owned(),
        target_id: target.id.clone(),
        target_origin: origin.to_owned(),
        status: Status::Pending,
        reason: StateReason::Pending.as_str().to_owned(),
        config_digest: config_digest.to_owned(),
        evidence_digest: None,
        observed_at: None,
        issued_at: timestamp(now),
        expires_at: timestamp(now + RESULT_TTL),
        verifier_id: node_id.to_owned(),
        key_epoch: canary_core::keys::KEY_EPOCH,
    }
}

async fn sign_with_limit(
    keyset: Arc<KeySet>,
    signing: Arc<Semaphore>,
    payload: Payload,
) -> Result<Statement, RuntimeError> {
    let permit = signing
        .acquire_owned()
        .await
        .expect("signing semaphore is never closed");
    let statement = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        sign_statement(payload, &keyset)
    })
    .await??;
    Ok(statement)
}

fn snapshot_from_statement(
    target: &Target,
    origin: String,
    statement: Statement,
    evidence: Option<canary_core::evidence::EvidenceBundle>,
    transport_warning: Option<String>,
) -> Result<TargetSnapshot, RuntimeError> {
    let payload = &statement.payload;
    Ok(TargetSnapshot {
        id: target.id.clone(),
        name: target.name.clone(),
        target_origin: origin,
        status: payload.status,
        reason: payload.reason.clone(),
        observed_at: payload
            .observed_at
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(canary_core::statement::StatementError::BadTimestamp)?,
        expires_at: payload
            .expires_at
            .parse()
            .map_err(canary_core::statement::StatementError::BadTimestamp)?,
        transport_warning,
        statement,
        evidence,
    })
}

fn canonical_second(value: DateTime<Utc>) -> DateTime<Utc> {
    Utc.timestamp_opt(value.timestamp(), 0)
        .single()
        .expect("UTC seconds are representable")
}
fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use canary_core::{
        evidence::{EvidenceBundle, ProbeReason, EVIDENCE_PROTOCOL},
        statement::Status,
    };
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering as AtomicOrdering};
    use tempfile::TempDir;

    struct CountingProbeRunner(AtomicUsize);

    struct RecordingProbeRunner(AtomicI64);

    struct FailingProbeRunner;

    struct PanickingProbeRunner;

    struct FixedRuntimeClock(DateTime<Utc>);

    struct AdjustableRuntimeClock(AtomicI64);

    #[test]
    fn execution_environment_tracks_nsm_device_availability() {
        let temp = TempDir::new().unwrap();
        let nsm = temp.path().join("nsm");
        assert_eq!(
            detect_execution_environment(&nsm),
            ExecutionEnvironment::NonEnclave
        );
        std::fs::write(&nsm, b"fixture").unwrap();
        assert_eq!(
            detect_execution_environment(&nsm),
            ExecutionEnvironment::NitroEnclave
        );
    }

    #[test]
    fn process_identity_has_a_canonical_binary_digest() {
        let identity = runtime_identity(IdentityMode::Stable).unwrap();
        let hex = identity.binary_digest.strip_prefix("sha256:").unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(identity.identity_mode, IdentityMode::Stable);
    }

    #[test]
    fn identity_source_selection_is_explicit_and_unambiguous() {
        assert!(matches!(
            select_identity_source(true, None).unwrap(),
            IdentitySource::Ephemeral
        ));
        assert!(matches!(
            select_identity_source(false, Some("seed".to_owned())).unwrap(),
            IdentitySource::Stable(_)
        ));
        assert!(matches!(
            select_identity_source(true, Some("seed".to_owned())),
            Err(RuntimeError::ConflictingIdentityInputs)
        ));
        assert!(matches!(
            select_identity_source(false, None),
            Err(RuntimeError::MissingMasterSeed)
        ));
    }

    impl RuntimeClock for FixedRuntimeClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    impl AdjustableRuntimeClock {
        fn set(&self, value: DateTime<Utc>) {
            self.0.store(value.timestamp(), AtomicOrdering::Relaxed);
        }
    }

    impl RuntimeClock for AdjustableRuntimeClock {
        fn now(&self) -> DateTime<Utc> {
            at(self.0.load(AtomicOrdering::Relaxed))
        }
    }

    #[async_trait::async_trait]
    impl ProbeRunner for CountingProbeRunner {
        async fn probe(&self, target: &Target, attempted_at: DateTime<Utc>) -> ProbeAttempt {
            self.0.fetch_add(1, AtomicOrdering::Relaxed);
            ProbeAttempt {
                target_id: target.id.clone(),
                attempted_at,
                completed_at: attempted_at,
                observed_at: None,
                latency: Duration::ZERO,
                classification: ProbeClassification::Transport,
                reason: ProbeReason::Timeout,
                evidence: None,
                evidence_digest: None,
                manifest_digest: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl ProbeRunner for RecordingProbeRunner {
        async fn probe(&self, target: &Target, attempted_at: DateTime<Utc>) -> ProbeAttempt {
            self.0
                .store(attempted_at.timestamp(), AtomicOrdering::Relaxed);
            ProbeAttempt {
                target_id: target.id.clone(),
                attempted_at,
                completed_at: attempted_at,
                observed_at: None,
                latency: Duration::ZERO,
                classification: ProbeClassification::Transport,
                reason: ProbeReason::Timeout,
                evidence: None,
                evidence_digest: None,
                manifest_digest: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl ProbeRunner for FailingProbeRunner {
        async fn probe(&self, target: &Target, attempted_at: DateTime<Utc>) -> ProbeAttempt {
            // `ALL_CHECKS_PASSED` without an evidence digest is rejected by
            // the reducer, deterministically exercising a worker fatal error.
            ProbeAttempt {
                target_id: target.id.clone(),
                attempted_at,
                completed_at: attempted_at,
                observed_at: Some(attempted_at),
                latency: Duration::ZERO,
                classification: ProbeClassification::Definitive,
                reason: ProbeReason::AllChecksPassed,
                evidence: None,
                evidence_digest: None,
                manifest_digest: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl ProbeRunner for PanickingProbeRunner {
        async fn probe(&self, _target: &Target, _attempted_at: DateTime<Utc>) -> ProbeAttempt {
            panic!("intentional monitor worker panic");
        }
    }

    fn config() -> Config {
        serde_json::from_value(serde_json::json!({"version":0,"node_id":"node-a","targets":[{"id":"target-a","name":"Target A","attestation_url":"https://example.test/attestation","expected_pcrs":{"0":"a".repeat(96),"1":"b".repeat(96),"2":"c".repeat(96)}}]})).unwrap()
    }
    fn options(temp: &TempDir) -> RuntimeOptions {
        RuntimeOptions {
            config_path: temp.path().join("canary.json"),
            database_path: temp.path().join("state.sqlite"),
            metadata_path: temp.path().join("metadata.json"),
            identity_source: IdentitySource::Stable(Zeroizing::new(
                base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            )),
        }
    }

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0).single().unwrap()
    }

    fn transport_attempt(now: DateTime<Utc>, reason: ProbeReason) -> ProbeAttempt {
        ProbeAttempt {
            target_id: "target-a".to_owned(),
            attempted_at: now,
            completed_at: now,
            observed_at: None,
            latency: Duration::from_millis(1),
            classification: ProbeClassification::Transport,
            reason,
            evidence: None,
            evidence_digest: None,
            manifest_digest: None,
        }
    }

    fn verified_attempt(now: DateTime<Utc>) -> ProbeAttempt {
        let evidence_digest = format!("sha256:{}", "a".repeat(64));
        let evidence = EvidenceBundle {
            protocol: EVIDENCE_PROTOCOL.to_owned(),
            target_id: "target-a".to_owned(),
            document: "AA==".to_owned(),
            nonce: "nonce".to_owned(),
            observed_at: timestamp(now),
            evidence_digest: evidence_digest.clone(),
            manifest: serde_json::json!({}),
            manifest_digest: format!("sha256:{}", "b".repeat(64)),
        };
        ProbeAttempt {
            target_id: "target-a".to_owned(),
            attempted_at: now,
            completed_at: now,
            observed_at: Some(now),
            latency: Duration::from_millis(1),
            classification: ProbeClassification::Definitive,
            reason: ProbeReason::AllChecksPassed,
            evidence: Some(evidence),
            evidence_digest: Some(evidence_digest),
            manifest_digest: Some(format!("sha256:{}", "b".repeat(64))),
        }
    }

    #[tokio::test]
    async fn initialization_persists_signed_pending_without_history() {
        let temp = TempDir::new().unwrap();
        let runtime = Runtime::initialize_with_config(config(), options(&temp))
            .await
            .unwrap();
        let view = runtime.snapshot().await;
        assert!(!runtime.is_ready());
        assert!(runtime.is_healthy());
        assert_eq!(view.targets[0].status, Status::Pending);
        assert_eq!(view.targets[0].statement.payload.reason, "PENDING");
        assert!(runtime
            .store()
            .history("target-a")
            .await
            .unwrap()
            .is_empty());
        let metadata: NodeMetadata = serde_json::from_slice(
            &tokio::fs::read(temp.path().join("metadata.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        metadata.validate().unwrap();
        assert_eq!(metadata.identity_mode, IdentityMode::Stable);
        assert_eq!(
            metadata.keyset_digest,
            digest(runtime.api_state().canonical_keys())
        );
    }

    #[tokio::test]
    async fn ephemeral_runtime_attests_mode_and_rotates_keys_on_every_start() {
        let first_dir = TempDir::new().unwrap();
        let mut first_options = options(&first_dir);
        first_options.identity_source = IdentitySource::Ephemeral;
        let first = Runtime::initialize_with_config(config(), first_options)
            .await
            .unwrap();

        let second_dir = TempDir::new().unwrap();
        let mut second_options = options(&second_dir);
        second_options.identity_source = IdentitySource::Ephemeral;
        let second = Runtime::initialize_with_config(config(), second_options)
            .await
            .unwrap();

        assert_ne!(
            first.api_state().canonical_keys(),
            second.api_state().canonical_keys()
        );
        assert_eq!(
            first.snapshot().await.runtime.identity_mode,
            IdentityMode::Ephemeral
        );
        let metadata: NodeMetadata = serde_json::from_slice(
            &tokio::fs::read(first_dir.path().join("metadata.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(metadata.identity_mode, IdentityMode::Ephemeral);
    }

    #[test]
    fn fixed_schedule_has_no_drift() {
        let period = Duration::from_secs(60);
        assert_eq!(scheduled_offset(period, 1, 2), Duration::from_secs(62));
        assert_eq!(scheduled_offset(period, 2, 2), Duration::from_secs(122));
    }

    #[tokio::test]
    async fn expiry_at_the_exact_deadline_publishes_signed_stale_without_evidence() {
        let temp = TempDir::new().unwrap();
        let runtime = Runtime::initialize_with_config(config(), options(&temp))
            .await
            .unwrap();
        let now = canonical_second(Utc::now());
        {
            let mut targets = runtime.inner.targets.lock().await;
            targets[0].reducer.apply_definitive(
                DefinitiveObservation::new(
                    StateReason::AllChecksPassed,
                    now - RESULT_TTL,
                    Some(format!("sha256:{}", "a".repeat(64))),
                )
                .unwrap(),
            );
        }
        runtime.publish_expired(now).await.unwrap();
        let view = runtime.snapshot().await;
        assert_eq!(view.targets[0].status, Status::Stale);
        assert_eq!(view.targets[0].reason, "STALE");
        assert!(view.targets[0].statement.payload.evidence_digest.is_none());
        assert!(view.targets[0].statement.payload.observed_at.is_none());
    }

    #[tokio::test]
    async fn restart_ignores_persisted_current_and_creates_fresh_pending() {
        let temp = TempDir::new().unwrap();
        let opts = options(&temp);
        let first = Runtime::initialize_with_config(config(), opts.clone())
            .await
            .unwrap();
        let now = canonical_second(Utc::now());
        {
            let mut targets = first.inner.targets.lock().await;
            targets[0].reducer.apply_definitive(
                DefinitiveObservation::new(
                    StateReason::AllChecksPassed,
                    now - RESULT_TTL,
                    Some(format!("sha256:{}", "a".repeat(64))),
                )
                .unwrap(),
            );
        }
        first.publish_expired(now).await.unwrap();
        assert_eq!(first.snapshot().await.targets[0].status, Status::Stale);
        let restarted = Runtime::initialize_with_config(config(), opts)
            .await
            .unwrap();
        let view = restarted.snapshot().await;
        assert_eq!(view.targets[0].status, Status::Pending);
        assert!(restarted
            .store()
            .history("target-a")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn cancelled_scheduler_exits_without_waiting_for_network() {
        let temp = TempDir::new().unwrap();
        let runtime = Runtime::initialize_with_config(config(), options(&temp))
            .await
            .unwrap();
        let token = CancellationToken::new();
        token.cancel();
        tokio::time::timeout(
            Duration::from_millis(200),
            runtime.run_until_cancelled(token),
        )
        .await
        .expect("cancelled runtime must terminate promptly")
        .expect("cancellation is a clean runtime exit");
    }

    #[tokio::test]
    async fn running_scheduler_cancels_cleanly_without_worker_exit_error() {
        let temp = TempDir::new().unwrap();
        let runtime = Runtime::initialize_with_config_and_probe_runner(
            config(),
            options(&temp),
            Arc::new(CountingProbeRunner(AtomicUsize::new(0))),
        )
        .await
        .unwrap();
        let token = CancellationToken::new();
        let task = tokio::spawn({
            let runtime = runtime.clone();
            let token = token.clone();
            async move { runtime.run_until_cancelled(token).await }
        });
        tokio::time::timeout(Duration::from_millis(500), async {
            while !runtime.is_ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("runtime must become ready after worker installation");
        token.cancel();
        tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .expect("cancelling running scheduler must terminate")
            .expect("scheduler task must not panic")
            .expect("cancellation must be a clean runtime exit");
        assert!(!runtime.is_ready());
        assert!(runtime.is_healthy());
    }

    #[test]
    fn probe_cap_is_fixed_at_eight() {
        assert_eq!(MAX_CONCURRENT_PROBES, 8);
    }

    #[tokio::test]
    async fn injected_runner_is_used_only_by_the_explicit_test_constructor() {
        let temp = TempDir::new().unwrap();
        let runner = Arc::new(CountingProbeRunner(AtomicUsize::new(0)));
        let runtime = Runtime::initialize_with_config_and_probe_runner(
            config(),
            options(&temp),
            runner.clone(),
        )
        .await
        .unwrap();
        runtime
            .probe_index(0, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(runner.0.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(runtime.snapshot().await.targets[0].status, Status::Stale);
    }

    #[tokio::test]
    async fn fixed_clock_controls_initial_publication_and_probe_attempt_time() {
        let temp = TempDir::new().unwrap();
        let fixed = at(42_000);
        let runner = Arc::new(RecordingProbeRunner(AtomicI64::new(-1)));
        let runtime = Runtime::initialize_with_config_and_probe_runner_and_clock(
            config(),
            options(&temp),
            runner.clone(),
            Arc::new(FixedRuntimeClock(fixed)),
        )
        .await
        .unwrap();
        let initial = runtime.snapshot().await;
        assert_eq!(initial.generated_at, fixed);
        assert_eq!(
            initial.targets[0].statement.payload.issued_at,
            timestamp(fixed)
        );
        assert_eq!(initial.targets[0].expires_at, fixed + RESULT_TTL);

        runtime
            .probe_index(0, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(runner.0.load(AtomicOrdering::Relaxed), fixed.timestamp());
        let after = runtime.snapshot().await;
        assert_eq!(after.generated_at, fixed);
        assert_eq!(
            after.targets[0].statement.payload.issued_at,
            timestamp(fixed)
        );
    }

    #[tokio::test]
    async fn repeated_negative_attempts_refresh_their_signed_ttl() {
        let temp = TempDir::new().unwrap();
        let start = at(1_000);
        let clock = Arc::new(AdjustableRuntimeClock(AtomicI64::new(start.timestamp())));
        let runtime = Runtime::initialize_with_config_and_probe_runner_and_clock(
            config(),
            options(&temp),
            Arc::new(CountingProbeRunner(AtomicUsize::new(0))),
            clock.clone(),
        )
        .await
        .unwrap();

        runtime
            .apply_attempt(0, transport_attempt(start, ProbeReason::Timeout))
            .await
            .unwrap();
        let first_stale = runtime.snapshot().await.targets.remove(0);
        clock.set(start + chrono::Duration::seconds(1));
        runtime
            .apply_attempt(
                0,
                transport_attempt(start + chrono::Duration::seconds(1), ProbeReason::Timeout),
            )
            .await
            .unwrap();
        let second_stale = runtime.snapshot().await.targets.remove(0);
        assert_eq!(second_stale.status, Status::Stale);
        assert!(second_stale.expires_at > first_stale.expires_at);
        assert_ne!(second_stale.statement, first_stale.statement);

        clock.set(start + chrono::Duration::seconds(2));
        runtime
            .apply_attempt(
                0,
                transport_attempt(start + chrono::Duration::seconds(2), ProbeReason::Timeout),
            )
            .await
            .unwrap();
        let first_unreachable = runtime.snapshot().await.targets.remove(0);
        clock.set(start + chrono::Duration::seconds(3));
        runtime
            .apply_attempt(
                0,
                transport_attempt(
                    start + chrono::Duration::seconds(3),
                    ProbeReason::Unreachable,
                ),
            )
            .await
            .unwrap();
        let second_unreachable = runtime.snapshot().await.targets.remove(0);
        assert_eq!(second_unreachable.status, Status::Unreachable);
        assert!(second_unreachable.expires_at > first_unreachable.expires_at);
        assert_ne!(second_unreachable.statement, first_unreachable.statement);
    }

    #[tokio::test]
    async fn fresh_verified_transport_preserves_exact_statement_and_evidence() {
        let temp = TempDir::new().unwrap();
        let start = at(2_000);
        let clock = Arc::new(AdjustableRuntimeClock(AtomicI64::new(start.timestamp())));
        let runtime = Runtime::initialize_with_config_and_probe_runner_and_clock(
            config(),
            options(&temp),
            Arc::new(CountingProbeRunner(AtomicUsize::new(0))),
            clock.clone(),
        )
        .await
        .unwrap();
        runtime
            .apply_attempt(0, verified_attempt(start))
            .await
            .unwrap();
        let verified = runtime.snapshot().await.targets.remove(0);
        clock.set(start + chrono::Duration::seconds(1));
        runtime
            .apply_attempt(
                0,
                transport_attempt(start + chrono::Duration::seconds(1), ProbeReason::Timeout),
            )
            .await
            .unwrap();
        let warned = runtime.snapshot().await.targets.remove(0);
        assert_eq!(warned.status, Status::Verified);
        assert_eq!(warned.statement, verified.statement);
        assert_eq!(warned.expires_at, verified.expires_at);
        assert_eq!(warned.evidence, verified.evidence);
        assert_eq!(warned.transport_warning.as_deref(), Some("TIMEOUT"));
    }

    #[tokio::test]
    async fn startup_worker_failure_cannot_restore_readiness() {
        let temp = TempDir::new().unwrap();
        let runtime = Runtime::initialize_with_config_and_probe_runner(
            config(),
            options(&temp),
            Arc::new(FailingProbeRunner),
        )
        .await
        .unwrap();
        assert!(!runtime.is_ready());
        let token = CancellationToken::new();
        let result = tokio::time::timeout(Duration::from_millis(500), {
            let runtime = runtime.clone();
            let token = token.clone();
            async move { runtime.run_until_cancelled(token).await }
        })
        .await
        .expect("fatal initial probe must terminate the runtime");
        assert!(matches!(
            result,
            Err(RuntimeError::WorkerFailed { worker, .. }) if worker == "target[0]"
        ));
        assert!(!runtime.is_ready());
        assert!(!runtime.is_healthy());
    }

    #[tokio::test]
    async fn panicking_worker_stops_runtime_and_propagates_join_error() {
        let temp = TempDir::new().unwrap();
        let runtime = Runtime::initialize_with_config_and_probe_runner(
            config(),
            options(&temp),
            Arc::new(PanickingProbeRunner),
        )
        .await
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            runtime.run_until_cancelled(CancellationToken::new()),
        )
        .await
        .expect("panicking worker must terminate the runtime");
        assert!(matches!(result, Err(RuntimeError::WorkerTask { .. })));
        assert!(!runtime.is_ready());
        assert!(!runtime.is_healthy());
    }
}
