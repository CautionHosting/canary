//! Async SQLite persistence for ephemeral Canary observations (spec §12).
//!
//! The transaction writes one attempt, prunes that target's history, and
//! replaces its persisted current material as a single unit.  It deliberately
//! has no restore-to-runtime operation: every process starts with freshly
//! signed `PENDING` state regardless of rows left by a same-enclave restart.

use std::{path::Path, str::FromStr};

use chrono::{DateTime, Utc};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row, SqlitePool,
};

use crate::model::{AttemptWrite, CurrentWrite, HistoryEntry, TargetSnapshot};

/// Default retained attempts per target. Runtime config may select a different
/// validated limit for a specific measured deployment.
pub const DEFAULT_HISTORY_LIMIT_ROWS: i64 = canary_core::config::DEFAULT_HISTORY_LIMIT as i64;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("SQLite failure: {0}")]
    Database(#[from] sqlx::Error),
    #[error("SQLite migration failure: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("could not serialize {field}: {source}")]
    Serialize {
        field: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("persisted {field} is malformed: {source}")]
    Deserialize {
        field: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("persisted {field} is invalid: {source}")]
    Timestamp {
        field: &'static str,
        #[source]
        source: chrono::ParseError,
    },
    #[error("latency value {0} is outside the supported range")]
    InvalidLatency(u64),
    #[error("history limit must be positive")]
    InvalidHistoryLimit,
}

/// The successfully committed material.  The scheduler must publish the
/// enclosed snapshot only after receiving this return value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitReceipt {
    pub attempt_id: i64,
    pub snapshot: TargetSnapshot,
}

/// A current-only publication that has reached SQLite durably.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentReceipt {
    pub snapshot: TargetSnapshot,
}

struct CurrentMaterial {
    statement_json: String,
    evidence_json: Option<String>,
    evidence_digest: Option<String>,
    nonce: Option<String>,
    manifest_digest: Option<String>,
    observed_at: Option<String>,
    expires_at: String,
}

/// Ephemeral SQLite store.  No method reconstructs a runtime snapshot from
/// the database; persistence is never an authority for post-restart state.
#[derive(Debug, Clone)]
pub struct Store {
    pool: SqlitePool,
    history_limit: i64,
}

impl Store {
    /// Open a SQLite database and apply the embedded workspace migrations.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_history_limit(path, DEFAULT_HISTORY_LIMIT_ROWS).await
    }

    pub async fn open_with_history_limit(
        path: impl AsRef<Path>,
        history_limit: i64,
    ) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true);
        Self::open_options(options, history_limit).await
    }

    /// Open a database URL and apply the embedded workspace migrations.
    /// This is useful for hermetic `sqlite::memory:` tests.
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        Self::connect_with_history_limit(database_url, DEFAULT_HISTORY_LIMIT_ROWS).await
    }

    pub async fn connect_with_history_limit(
        database_url: &str,
        history_limit: i64,
    ) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::from_str(database_url)?
            .foreign_keys(true)
            .create_if_missing(true);
        Self::open_options(options, history_limit).await
    }

    async fn open_options(
        options: SqliteConnectOptions,
        history_limit: i64,
    ) -> Result<Self, StoreError> {
        if history_limit < 1 {
            return Err(StoreError::InvalidHistoryLimit);
        }
        // A single connection makes `sqlite::memory:` deterministic and avoids
        // a second connection seeing a separate in-memory database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self {
            pool,
            history_limit,
        })
    }

    /// Commit an attempt, prune this target to its configured history limit,
    /// and write
    /// the current signed state/evidence in one transaction.
    ///
    /// A failure returns before a receipt exists, so callers cannot legally
    /// publish the candidate in-memory snapshot.
    pub async fn commit(&self, attempt: AttemptWrite) -> Result<CommitReceipt, StoreError> {
        let latency_ms = attempt
            .latency_ms
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StoreError::InvalidLatency(attempt.latency_ms.unwrap_or_default()))?;
        let current = current_material(&attempt.target)?;
        let attempt_evidence_json = attempt
            .attempt_evidence
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|source| StoreError::Serialize {
                field: "attempt evidence",
                source,
            })?;
        let attempt_evidence_digest = attempt
            .attempt_evidence
            .as_ref()
            .map(|evidence| evidence.evidence_digest.as_str());
        let attempt_nonce = attempt
            .attempt_evidence
            .as_ref()
            .map(|evidence| evidence.nonce.as_str());
        let attempt_manifest_digest = attempt
            .attempt_evidence
            .as_ref()
            .map(|evidence| evidence.manifest_digest.as_str());
        let attempted_at = timestamp(attempt.attempted_at);
        let attempt_observed_at = attempt.attempt_observed_at.map(timestamp);

        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "INSERT INTO attempts \
             (target_id, attempted_at, observed_at, state, reason, attempt_reason, latency_ms, config_digest, \
              statement_json, evidence_json, evidence_digest, nonce, manifest_digest, transport_warning) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&attempt.target.id)
        .bind(&attempted_at)
        .bind(&attempt_observed_at)
        .bind(status_name(attempt.target.status))
        .bind(&attempt.target.reason)
        .bind(&attempt.attempt_reason)
        .bind(latency_ms)
        .bind(&attempt.config_digest)
        .bind(&current.statement_json)
        .bind(&attempt_evidence_json)
        .bind(attempt_evidence_digest)
        .bind(attempt_nonce)
        .bind(attempt_manifest_digest)
        .bind(&attempt.attempt_transport_warning)
        .execute(&mut *tx)
        .await?;
        let attempt_id = result.last_insert_rowid();

        // Retention is in the same transaction as the insert/current update;
        // one target never affects another target's history.
        sqlx::query(
            "DELETE FROM attempts
             WHERE target_id = ?
               AND id NOT IN (
                   SELECT id FROM attempts
                   WHERE target_id = ?
                   ORDER BY attempted_at DESC, id DESC
                   LIMIT ?
               )",
        )
        .bind(&attempt.target.id)
        .bind(&attempt.target.id)
        .bind(self.history_limit)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO current_targets
             (target_id, target_name, target_origin, last_attempted_at, observed_at, expires_at,
              state, reason, transport_warning, config_digest, statement_json, evidence_json,
              evidence_digest, nonce, manifest_digest)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(target_id) DO UPDATE SET
               target_name = excluded.target_name,
               target_origin = excluded.target_origin,
               last_attempted_at = excluded.last_attempted_at,
               observed_at = excluded.observed_at,
               expires_at = excluded.expires_at,
               state = excluded.state,
               reason = excluded.reason,
               transport_warning = excluded.transport_warning,
               config_digest = excluded.config_digest,
               statement_json = excluded.statement_json,
               evidence_json = excluded.evidence_json,
               evidence_digest = excluded.evidence_digest,
               nonce = excluded.nonce,
               manifest_digest = excluded.manifest_digest",
        )
        .bind(&attempt.target.id)
        .bind(&attempt.target.name)
        .bind(&attempt.target.target_origin)
        .bind(&attempted_at)
        .bind(&current.observed_at)
        .bind(&current.expires_at)
        .bind(status_name(attempt.target.status))
        .bind(&attempt.target.reason)
        .bind(&attempt.target.transport_warning)
        .bind(&attempt.config_digest)
        .bind(&current.statement_json)
        .bind(&current.evidence_json)
        .bind(&current.evidence_digest)
        .bind(&current.nonce)
        .bind(&current.manifest_digest)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(CommitReceipt {
            attempt_id,
            snapshot: attempt.target,
        })
    }

    /// Persist a signed current state without manufacturing a probe attempt.
    ///
    /// Used for startup `PENDING` and active timer-derived expiry states.  On
    /// an existing target it preserves `last_attempted_at`; callers receive a
    /// receipt only after the database commit and may then publish in memory.
    pub async fn publish_current(
        &self,
        current_write: CurrentWrite,
    ) -> Result<CurrentReceipt, StoreError> {
        let current = current_material(&current_write.target)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO current_targets
             (target_id, target_name, target_origin, last_attempted_at, observed_at, expires_at,
              state, reason, transport_warning, config_digest, statement_json, evidence_json,
              evidence_digest, nonce, manifest_digest)
             VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(target_id) DO UPDATE SET
               target_name = excluded.target_name,
               target_origin = excluded.target_origin,
               observed_at = excluded.observed_at,
               expires_at = excluded.expires_at,
               state = excluded.state,
               reason = excluded.reason,
               transport_warning = excluded.transport_warning,
               config_digest = excluded.config_digest,
               statement_json = excluded.statement_json,
               evidence_json = excluded.evidence_json,
               evidence_digest = excluded.evidence_digest,
               nonce = excluded.nonce,
               manifest_digest = excluded.manifest_digest",
        )
        .bind(&current_write.target.id)
        .bind(&current_write.target.name)
        .bind(&current_write.target.target_origin)
        .bind(&current.observed_at)
        .bind(&current.expires_at)
        .bind(status_name(current_write.target.status))
        .bind(&current_write.target.reason)
        .bind(&current_write.target.transport_warning)
        .bind(&current_write.config_digest)
        .bind(&current.statement_json)
        .bind(&current.evidence_json)
        .bind(&current.evidence_digest)
        .bind(&current.nonce)
        .bind(&current.manifest_digest)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(CurrentReceipt {
            snapshot: current_write.target,
        })
    }

    /// Return the newest bounded history for one target.  This query never
    /// selects raw evidence, nonce, or signature JSON.
    pub async fn history(&self, target_id: &str) -> Result<Vec<HistoryEntry>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, target_id, attempted_at, observed_at, state, reason, attempt_reason, latency_ms,
                    evidence_digest, manifest_digest, config_digest, transport_warning
             FROM attempts WHERE target_id = ?
             ORDER BY attempted_at DESC, id DESC LIMIT ?",
        )
        .bind(target_id)
        .bind(self.history_limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(history_row).collect()
    }

    #[cfg(test)]
    async fn count_rows(&self, table: &str, target_id: &str) -> Result<i64, StoreError> {
        let query = match table {
            "attempts" => "SELECT COUNT(*) AS count FROM attempts WHERE target_id = ?",
            "current_targets" => {
                "SELECT COUNT(*) AS count FROM current_targets WHERE target_id = ?"
            }
            _ => unreachable!("test-only fixed table names"),
        };
        Ok(sqlx::query(query)
            .bind(target_id)
            .fetch_one(&self.pool)
            .await?
            .get("count"))
    }

    #[cfg(test)]
    async fn nullable_columns(
        &self,
        target_id: &str,
    ) -> Result<
        (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ),
        StoreError,
    > {
        let row = sqlx::query(
            "SELECT evidence_json, evidence_digest, nonce, manifest_digest
             FROM attempts WHERE target_id = ? ORDER BY id DESC LIMIT 1",
        )
        .bind(target_id)
        .fetch_one(&self.pool)
        .await?;
        Ok((
            row.try_get("evidence_json")?,
            row.try_get("evidence_digest")?,
            row.try_get("nonce")?,
            row.try_get("manifest_digest")?,
        ))
    }

    #[cfg(test)]
    async fn persisted_material(
        &self,
        target_id: &str,
    ) -> Result<(String, String, String, String, String, Option<String>), StoreError> {
        let row = sqlx::query(
            "SELECT attempted_at, observed_at, state, reason, statement_json, evidence_json
             FROM attempts WHERE target_id = ? ORDER BY id DESC LIMIT 1",
        )
        .bind(target_id)
        .fetch_one(&self.pool)
        .await?;
        Ok((
            row.try_get("attempted_at")?,
            row.try_get("observed_at")?,
            row.try_get("state")?,
            row.try_get("reason")?,
            row.try_get("statement_json")?,
            row.try_get("evidence_json")?,
        ))
    }

    #[cfg(test)]
    async fn current_row(
        &self,
        target_id: &str,
    ) -> Result<(Option<String>, String, String), StoreError> {
        let row = sqlx::query(
            "SELECT last_attempted_at, state, reason
             FROM current_targets WHERE target_id = ?",
        )
        .bind(target_id)
        .fetch_one(&self.pool)
        .await?;
        Ok((
            row.try_get("last_attempted_at")?,
            row.try_get("state")?,
            row.try_get("reason")?,
        ))
    }

    #[cfg(test)]
    fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

fn current_material(target: &TargetSnapshot) -> Result<CurrentMaterial, StoreError> {
    let statement_json =
        serde_json::to_string(&target.statement).map_err(|source| StoreError::Serialize {
            field: "statement",
            source,
        })?;
    let evidence_json = target
        .evidence
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|source| StoreError::Serialize {
            field: "evidence",
            source,
        })?;
    Ok(CurrentMaterial {
        statement_json,
        evidence_digest: target
            .evidence
            .as_ref()
            .map(|evidence| evidence.evidence_digest.clone()),
        nonce: target
            .evidence
            .as_ref()
            .map(|evidence| evidence.nonce.clone()),
        manifest_digest: target
            .evidence
            .as_ref()
            .map(|evidence| evidence.manifest_digest.clone()),
        evidence_json,
        observed_at: target.observed_at.map(timestamp),
        expires_at: timestamp(target.expires_at),
    })
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn parse_timestamp(field: &'static str, value: String) -> Result<DateTime<Utc>, StoreError> {
    value
        .parse()
        .map_err(|source| StoreError::Timestamp { field, source })
}

fn status_name(status: canary_core::statement::Status) -> &'static str {
    match status {
        canary_core::statement::Status::Verified => "VERIFIED",
        canary_core::statement::Status::Failed => "FAILED",
        canary_core::statement::Status::Pending => "PENDING",
        canary_core::statement::Status::Unreachable => "UNREACHABLE",
        canary_core::statement::Status::Stale => "STALE",
    }
}

fn parse_status(value: String) -> Result<canary_core::statement::Status, StoreError> {
    serde_json::from_value(serde_json::Value::String(value)).map_err(|source| {
        StoreError::Deserialize {
            field: "state",
            source,
        }
    })
}

fn history_row(row: sqlx::sqlite::SqliteRow) -> Result<HistoryEntry, StoreError> {
    let latency_ms: Option<i64> = row.try_get("latency_ms")?;
    Ok(HistoryEntry {
        id: row.try_get("id")?,
        target_id: row.try_get("target_id")?,
        attempted_at: parse_timestamp("attempted_at", row.try_get("attempted_at")?)?,
        observed_at: row
            .try_get::<Option<String>, _>("observed_at")?
            .map(|value| parse_timestamp("observed_at", value))
            .transpose()?,
        status: parse_status(row.try_get("state")?)?,
        reason: row.try_get("reason")?,
        attempt_reason: row.try_get("attempt_reason")?,
        latency_ms: latency_ms
            .map(u64::try_from)
            .transpose()
            .map_err(|_| StoreError::InvalidLatency(latency_ms.unwrap_or_default() as u64))?,
        evidence_digest: row.try_get("evidence_digest")?,
        manifest_digest: row.try_get("manifest_digest")?,
        config_digest: row.try_get("config_digest")?,
        transport_warning: row.try_get("transport_warning")?,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use canary_core::{
        evidence::EvidenceBundle,
        statement::{Payload, Signature, Signer, Statement, Status},
    };
    use chrono::{Duration, TimeZone};
    use tempfile::TempDir;

    use super::*;

    static NEXT_DB: AtomicU64 = AtomicU64::new(0);

    async fn store() -> (TempDir, Store) {
        store_with_history_limit(DEFAULT_HISTORY_LIMIT_ROWS).await
    }

    async fn store_with_history_limit(history_limit: i64) -> (TempDir, Store) {
        let dir = tempfile::tempdir().expect("temp directory");
        let path = dir.path().join(format!(
            "canary-{}.sqlite3",
            NEXT_DB.fetch_add(1, Ordering::Relaxed)
        ));
        let store = Store::open_with_history_limit(&path, history_limit)
            .await
            .expect("migrations apply");
        (dir, store)
    }

    fn at(second: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + second, 0)
            .single()
            .unwrap()
    }

    fn statement(target_id: &str, status: Status, observed_at: Option<DateTime<Utc>>) -> Statement {
        let issued_at = observed_at.unwrap_or_else(|| at(0));
        Statement {
            payload: Payload {
                claim_type: "caution.canary.pcr-match.v0".to_owned(),
                target_id: target_id.to_owned(),
                target_origin: "https://example.test".to_owned(),
                status,
                reason: "ALL_CHECKS_PASSED".to_owned(),
                config_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                evidence_digest: None,
                observed_at: observed_at.map(timestamp),
                issued_at: timestamp(issued_at),
                expires_at: timestamp(issued_at + Duration::seconds(180)),
                verifier_id: "node".to_owned(),
                key_epoch: 0,
            },
            signers: vec![Signer {
                verifier_id: "node".to_owned(),
                key_epoch: 0,
                signatures: vec![Signature {
                    alg: "Ed25519".to_owned(),
                    sig: "placeholder".to_owned(),
                }],
            }],
        }
    }

    fn evidence(target_id: &str, observed_at: DateTime<Utc>) -> EvidenceBundle {
        EvidenceBundle {
            protocol: "caution-canary-evidence-v0".to_owned(),
            target_id: target_id.to_owned(),
            document: "AA==".to_owned(),
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            observed_at: timestamp(observed_at),
            evidence_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            manifest: serde_json::json!({}),
            manifest_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        }
    }

    fn attempt(target_id: &str, second: i64, with_evidence: bool) -> AttemptWrite {
        let observed_at = if with_evidence {
            Some(at(second))
        } else {
            None
        };
        let status = if with_evidence {
            Status::Verified
        } else {
            Status::Unreachable
        };
        let stmt = statement(target_id, status, observed_at);
        AttemptWrite {
            target: TargetSnapshot {
                id: target_id.to_owned(),
                name: format!("{target_id} name"),
                target_origin: "https://example.test".to_owned(),
                status,
                reason: if with_evidence {
                    "ALL_CHECKS_PASSED".to_owned()
                } else {
                    "TIMEOUT".to_owned()
                },
                observed_at,
                expires_at: at(second + 180),
                transport_warning: (!with_evidence).then(|| "TIMEOUT".to_owned()),
                statement: stmt,
                evidence: with_evidence.then(|| evidence(target_id, at(second))),
            },
            attempted_at: at(second),
            attempt_reason: if with_evidence {
                "ALL_CHECKS_PASSED".to_owned()
            } else {
                "TIMEOUT".to_owned()
            },
            attempt_observed_at: observed_at,
            attempt_evidence: with_evidence.then(|| evidence(target_id, at(second))),
            attempt_transport_warning: (!with_evidence).then(|| "TIMEOUT".to_owned()),
            latency_ms: Some(42),
            config_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        }
    }

    fn current_write(target_id: &str, status: Status, reason: &str, second: i64) -> CurrentWrite {
        CurrentWrite {
            target: TargetSnapshot {
                id: target_id.to_owned(),
                name: format!("{target_id} name"),
                target_origin: "https://example.test".to_owned(),
                status,
                reason: reason.to_owned(),
                observed_at: None,
                expires_at: at(second + 180),
                transport_warning: None,
                statement: statement(target_id, status, None),
                evidence: None,
            },
            config_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        }
    }

    #[tokio::test]
    async fn migrations_are_idempotent_on_an_empty_database() {
        let (dir, first) = store().await;
        drop(first);
        let path = dir.path().join("reopen.sqlite3");
        let one = Store::open(&path).await.expect("first open");
        let two = Store::open(&path).await.expect("second open");
        assert!(one.history("missing").await.unwrap().is_empty());
        assert!(two.history("missing").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn nullable_evidence_material_is_persisted_as_null() {
        let (_dir, store) = store().await;
        store.commit(attempt("one", 1, false)).await.unwrap();
        assert_eq!(
            store.nullable_columns("one").await.unwrap(),
            (None, None, None, None)
        );
    }

    #[tokio::test]
    async fn startup_pending_publishes_current_without_attempt_history() {
        let (_dir, store) = store().await;
        let receipt = store
            .publish_current(current_write("one", Status::Pending, "PENDING", 0))
            .await
            .unwrap();

        assert_eq!(receipt.snapshot.status, Status::Pending);
        assert!(store.history("one").await.unwrap().is_empty());
        assert_eq!(store.count_rows("attempts", "one").await.unwrap(), 0);
        assert_eq!(
            store.current_row("one").await.unwrap(),
            (None, "PENDING".to_owned(), "PENDING".to_owned())
        );
    }

    #[tokio::test]
    async fn timer_only_current_publication_preserves_history_and_last_attempt() {
        let (_dir, store) = store().await;
        store.commit(attempt("one", 1, true)).await.unwrap();
        let receipt = store
            .publish_current(current_write("one", Status::Stale, "STALE", 181))
            .await
            .unwrap();

        assert_eq!(receipt.snapshot.status, Status::Stale);
        assert_eq!(store.history("one").await.unwrap().len(), 1);
        assert_eq!(
            store.current_row("one").await.unwrap(),
            (
                Some(timestamp(at(1))),
                "STALE".to_owned(),
                "STALE".to_owned()
            )
        );
    }

    #[tokio::test]
    async fn reopening_store_keeps_rows_diagnostic_only_without_runtime_restore() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("restart.sqlite3");
        let first = Store::open(&path).await.unwrap();
        first.commit(attempt("one", 1, true)).await.unwrap();
        drop(first);

        let restarted = Store::open(&path).await.unwrap();
        // `Store` exposes only bounded diagnostics (`history`) and has no
        // API that yields a TargetSnapshot/RuntimeSnapshot from persisted
        // current rows. Runtime startup must therefore create PENDING itself.
        assert_eq!(restarted.history("one").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn transport_attempt_does_not_duplicate_retained_current_evidence() {
        let (_dir, store) = store().await;
        let verified = attempt("one", 1, true);
        store.commit(verified.clone()).await.unwrap();

        let mut timeout = verified;
        timeout.attempted_at = at(2);
        timeout.attempt_reason = "TIMEOUT".to_owned();
        timeout.attempt_observed_at = None;
        timeout.attempt_evidence = None;
        timeout.attempt_transport_warning = Some("TIMEOUT".to_owned());
        timeout.target.transport_warning = Some("TIMEOUT".to_owned());
        // The target snapshot intentionally retains the successful statement
        // and evidence from second 1 while this new attempt has none.
        store.commit(timeout).await.unwrap();

        assert_eq!(
            store.nullable_columns("one").await.unwrap(),
            (None, None, None, None)
        );
        let attempt_row = sqlx::query(
            "SELECT state, reason, attempt_reason FROM attempts
             WHERE target_id = ? ORDER BY id DESC LIMIT 1",
        )
        .bind("one")
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            attempt_row.try_get::<String, _>("state").unwrap(),
            "VERIFIED"
        );
        assert_eq!(
            attempt_row.try_get::<String, _>("reason").unwrap(),
            "ALL_CHECKS_PASSED"
        );
        assert_eq!(
            attempt_row.try_get::<String, _>("attempt_reason").unwrap(),
            "TIMEOUT"
        );
        let history = store.history("one").await.unwrap();
        assert_eq!(history[0].status, Status::Verified);
        assert_eq!(history[0].reason, "ALL_CHECKS_PASSED");
        assert_eq!(history[0].attempt_reason, "TIMEOUT");
        let current =
            sqlx::query("SELECT evidence_json, nonce FROM current_targets WHERE target_id = ?")
                .bind("one")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(current
            .try_get::<Option<String>, _>("evidence_json")
            .unwrap()
            .is_some());
        assert!(current
            .try_get::<Option<String>, _>("nonce")
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn successful_attempt_persists_current_signed_and_evidence_material() {
        let (_dir, store) = store().await;
        let write = attempt("one", 7, true);
        store.commit(write.clone()).await.unwrap();

        let (attempted_at, observed_at, state, reason, statement_json, evidence_json) =
            store.persisted_material("one").await.unwrap();
        assert_eq!(attempted_at, timestamp(at(7)));
        assert_eq!(observed_at, timestamp(at(7)));
        assert_eq!(state, "VERIFIED");
        assert_eq!(reason, "ALL_CHECKS_PASSED");
        assert_eq!(
            serde_json::from_str::<Statement>(&statement_json).unwrap(),
            write.target.statement.clone()
        );
        assert_eq!(
            serde_json::from_str::<EvidenceBundle>(&evidence_json.unwrap()).unwrap(),
            write.target.evidence.clone().unwrap()
        );
        let current = sqlx::query(
            "SELECT state, reason, statement_json, evidence_json
             FROM current_targets WHERE target_id = ?",
        )
        .bind("one")
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(current.try_get::<String, _>("state").unwrap(), "VERIFIED");
        assert_eq!(
            current.try_get::<String, _>("reason").unwrap(),
            "ALL_CHECKS_PASSED"
        );
        assert_eq!(
            serde_json::from_str::<Statement>(
                &current.try_get::<String, _>("statement_json").unwrap()
            )
            .unwrap(),
            write.target.statement
        );
        assert_eq!(
            serde_json::from_str::<EvidenceBundle>(
                &current.try_get::<String, _>("evidence_json").unwrap()
            )
            .unwrap(),
            write.target.evidence.unwrap()
        );
    }

    #[tokio::test]
    async fn prune_is_per_target_and_uses_the_configured_limit() {
        const LIMIT: i64 = 100;
        let (_dir, store) = store_with_history_limit(LIMIT).await;
        for second in 0..101 {
            store.commit(attempt("one", second, true)).await.unwrap();
        }
        store.commit(attempt("two", 0, true)).await.unwrap();

        let one = store.history("one").await.unwrap();
        assert_eq!(one.len(), LIMIT as usize);
        assert_eq!(one.first().unwrap().attempted_at, at(100));
        assert_eq!(one.last().unwrap().attempted_at, at(1));
        assert_eq!(store.history("two").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_current_update_failure_rolls_back_attempt_and_pruning() {
        let (_dir, store) = store().await;
        store.commit(attempt("one", 1, true)).await.unwrap();
        sqlx::query(
            "CREATE TRIGGER fail_current_update BEFORE UPDATE ON current_targets
             BEGIN SELECT RAISE(ABORT, 'forced current update failure'); END",
        )
        .execute(store.pool())
        .await
        .unwrap();

        let err = store.commit(attempt("one", 2, false)).await.unwrap_err();
        assert!(matches!(err, StoreError::Database(_)));
        assert_eq!(store.count_rows("attempts", "one").await.unwrap(), 1);
        assert_eq!(store.count_rows("current_targets", "one").await.unwrap(), 1);
        let history = store.history("one").await.unwrap();
        assert_eq!(history[0].attempted_at, at(1));
    }
}
