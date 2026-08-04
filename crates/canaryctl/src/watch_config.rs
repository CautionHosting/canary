//! Strict configuration loading for the external Canary webhook watcher.
//!
//! This configuration deliberately lives outside measured `canary.json`: it
//! contains notification routing and references to local webhook secrets.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

const MAX_TARGETS: usize = 100;
const MAX_WEBHOOKS: usize = 256;

/// Loaded watcher configuration, including HMAC keys read from the process
/// environment. This type intentionally does not implement `Debug` so keys
/// cannot be formatted accidentally.
pub(crate) struct WatchConfig {
    pub(crate) canary: WatchCanary,
    pub(crate) poll_interval_seconds: u64,
    pub(crate) heartbeat_interval_seconds: u64,
    pub(crate) failure_threshold: u32,
    pub(crate) targets: Vec<WatchTarget>,
}

pub(crate) struct WatchCanary {
    pub(crate) url: Url,
    pub(crate) pcrs: Option<PathBuf>,
    pub(crate) keys: PathBuf,
}

pub(crate) struct WatchTarget {
    pub(crate) id: String,
    pub(crate) webhooks: Vec<Webhook>,
}

pub(crate) struct Webhook {
    pub(crate) id: String,
    pub(crate) url: Url,
    pub(crate) secret_env: String,
    pub(crate) secret: Zeroizing<[u8; 32]>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWatchConfig {
    version: u32,
    canary: RawCanary,
    poll_interval_seconds: u64,
    heartbeat_interval_seconds: u64,
    failure_threshold: u32,
    targets: Vec<RawTarget>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCanary {
    url: String,
    pcrs: Option<PathBuf>,
    keys: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTarget {
    id: String,
    webhooks: Vec<RawWebhook>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWebhook {
    id: String,
    url: String,
    secret_env: String,
}

impl WatchConfig {
    /// Read, parse and validate a watcher configuration. Relative trust-input
    /// paths are interpreted relative to `path`, never the process CWD.
    pub(crate) fn load(path: &Path, allow_http_webhooks: bool) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading watcher config {}", path.display()))?;
        let raw: RawWatchConfig = serde_json::from_str(&text)
            .with_context(|| format!("parsing watcher config {}", path.display()))?;
        let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
        Self::from_raw(raw, config_dir, allow_http_webhooks)
    }

    /// Return the Canary origin after enforcing the explicit HTTP permission.
    /// Callers must use this before making any Canary requests.
    pub(crate) fn canary_url(&self, allow_http_canary: bool) -> Result<&Url> {
        if self.canary.url.scheme() == "https" || allow_http_canary {
            Ok(&self.canary.url)
        } else {
            bail!("canary.url must use HTTPS unless --allow-http-canary is set")
        }
    }

    fn from_raw(raw: RawWatchConfig, config_dir: &Path, allow_http_webhooks: bool) -> Result<Self> {
        if raw.version != 1 {
            bail!("watcher config version must be 1");
        }
        validate_positive("poll_interval_seconds", raw.poll_interval_seconds)?;
        validate_positive("heartbeat_interval_seconds", raw.heartbeat_interval_seconds)?;
        if raw.failure_threshold == 0 {
            bail!("failure_threshold must be at least 1");
        }
        if raw.targets.is_empty() {
            bail!("watcher config must contain at least one target");
        }
        if raw.targets.len() > MAX_TARGETS {
            bail!("watcher config must contain at most {MAX_TARGETS} targets");
        }

        let canary_url = parse_canary_url(&raw.canary.url)?;
        let canary = WatchCanary {
            url: canary_url,
            pcrs: raw
                .canary
                .pcrs
                .as_deref()
                .map(|value| resolve_config_path(config_dir, value)),
            keys: resolve_config_path(config_dir, &raw.canary.keys),
        };

        let mut target_ids = HashSet::new();
        let mut webhook_ids = HashSet::new();
        let mut webhook_count = 0_usize;
        let mut targets = Vec::with_capacity(raw.targets.len());
        for target in raw.targets {
            validate_route_identifier("target id", &target.id)?;
            if !target_ids.insert(target.id.clone()) {
                bail!("duplicate target id {:?}", target.id);
            }
            if target.webhooks.is_empty() {
                bail!("target {:?} must configure at least one webhook", target.id);
            }

            let mut webhooks = Vec::with_capacity(target.webhooks.len());
            for webhook in target.webhooks {
                webhook_count = webhook_count.saturating_add(1);
                if webhook_count > MAX_WEBHOOKS {
                    bail!("watcher config must contain at most {MAX_WEBHOOKS} webhooks");
                }
                validate_route_identifier("webhook id", &webhook.id)?;
                if !webhook_ids.insert(webhook.id.clone()) {
                    bail!("duplicate webhook id {:?}", webhook.id);
                }
                validate_env_name(&webhook.secret_env)?;
                let url = parse_webhook_url(&webhook.url, allow_http_webhooks)?;
                let hmac_key = load_hmac_key(&webhook.secret_env)?;
                webhooks.push(Webhook {
                    id: webhook.id,
                    url,
                    secret_env: webhook.secret_env,
                    secret: hmac_key,
                });
            }
            targets.push(WatchTarget {
                id: target.id,
                webhooks,
            });
        }

        Ok(Self {
            canary,
            poll_interval_seconds: raw.poll_interval_seconds,
            heartbeat_interval_seconds: raw.heartbeat_interval_seconds,
            failure_threshold: raw.failure_threshold,
            targets,
        })
    }
}

fn validate_positive(name: &str, value: u64) -> Result<()> {
    if value == 0 {
        bail!("{name} must be at least 1");
    }
    Ok(())
}

fn validate_route_identifier(field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        bail!("{field} must contain only non-empty ASCII letters, digits, '-' or '_'");
    }
    Ok(())
}

fn validate_env_name(value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        bail!(
            "webhook secret_env must be a valid environment variable name beginning with a letter or '_'"
        );
    }
    Ok(())
}

fn resolve_config_path(config_dir: &Path, value: &Path) -> PathBuf {
    if value.is_absolute() {
        value.to_path_buf()
    } else {
        config_dir.join(value)
    }
}

fn parse_canary_url(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).context("parsing canary.url")?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "/" && !url.path().is_empty())
    {
        bail!(
            "canary.url must be an HTTP or HTTPS origin with no credentials, query, fragment, or path"
        );
    }
    url.set_path("/");
    Ok(url)
}

fn parse_webhook_url(value: &str, allow_http: bool) -> Result<Url> {
    let url = Url::parse(value).context("parsing webhook url")?;
    let valid_scheme = url.scheme() == "https" || (allow_http && url.scheme() == "http");
    if !valid_scheme
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        if allow_http {
            bail!("webhook url must be an HTTP or HTTPS URL with no credentials or fragment");
        }
        bail!("webhook url must be an HTTPS URL with no credentials or fragment");
    }
    Ok(url)
}

fn load_hmac_key(secret_env: &str) -> Result<Zeroizing<[u8; 32]>> {
    let encoded = Zeroizing::new(std::env::var(secret_env).with_context(|| {
        format!("required webhook secret environment variable {secret_env:?} is unset")
    })?);
    let decoded = Zeroizing::new(
        STANDARD
            .decode(encoded.as_bytes())
            .with_context(|| format!("decoding base64 webhook secret from {secret_env:?}"))?,
    );
    let key: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "webhook secret environment variable {secret_env:?} must decode to exactly 32 bytes"
        )
    })?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::json;
    use tempfile::TempDir;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn secret_name() -> String {
        format!(
            "CANARY_WATCH_TEST_SECRET_{}",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn set_secret(name: &str) {
        std::env::set_var(name, STANDARD.encode([0x5a; 32]));
    }

    fn write_config(dir: &TempDir, value: serde_json::Value) -> PathBuf {
        let path = dir.path().join("canary-watch.json");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        path
    }

    fn config(secret: &str) -> serde_json::Value {
        json!({
            "version": 1,
            "canary": {
                "url": "https://canary.example.test",
                "pcrs": "trust/canary-pcrs.json",
                "keys": "trust/canary-keys.json"
            },
            "poll_interval_seconds": 30,
            "heartbeat_interval_seconds": 300,
            "failure_threshold": 3,
            "targets": [{
                "id": "payments-prod",
                "webhooks": [{
                    "id": "payments-ops",
                    "url": "https://alerts.example.test/hooks/payments?route=ops",
                    "secret_env": secret
                }]
            }]
        })
    }

    #[test]
    fn loads_multiple_webhooks_and_resolves_relative_paths() {
        let dir = tempfile::tempdir().unwrap();
        let first_secret = secret_name();
        let second_secret = secret_name();
        set_secret(&first_secret);
        set_secret(&second_secret);
        let mut value = config(&first_secret);
        value["targets"][0]["webhooks"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": "payments-oncall",
                "url": "https://oncall.example.test/canary",
                "secret_env": second_secret,
            }));
        let path = write_config(&dir, value);

        let loaded = WatchConfig::load(&path, false).unwrap();

        assert_eq!(loaded.targets[0].webhooks.len(), 2);
        assert_eq!(
            loaded.canary.pcrs,
            Some(dir.path().join("trust/canary-pcrs.json"))
        );
        assert_eq!(
            loaded.canary.keys,
            dir.path().join("trust/canary-keys.json")
        );
        assert_eq!(&*loaded.targets[0].webhooks[0].secret, &[0x5a; 32]);
        std::env::remove_var(first_secret);
        std::env::remove_var(second_secret);
    }

    #[test]
    fn rejects_strict_schema_and_duplicate_ids() {
        let dir = tempfile::tempdir().unwrap();
        let secret = secret_name();
        set_secret(&secret);
        let mut wrong_version = config(&secret);
        wrong_version["version"] = json!(2);
        assert!(WatchConfig::load(&write_config(&dir, wrong_version), false).is_err());

        let mut unknown = config(&secret);
        unknown["unexpected"] = json!(true);
        assert!(WatchConfig::load(&write_config(&dir, unknown), false).is_err());

        let mut duplicate_target = config(&secret);
        duplicate_target["targets"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": "payments-prod",
                "webhooks": [{
                    "id": "other",
                    "url": "https://alerts.example.test/other",
                    "secret_env": secret,
                }]
            }));
        assert!(WatchConfig::load(&write_config(&dir, duplicate_target), false).is_err());

        let mut duplicate_webhook = config(&secret);
        duplicate_webhook["targets"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": "ai-prod",
                "webhooks": [{
                    "id": "payments-ops",
                    "url": "https://alerts.example.test/ai",
                    "secret_env": secret,
                }]
            }));
        assert!(WatchConfig::load(&write_config(&dir, duplicate_webhook), false).is_err());

        let mut invalid_env = config(&secret);
        invalid_env["targets"][0]["webhooks"][0]["secret_env"] = json!("INVALID-ENV-NAME");
        assert!(WatchConfig::load(&write_config(&dir, invalid_env), false).is_err());
        std::env::remove_var(secret);
    }

    #[test]
    fn validates_webhook_scheme_and_local_canary_mode() {
        let dir = tempfile::tempdir().unwrap();
        let secret = secret_name();
        set_secret(&secret);
        let mut value = config(&secret);
        value["targets"][0]["webhooks"][0]["url"] = json!("http://127.0.0.1:8080/hook");
        let path = write_config(&dir, value);
        assert!(WatchConfig::load(&path, false).is_err());
        assert!(WatchConfig::load(&path, true).is_ok());

        let mut local_canary = config(&secret);
        local_canary["canary"]["url"] = json!("http://127.0.0.1:8081");
        let loaded = WatchConfig::load(&write_config(&dir, local_canary), false).unwrap();
        assert!(loaded.canary_url(false).is_err());
        assert!(loaded.canary_url(true).is_ok());
        std::env::remove_var(secret);
    }

    #[test]
    fn requires_present_exactly_sized_secret_and_nonempty_routes() {
        let dir = tempfile::tempdir().unwrap();
        let missing = secret_name();
        assert!(WatchConfig::load(&write_config(&dir, config(&missing)), false).is_err());

        let short = secret_name();
        std::env::set_var(&short, STANDARD.encode([0u8; 31]));
        assert!(WatchConfig::load(&write_config(&dir, config(&short)), false).is_err());
        std::env::remove_var(short);

        let secret = secret_name();
        set_secret(&secret);
        let mut empty_routes = config(&secret);
        empty_routes["targets"][0]["webhooks"] = json!([]);
        assert!(WatchConfig::load(&write_config(&dir, empty_routes), false).is_err());
        std::env::remove_var(secret);
    }
}
