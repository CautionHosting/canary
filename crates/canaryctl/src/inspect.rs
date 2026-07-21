//! `canaryctl enroll` — verify Canary's measured config/key binding.

use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use canary_core::canonical::{canonicalize, digest};
use canary_core::evidence::{pcrs_from_hex, verify_evidence};
use canary_core::keys::KeysDocument;
use canary_core::node::{ConfigDocument, IdentityMode, NodeMetadata};
use rand::rngs::OsRng;
use rand::RngCore as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config_cmd::TrustedHashesFile;

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Serialize)]
struct NonceRequest {
    nonce: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationResponse {
    document: String,
    manifest: serde_json::Value,
}

pub(crate) struct InspectedNode {
    pub(crate) config: ConfigDocument,
    pub(crate) keys: KeysDocument,
    pub(crate) keys_bytes: Vec<u8>,
    pub(crate) trust: NodeTrust,
    pub(crate) metadata: Option<NodeMetadata>,
    agent: ureq::Agent,
    base: Url,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NodeTrust {
    Attested,
    UnattestedDev,
}

pub(crate) struct EnrollmentOutcome {
    pub(crate) node_id: String,
    pub(crate) config_digest: String,
    pub(crate) keyset_digest: String,
    trust: NodeTrust,
    identity: Option<IdentityMode>,
}

impl EnrollmentOutcome {
    pub(crate) fn trust_name(&self) -> &'static str {
        match self.trust {
            NodeTrust::Attested => "ATTESTED",
            NodeTrust::UnattestedDev => "TOFU",
        }
    }

    pub(crate) fn identity_name(&self) -> &'static str {
        match self.identity {
            Some(IdentityMode::Stable) => "stable",
            Some(IdentityMode::Ephemeral) => "ephemeral",
            None => "unknown",
        }
    }

    pub(crate) fn verbose_text(&self, keys_path: &Path) -> String {
        let trust = match self.trust {
            NodeTrust::Attested => "fresh Nitro attestation and expected Canary PCR0/1/2 verified",
            NodeTrust::UnattestedDev => {
                "TOFU: Canary attestation and config authenticity were not verified"
            }
        };
        format!(
            "ENROLLED {}\n  trust: {}\n  identity: {}\n  keys: {}\n  config_digest: {}\n  keyset_digest: {}",
            self.node_id,
            trust,
            self.identity_name(),
            keys_path.display(),
            self.config_digest,
            self.keyset_digest
        )
    }
}

impl InspectedNode {
    pub(crate) fn get_json<T: DeserializeOwned>(&self, segments: &[&str]) -> Result<T> {
        let bytes = get(&self.agent, relative_endpoint(&self.base, segments)?)?;
        serde_json::from_slice(&bytes).context("parsing strict JSON API response")
    }

    pub(crate) fn get_optional_json<T: DeserializeOwned>(
        &self,
        segments: &[&str],
    ) -> Result<Option<T>> {
        match get_optional(&self.agent, relative_endpoint(&self.base, segments)?)? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .context("parsing strict JSON API response")
                .map(Some),
            None => Ok(None),
        }
    }

    pub(crate) fn write_keys(&self, path: &Path) -> Result<()> {
        write_verified_keys(path, &self.keys_bytes)
    }

    /// Require an operator-enrolled key document to exactly match the live
    /// canonical keyset. In stable attested mode this adds continuity to the
    /// fresh binding; in ephemeral mode it pins the current process; in demo
    /// mode it is the sole TOFU key pin.
    pub(crate) fn verify_pinned_keys(&self, path: &Path) -> Result<()> {
        let pinned_bytes = std::fs::read(path)
            .with_context(|| format!("reading pinned Canary keys {}", path.display()))?;
        let pinned: KeysDocument = serde_json::from_slice(&pinned_bytes)
            .with_context(|| format!("parsing pinned Canary keys {}", path.display()))?;
        validate_keys_document(&pinned)
            .with_context(|| format!("validating pinned Canary keys {}", path.display()))?;
        let canonical = canonicalize(&pinned)
            .with_context(|| format!("canonicalizing pinned Canary keys {}", path.display()))?;
        if canonical != pinned_bytes {
            bail!(
                "pinned Canary keys {} are not exact RFC 8785 canonical bytes; use canaryctl enroll --keys",
                path.display()
            );
        }
        if pinned_bytes != self.keys_bytes {
            bail!(
                "live Canary keyset does not match pinned --keys {}; refuse key substitution or unapproved rotation",
                path.display()
            );
        }
        Ok(())
    }
}

enum TrustMode<'a> {
    TrustedPcrs(&'a Path),
    UnattestedDev,
}

pub(crate) fn enroll(
    base_url: &str,
    pcrs_file: Option<&Path>,
    insecure: bool,
    keys_out: &Path,
) -> Result<EnrollmentOutcome> {
    if keys_out.exists() {
        bail!(
            "refusing to overwrite existing --keys {}; choose a new path",
            keys_out.display()
        );
    }
    let mode = select_trust_mode(pcrs_file, insecure)?;
    let inspected = match mode {
        TrustMode::TrustedPcrs(path) => inspect(base_url, path)?,
        TrustMode::UnattestedDev => inspect_unattested(base_url)?,
    };
    inspected
        .write_keys(keys_out)
        .with_context(|| format!("writing verified keys {}", keys_out.display()))?;
    Ok(EnrollmentOutcome {
        node_id: inspected.config.config.node_id.clone(),
        config_digest: inspected.config.config_digest.clone(),
        keyset_digest: digest(&inspected.keys_bytes),
        trust: inspected.trust,
        identity: inspected.metadata.as_ref().map(|value| value.identity_mode),
    })
}

pub(crate) fn inspect(base_url: &str, pcrs_file: &Path) -> Result<InspectedNode> {
    let mut inspected = fetch_public_documents(base_url, false)?;

    let mut nonce = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|err| anyhow::anyhow!("OS CSPRNG failed while generating nonce: {err}"))?;
    let response_bytes = post_nonce(
        &inspected.agent,
        endpoint(&inspected.base, "attestation")?,
        &nonce,
    )?;
    let response: AttestationResponse =
        serde_json::from_slice(&response_bytes).context("parsing strict /attestation response")?;
    let document = STANDARD
        .decode(&response.document)
        .context("decoding /attestation document base64")?;
    if STANDARD.encode(&document) != response.document {
        bail!("/attestation document must use canonical padded standard base64");
    }
    let _ = response.manifest;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX epoch")?;
    let trusted = TrustedHashesFile::load(pcrs_file)?.into_expected_pcrs();
    let expected = pcrs_from_hex(&trusted.pcr0, &trusted.pcr1, &trusted.pcr2)
        .context("decoding trusted PCR0/1/2")?;
    let outcome = verify_evidence(&document, &expected, &nonce, now);
    if !outcome.passed {
        bail!(
            "fresh Canary Bootproof verification failed: {}",
            outcome.reason.as_str()
        );
    }
    let user_data = outcome
        .user_data
        .context("verified Canary attestation is missing signed user_data")?;
    let metadata = validate_verified_binding(
        &inspected.config,
        &inspected.keys,
        &inspected.keys_bytes,
        &user_data,
    )?;
    inspected.trust = NodeTrust::Attested;
    inspected.metadata = Some(metadata);
    Ok(inspected)
}

pub(crate) fn inspect_unattested(base_url: &str) -> Result<InspectedNode> {
    let inspected = fetch_public_documents(base_url, true)?;
    validate_public_documents(&inspected.config, &inspected.keys, &inspected.keys_bytes)?;
    Ok(inspected)
}

fn fetch_public_documents(base_url: &str, allow_http: bool) -> Result<InspectedNode> {
    fetch_public_documents_with(base_url, allow_http, get)
}

fn fetch_public_documents_with(
    base_url: &str,
    allow_http: bool,
    mut fetch: impl FnMut(&ureq::Agent, Url) -> Result<Vec<u8>>,
) -> Result<InspectedNode> {
    let base = parse_base_url(base_url, allow_http)?;
    let agent = http_agent(allow_http);
    let config_bytes = fetch(&agent, endpoint(&base, "config.json")?)?;
    let keys_bytes = fetch(&agent, endpoint(&base, "keys.json")?)?;
    let config = serde_json::from_slice(&config_bytes).context("parsing strict /config.json")?;
    let keys = serde_json::from_slice(&keys_bytes).context("parsing strict /keys.json")?;
    Ok(InspectedNode {
        config,
        keys,
        keys_bytes,
        trust: NodeTrust::UnattestedDev,
        metadata: None,
        agent,
        base,
    })
}

/// Check every post-attestation link. Callers must pass `signed_user_data`
/// only from a successful `verify_evidence` result; this function does not
/// itself establish COSE authenticity or freshness.
fn validate_verified_binding(
    config: &ConfigDocument,
    keys: &KeysDocument,
    keys_bytes: &[u8],
    signed_user_data: &[u8],
) -> Result<NodeMetadata> {
    validate_public_documents(config, keys, keys_bytes)?;
    let metadata: NodeMetadata =
        serde_json::from_slice(signed_user_data).context("parsing strict signed node metadata")?;
    metadata
        .validate()
        .context("validating signed node metadata")?;
    if metadata.node_id != config.config.node_id {
        bail!("metadata node_id does not match /config.json");
    }
    if metadata.config_digest != config.config_digest {
        bail!("metadata config_digest does not match canonical config member");
    }
    if metadata.keyset_digest != digest(keys_bytes) {
        bail!("metadata keyset_digest does not match exact canonical /keys.json");
    }
    if keys.key_epoch != metadata.key_epoch {
        bail!("/keys.json key_epoch does not match signed node metadata");
    }
    Ok(metadata)
}

fn validate_public_documents(
    config: &ConfigDocument,
    keys: &KeysDocument,
    keys_bytes: &[u8],
) -> Result<()> {
    config.validate().context("validating /config.json")?;
    validate_keys_document(keys).context("validating V0 /keys.json")?;
    let canonical_keys = canonicalize(keys).context("canonicalizing /keys.json")?;
    if canonical_keys != keys_bytes {
        bail!("/keys.json is not exact RFC 8785 canonical bytes");
    }
    if keys.node_id != config.config.node_id {
        bail!("/keys.json node_id does not match /config.json");
    }
    if keys.key_epoch != canary_core::keys::KEY_EPOCH {
        bail!("/keys.json key_epoch is not supported by V0");
    }
    Ok(())
}

fn write_verified_keys(path: &Path, keys_bytes: &[u8]) -> Result<()> {
    if path.exists() {
        bail!(
            "refusing to overwrite existing --keys {}; choose a new path",
            path.display()
        );
    }
    write_keys_no_clobber(path, keys_bytes)
}

fn validate_keys_document(keys: &KeysDocument) -> Result<()> {
    const ED25519: &str = "Ed25519";
    const ML_DSA_65: &str = "ML-DSA-65";
    // FIPS 204 ML-DSA-65 public-key encoding length.
    const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
    if keys.protocol != canary_core::node::NODE_PROTOCOL {
        bail!("keys document protocol must be caution-canary-v0");
    }
    if keys.keys.len() != 2 {
        bail!("V0 keys document must contain exactly two keys");
    }
    for algorithm in [ED25519, ML_DSA_65] {
        if keys.keys.iter().filter(|key| key.alg == algorithm).count() != 1 {
            bail!("V0 keys document must contain exactly one {algorithm} key");
        }
    }
    if keys
        .keys
        .iter()
        .any(|key| key.encoding != "base64url" || (key.alg != ED25519 && key.alg != ML_DSA_65))
    {
        bail!("V0 keys document has an unsupported algorithm or encoding");
    }
    for key in &keys.keys {
        let decoded = URL_SAFE_NO_PAD
            .decode(&key.public_key)
            .with_context(|| format!("decoding canonical base64url {} public key", key.alg))?;
        if URL_SAFE_NO_PAD.encode(&decoded) != key.public_key {
            bail!(
                "{} public key must use unpadded canonical base64url",
                key.alg
            );
        }
        let expected = if key.alg == ED25519 {
            32
        } else {
            ML_DSA_65_PUBLIC_KEY_BYTES
        };
        if decoded.len() != expected {
            bail!(
                "{} public key must decode to exactly {expected} bytes, got {}",
                key.alg,
                decoded.len()
            );
        }
    }
    Ok(())
}

/// Publish verified raw keys atomically without replacing an existing path.
/// A hard link to the final path is an atomic no-clobber operation when the
/// temporary file and destination are in the same directory/filesystem.
fn write_keys_no_clobber(path: &Path, contents: &[u8]) -> Result<()> {
    write_keys_no_clobber_with_suffixes(path, contents, random_temporary_suffix)
}

fn random_temporary_suffix() -> Result<String> {
    let mut random = [0u8; 16];
    OsRng.try_fill_bytes(&mut random).map_err(|err| {
        anyhow::anyhow!("OS CSPRNG failed while creating temporary output: {err}")
    })?;
    Ok(hex::encode(random))
}

fn write_keys_no_clobber_with_suffixes(
    path: &Path,
    contents: &[u8],
    mut next_suffix: impl FnMut() -> Result<String>,
) -> Result<()> {
    const MAX_TEMPORARY_ATTEMPTS: usize = 16;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("--keys must have a UTF-8 file name")?;

    let mut created = None;
    for _ in 0..MAX_TEMPORARY_ATTEMPTS {
        let suffix = next_suffix()?;
        let temporary = parent.join(format!(".{name}.inspect-{suffix}.tmp"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temporary)
        {
            Ok(file) => {
                created = Some((temporary, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("creating temporary output {}", temporary.display()));
            }
        }
    }
    let (temporary, mut file) =
        created.context("could not allocate a unique temporary output file")?;
    let mut temporary_exists = true;
    let result = (|| -> Result<()> {
        file.write_all(contents)
            .with_context(|| format!("writing temporary output {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing temporary output {}", temporary.display()))?;
        drop(file);
        std::fs::hard_link(&temporary, path).with_context(|| {
            format!(
                "creating --keys {} without replacing an existing file",
                path.display()
            )
        })?;
        std::fs::remove_file(&temporary)
            .with_context(|| format!("removing temporary output {}", temporary.display()))?;
        temporary_exists = false;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("syncing output directory {}", parent.display()))?;
        Ok(())
    })();
    if result.is_err() && temporary_exists {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn select_trust_mode(pcrs_file: Option<&Path>, insecure: bool) -> Result<TrustMode<'_>> {
    match (pcrs_file, insecure) {
        (Some(path), false) => Ok(TrustMode::TrustedPcrs(path)),
        (None, true) => Ok(TrustMode::UnattestedDev),
        (Some(_), true) | (None, false) => {
            bail!("pass exactly one of --pcrs or --insecure")
        }
    }
}

fn http_agent(allow_http: bool) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .https_only(!allow_http)
        .redirects(0)
        .timeout_connect(Duration::from_secs(5))
        .timeout(HTTP_TIMEOUT)
        .build()
}

fn parse_base_url(value: &str, allow_http: bool) -> Result<Url> {
    let mut url = Url::parse(value).context("parsing --url")?;
    let valid_scheme = url.scheme() == "https" || (allow_http && url.scheme() == "http");
    if !valid_scheme
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "/" && !url.path().is_empty())
    {
        if allow_http {
            bail!("--url must be an HTTP or HTTPS origin with no credentials, query, fragment, or path");
        }
        bail!("--url must be an HTTPS origin with no credentials, query, fragment, or path");
    }
    url.set_path("/");
    Ok(url)
}

fn endpoint(base: &Url, name: &str) -> Result<Url> {
    if !matches!(name, "config.json" | "keys.json" | "attestation") {
        bail!("internal unsafe endpoint name");
    }
    base.join(name).context("constructing fixed endpoint URL")
}

fn relative_endpoint(base: &Url, segments: &[&str]) -> Result<Url> {
    if segments.is_empty() {
        bail!("relative API path must contain at least one path segment");
    }
    for segment in segments {
        if segment.is_empty()
            || matches!(*segment, "." | "..")
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            bail!("relative API path contains an unsafe segment");
        }
    }
    base.join(&segments.join("/"))
        .context("constructing relative API path URL")
}

fn get(agent: &ureq::Agent, url: Url) -> Result<Vec<u8>> {
    let response = agent
        .get(url.as_str())
        .call()
        .with_context(|| format!("GET {url}"))?;
    read_limited(response.into_reader())
}

fn get_optional(agent: &ureq::Agent, url: Url) -> Result<Option<Vec<u8>>> {
    match agent.get(url.as_str()).call() {
        Ok(response) => read_limited(response.into_reader()).map(Some),
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("GET {url}")),
    }
}

fn post_nonce(agent: &ureq::Agent, url: Url, nonce: &[u8; 32]) -> Result<Vec<u8>> {
    let response = agent
        .post(url.as_str())
        .set("Content-Type", "application/json")
        .send_json(NonceRequest {
            nonce: STANDARD.encode(nonce),
        })
        .with_context(|| format!("POST {url}"))?;
    read_limited(response.into_reader())
}

fn read_limited(mut reader: impl std::io::Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("reading HTTP response")?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        bail!("HTTP response exceeds {MAX_RESPONSE_BYTES} byte limit");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use canary_core::config::Config;
    use canary_core::keys::{KeySet, MasterSeed};

    fn binding_fixture() -> (ConfigDocument, KeysDocument, Vec<u8>, NodeMetadata) {
        let config: Config = serde_json::from_value(serde_json::json!({
            "version": 0,
            "node_id": "node-a",
            "targets": [{
                "id":"target-a", "name":"Target A",
                "attestation_url":"https://target.example/attestation",
                "expected_pcrs":{"0":"a".repeat(96), "1":"b".repeat(96), "2":"c".repeat(96)}
            }]
        }))
        .unwrap();
        let config = ConfigDocument::new(config).unwrap();
        let seed = MasterSeed::from_base64(&STANDARD.encode([7u8; 32])).unwrap();
        let keys = KeySet::derive(&seed, "node-a").unwrap().keys_document();
        let keys_bytes = canonicalize(&keys).unwrap();
        let metadata = NodeMetadata::new(
            "node-a".to_owned(),
            config.config_digest.clone(),
            digest(&keys_bytes),
            canary_core::node::IdentityMode::Stable,
        )
        .unwrap();
        (config, keys, keys_bytes, metadata)
    }

    fn metadata_bytes(metadata: &NodeMetadata) -> Vec<u8> {
        canonicalize(metadata).unwrap()
    }

    #[test]
    fn base_url_is_an_https_origin_only() {
        assert!(parse_base_url("https://example.com", false).is_ok());
        for bad in [
            "http://example.com",
            "https://u@example.com",
            "https://example.com/a",
            "https://example.com/?q=x",
            "https://example.com/#x",
        ] {
            assert!(parse_base_url(bad, false).is_err(), "{bad}");
        }
    }

    #[test]
    fn insecure_mode_alone_allows_http_without_attestation() {
        let path = Path::new("trusted_hashes.json");
        assert!(matches!(
            select_trust_mode(Some(path), false).unwrap(),
            TrustMode::TrustedPcrs(_)
        ));
        assert!(matches!(
            select_trust_mode(None, true).unwrap(),
            TrustMode::UnattestedDev
        ));
        assert!(select_trust_mode(Some(path), true).is_err());
        assert!(select_trust_mode(None, false).is_err());
        assert!(parse_base_url("http://example.com", true).is_ok());
        assert!(parse_base_url("http://example.com", false).is_err());
    }

    #[test]
    fn insecure_inspection_fetches_only_public_documents() {
        let (config, _, keys_bytes, _) = binding_fixture();
        let config_bytes = serde_json::to_vec(&config).unwrap();
        let mut paths = Vec::new();
        let inspected = fetch_public_documents_with("http://localhost:1111", true, |_, url| {
            paths.push(url.path().to_owned());
            match url.path() {
                "/config.json" => Ok(config_bytes.clone()),
                "/keys.json" => Ok(keys_bytes.clone()),
                path => panic!("unexpected dev-mode request: {path}"),
            }
        })
        .unwrap();
        validate_public_documents(&inspected.config, &inspected.keys, &inspected.keys_bytes)
            .unwrap();

        assert_eq!(paths, ["/config.json", "/keys.json"]);
        assert_eq!(inspected.trust, NodeTrust::UnattestedDev);
    }

    #[test]
    fn pinned_keys_must_be_canonical_and_exactly_match_live_keyset() {
        let (config, keys, keys_bytes, _) = binding_fixture();
        let inspected = InspectedNode {
            config,
            keys: keys.clone(),
            keys_bytes: keys_bytes.clone(),
            trust: NodeTrust::UnattestedDev,
            metadata: None,
            agent: http_agent(true),
            base: parse_base_url("http://localhost:1111", true).unwrap(),
        };
        let directory = tempfile::tempdir().unwrap();
        let pinned = directory.path().join("keys.json");
        std::fs::write(&pinned, &keys_bytes).unwrap();
        inspected.verify_pinned_keys(&pinned).unwrap();

        std::fs::write(&pinned, serde_json::to_vec_pretty(&keys).unwrap()).unwrap();
        assert!(inspected
            .verify_pinned_keys(&pinned)
            .unwrap_err()
            .to_string()
            .contains("not exact RFC 8785 canonical bytes"));

        let other_seed = MasterSeed::from_base64(&STANDARD.encode([8u8; 32])).unwrap();
        let other_keys = KeySet::derive(&other_seed, "node-a")
            .unwrap()
            .keys_document();
        std::fs::write(&pinned, canonicalize(&other_keys).unwrap()).unwrap();
        assert!(inspected
            .verify_pinned_keys(&pinned)
            .unwrap_err()
            .to_string()
            .contains("refuse key substitution"));
    }

    #[test]
    fn only_fixed_endpoint_names_are_joined() {
        let base = parse_base_url("https://example.com", false).unwrap();
        assert_eq!(
            endpoint(&base, "keys.json").unwrap().as_str(),
            "https://example.com/keys.json"
        );
        assert!(endpoint(&base, "../keys.json").is_err());
    }

    #[test]
    fn relative_api_paths_reject_traversal_and_queries() {
        let base = parse_base_url("https://example.com", false).unwrap();
        assert_eq!(
            relative_endpoint(&base, &["targets", "demo", "statement"])
                .unwrap()
                .as_str(),
            "https://example.com/targets/demo/statement"
        );
        assert!(relative_endpoint(&base, &[]).is_err());
        assert!(relative_endpoint(&base, &["targets", "", "statement"]).is_err());
        assert!(relative_endpoint(&base, &["targets", "..", "statement"]).is_err());
        assert!(relative_endpoint(&base, &["targets", "demo?x=1", "statement"]).is_err());
        assert!(relative_endpoint(&base, &["targets", "demo", "$statement"]).is_err());
    }

    #[test]
    fn bounded_response_rejects_one_byte_over_limit() {
        assert_eq!(
            read_limited(vec![0u8; MAX_RESPONSE_BYTES].as_slice())
                .unwrap()
                .len(),
            MAX_RESPONSE_BYTES
        );
        assert!(read_limited(vec![0u8; MAX_RESPONSE_BYTES + 1].as_slice()).is_err());
    }

    #[test]
    fn keys_document_rejects_duplicate_or_unknown_algorithms() {
        let ed = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let ml = URL_SAFE_NO_PAD.encode(vec![0u8; 1_952]);
        let mut keys: KeysDocument = serde_json::from_value(serde_json::json!({
            "protocol":"caution-canary-v0", "node_id":"node-a", "key_epoch":0,
            "keys":[
                {"alg":"Ed25519", "encoding":"base64url", "public_key":ed},
                {"alg":"ML-DSA-65", "encoding":"base64url", "public_key":ml}
            ]
        }))
        .unwrap();
        assert!(validate_keys_document(&keys).is_ok());
        keys.keys[1].alg = "Ed25519".to_owned();
        assert!(validate_keys_document(&keys).is_err());
    }

    #[test]
    fn keys_document_rejects_noncanonical_or_wrong_length_public_keys() {
        let mut keys: KeysDocument = serde_json::from_value(serde_json::json!({
            "protocol":"caution-canary-v0", "node_id":"node-a", "key_epoch":0,
            "keys":[
                {"alg":"Ed25519", "encoding":"base64url", "public_key":"AA=="},
                {"alg":"ML-DSA-65", "encoding":"base64url", "public_key":URL_SAFE_NO_PAD.encode(vec![0u8; 1952])}
            ]
        }))
        .unwrap();
        assert!(validate_keys_document(&keys).is_err());
        keys.keys[0].public_key = URL_SAFE_NO_PAD.encode([0u8; 31]);
        assert!(validate_keys_document(&keys).is_err());
        keys.keys[0].public_key = URL_SAFE_NO_PAD.encode([0u8; 32]);
        keys.keys[1].public_key = URL_SAFE_NO_PAD.encode(vec![0u8; 1_951]);
        assert!(validate_keys_document(&keys).is_err());
    }

    #[test]
    fn no_clobber_writer_refuses_existing_output() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.json");
        std::fs::write(&path, b"old").unwrap();
        let temporary = directory.path().join(".keys.json.inspect-test.tmp");
        assert!(
            write_keys_no_clobber_with_suffixes(&path, b"new", || Ok("test".to_owned())).is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
        assert!(!temporary.exists());
    }

    #[test]
    fn no_clobber_writer_publishes_new_output() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.json");
        write_keys_no_clobber(&path, b"verified").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"verified");
    }

    #[test]
    fn no_clobber_writer_retries_temp_name_collisions_without_removing_them() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.json");
        let collision = directory.path().join(".keys.json.inspect-collision.tmp");
        let retry = directory.path().join(".keys.json.inspect-retry.tmp");
        std::fs::write(&collision, b"pre-existing temporary").unwrap();
        let mut suffixes = ["collision", "retry"].into_iter();

        write_keys_no_clobber_with_suffixes(&path, b"verified", || {
            Ok(suffixes.next().unwrap().to_owned())
        })
        .unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"verified");
        assert_eq!(
            std::fs::read(&collision).unwrap(),
            b"pre-existing temporary"
        );
        assert!(!retry.exists());
    }

    #[test]
    fn verified_binding_accepts_real_derived_keys_and_matching_metadata() {
        let (config, keys, keys_bytes, metadata) = binding_fixture();
        let actual =
            validate_verified_binding(&config, &keys, &keys_bytes, &metadata_bytes(&metadata))
                .unwrap();
        assert_eq!(actual, metadata);

        let mut ephemeral = metadata;
        ephemeral.identity_mode = IdentityMode::Ephemeral;
        let actual =
            validate_verified_binding(&config, &keys, &keys_bytes, &metadata_bytes(&ephemeral))
                .unwrap();
        assert_eq!(actual.identity_mode, IdentityMode::Ephemeral);
    }

    #[test]
    fn verified_binding_rejects_bad_metadata_and_key_links() {
        let (config, keys, keys_bytes, metadata) = binding_fixture();
        let mut wrong_protocol = metadata.clone();
        wrong_protocol.protocol = "wrong".to_owned();
        let mut wrong_node = metadata.clone();
        wrong_node.node_id = "other".to_owned();
        let mut wrong_epoch = metadata.clone();
        wrong_epoch.key_epoch = 1;
        let mut wrong_config_digest = metadata.clone();
        wrong_config_digest.config_digest = format!("sha256:{}", "d".repeat(64));
        let mut wrong_keyset_digest = metadata.clone();
        wrong_keyset_digest.keyset_digest = format!("sha256:{}", "e".repeat(64));
        let unknown_metadata = serde_json::to_vec(&serde_json::json!({
            "protocol": metadata.protocol,
            "node_id": metadata.node_id,
            "config_digest": metadata.config_digest,
            "keyset_digest": metadata.keyset_digest,
            "key_epoch": metadata.key_epoch,
            "identity_mode": metadata.identity_mode,
            "extra": true,
        }))
        .unwrap();
        let noncanonical_keys = serde_json::to_vec_pretty(&keys).unwrap();
        let cases: Vec<(&str, Vec<u8>, KeysDocument, Vec<u8>)> = vec![
            (
                "missing field",
                br#"{"protocol":"caution-canary-v0"}"#.to_vec(),
                keys.clone(),
                keys_bytes.clone(),
            ),
            (
                "malformed metadata",
                b"not-json".to_vec(),
                keys.clone(),
                keys_bytes.clone(),
            ),
            (
                "unknown metadata field",
                unknown_metadata,
                keys.clone(),
                keys_bytes.clone(),
            ),
            (
                "wrong protocol",
                metadata_bytes(&wrong_protocol),
                keys.clone(),
                keys_bytes.clone(),
            ),
            (
                "wrong node",
                metadata_bytes(&wrong_node),
                keys.clone(),
                keys_bytes.clone(),
            ),
            (
                "wrong epoch",
                metadata_bytes(&wrong_epoch),
                keys.clone(),
                keys_bytes.clone(),
            ),
            (
                "config digest mismatch",
                metadata_bytes(&wrong_config_digest),
                keys.clone(),
                keys_bytes.clone(),
            ),
            (
                "keyset digest mismatch",
                metadata_bytes(&wrong_keyset_digest),
                keys.clone(),
                keys_bytes.clone(),
            ),
            (
                "noncanonical keys",
                metadata_bytes(&metadata),
                keys.clone(),
                noncanonical_keys,
            ),
        ];
        for (name, user_data, candidate_keys, candidate_bytes) in cases {
            assert!(
                validate_verified_binding(&config, &candidate_keys, &candidate_bytes, &user_data)
                    .is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn validation_failure_never_creates_keys_output() {
        let (config, keys, keys_bytes, mut metadata) = binding_fixture();
        metadata.keyset_digest = format!("sha256:{}", "e".repeat(64));
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("keys.json");
        assert!(
            validate_verified_binding(&config, &keys, &keys_bytes, &metadata_bytes(&metadata))
                .is_err()
        );
        assert!(!output.exists());
    }
}
