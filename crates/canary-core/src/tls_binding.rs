//! Pure verification of attested TLS metadata against one observed
//! HTTPS peer certificate. Callers must supply `user_data` only after Nitro
//! chain, signature, nonce and expected-PCR verification has succeeded.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::{Host, Url};

pub const TLS_MODE: &str = "tls";
pub const TLS_BINDING_MISMATCH_REASON: &str = "TLS_BINDING_MISMATCH";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsBindingResult {
    pub attested_mode: String,
    pub attested_domain: String,
    pub attested_certfp: String,
    pub observed_certfp: String,
}

impl TlsBindingResult {
    pub fn is_well_formed(&self) -> bool {
        canonical_mode(&self.attested_mode)
            && canonical_domain(&self.attested_domain)
            && canonical_sha256(&self.attested_certfp)
            && canonical_sha256(&self.observed_certfp)
    }

    pub fn matches(&self, expected_domain: &str) -> bool {
        self.is_well_formed()
            && self.attested_mode == TLS_MODE
            && self.attested_domain == expected_domain
            && self.attested_certfp == self.observed_certfp
    }
}

fn canonical_mode(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsUserData {
    tls: AttestedTls,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestedTls {
    mode: String,
    domain: String,
    certfp: String,
}

/// Build a signed diagnostic result from authenticated TLS metadata and the
/// leaf certificate observed on the exact attestation response connection.
pub fn evaluate_tls_binding(
    user_data: Option<&[u8]>,
    peer_certificate_der: Option<&[u8]>,
) -> Option<TlsBindingResult> {
    let metadata: TlsUserData = serde_json::from_slice(user_data?).ok()?;
    let result = TlsBindingResult {
        attested_mode: metadata.tls.mode,
        attested_domain: metadata.tls.domain,
        attested_certfp: metadata.tls.certfp,
        observed_certfp: hex::encode(Sha256::digest(peer_certificate_der?)),
    };
    result.is_well_formed().then_some(result)
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_domain(value: &str) -> bool {
    if value.is_empty() || value.ends_with('.') || !value.is_ascii() {
        return false;
    }
    let Ok(url) = Url::parse(&format!("https://{value}/")) else {
        return false;
    };
    matches!(url.host(), Some(Host::Domain(domain)) if domain == value)
        && url.port().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_data(mode: &str, domain: &str, certfp: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "tls": {"mode": mode, "domain": domain, "certfp": certfp}
        }))
        .unwrap()
    }

    #[test]
    fn matching_metadata_binds_the_observed_leaf() {
        let certificate = b"leaf certificate DER";
        let certfp = hex::encode(Sha256::digest(certificate));
        let result = evaluate_tls_binding(
            Some(&user_data(TLS_MODE, "app.example.com", &certfp)),
            Some(certificate),
        )
        .unwrap();
        assert!(result.matches("app.example.com"));
    }

    #[test]
    fn valid_but_unequal_metadata_is_retained_for_signed_diagnostics() {
        let certificate = b"leaf certificate DER";
        let observed = hex::encode(Sha256::digest(certificate));
        let wrong_domain = evaluate_tls_binding(
            Some(&user_data(TLS_MODE, "other.example.com", &observed)),
            Some(certificate),
        )
        .unwrap();
        assert!(!wrong_domain.matches("app.example.com"));
        assert_eq!(wrong_domain.attested_domain, "other.example.com");

        let wrong_fingerprint = evaluate_tls_binding(
            Some(&user_data(TLS_MODE, "app.example.com", &"a".repeat(64))),
            Some(certificate),
        )
        .unwrap();
        assert!(!wrong_fingerprint.matches("app.example.com"));
        assert_ne!(
            wrong_fingerprint.attested_certfp,
            wrong_fingerprint.observed_certfp
        );
    }

    #[test]
    fn missing_or_noncanonical_inputs_fail_closed() {
        assert_eq!(evaluate_tls_binding(None, Some(b"certificate")), None);
        assert_eq!(
            evaluate_tls_binding(
                Some(&user_data(TLS_MODE, "app.example.com", &"a".repeat(64))),
                None,
            ),
            None
        );
        for malformed in [
            br#"{}"#.as_slice(),
            br#"{"tls":{"mode":"tls","domain":"App.example.com","certfp":"aa"}}"#,
            br#"{"tls":{"mode":"tls\n","domain":"app.example.com","certfp":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#,
            br#"{"tls":{"mode":"tls","domain":"app.example.com","certfp":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#,
            br#"{"tls":{"mode":"tls","domain":"app.example.com","certfp":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true}}"#,
        ] {
            assert!(evaluate_tls_binding(Some(malformed), Some(b"certificate")).is_none());
        }
    }

    #[test]
    fn wrong_mode_is_well_formed_but_does_not_match() {
        let result = evaluate_tls_binding(
            Some(&user_data("caddy", "app.example.com", &"a".repeat(64))),
            Some(b"certificate"),
        )
        .unwrap();
        assert!(!result.matches("app.example.com"));
    }
}
