//! RFC 8785 (JCS) canonical JSON serialization and SHA-256 digest helpers.
//!
//! Used to compute `config_digest`, `keyset_digest`, and the signed statement
//! payload bytes per spec §6, §7.3, §8.3, §9. Canonicalization must be
//! byte-exact and stable.

use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    #[error("canonical JSON serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// RFC 8785 canonical JSON bytes for any serializable value.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    Ok(serde_jcs::to_vec(value)?)
}

/// RFC 8785 canonical JSON bytes for an already-parsed `serde_json::Value`.
pub fn canonicalize_value(value: &serde_json::Value) -> Result<Vec<u8>, CanonicalError> {
    canonicalize(value)
}

/// Lowercase hex SHA-256 digest of `bytes`, no prefix.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Spec digest form: `sha256:` followed by lowercase hex SHA-256 of `bytes`.
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// Canonicalize `value` then compute its spec digest form.
pub fn digest_canonical<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    Ok(digest(&canonicalize(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys() {
        let v = json!({"b": 1, "a": 2});
        let bytes = canonicalize(&v).unwrap();
        assert_eq!(bytes, br#"{"a":2,"b":1}"#);
    }

    #[test]
    fn strips_whitespace_no_trailing() {
        let v = json!({"a": [1, 2, 3], "b": "x"});
        let bytes = canonicalize(&v).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(!s.contains(' '));
        assert!(!s.ends_with(' '));
        assert_eq!(s, r#"{"a":[1,2,3],"b":"x"}"#);
    }

    #[test]
    fn nested_keys_sorted() {
        let v = json!({"z": {"y": 1, "x": 2}, "a": 1});
        let bytes = canonicalize(&v).unwrap();
        assert_eq!(bytes, br#"{"a":1,"z":{"x":2,"y":1}}"#);
    }

    #[test]
    fn round_trip_stability() {
        let v = json!({"b": [3, 1, {"y": true, "x": null}], "a": "hello"});
        let once = canonicalize(&v).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&once).unwrap();
        let twice = canonicalize(&parsed).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn digest_has_prefix_and_matches_independent_sha256() {
        let bytes = b"hello canary";
        let d = digest(bytes);
        assert!(d.starts_with("sha256:"));
        let expected = hex::encode(Sha256::digest(bytes));
        assert_eq!(d, format!("sha256:{expected}"));
    }

    #[test]
    fn sha256_of_empty_string_known_answer() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn known_answer_canonical_and_digest() {
        // Fixed tiny JSON; canonical form and digest locked against regression.
        let v = json!({"b": 1, "a": true, "c": [1, 2]});
        let bytes = canonicalize(&v).unwrap();
        assert_eq!(bytes, br#"{"a":true,"b":1,"c":[1,2]}"#);

        let d = digest(&bytes);
        assert_eq!(
            d,
            "sha256:90cd679e44e82f0f88461d70b7ed022b40c733c7610d3ecabe18341ce6fbf23a"
        );
        assert_eq!(d, digest_canonical(&v).unwrap());
    }
}
