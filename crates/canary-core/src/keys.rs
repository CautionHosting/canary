//! Master-seed parsing, HKDF-SHA-256 child-key derivation, and hybrid
//! Ed25519 + ML-DSA-65 keygen/sign/verify (spec §8.1, §8.2, §8.3).
//!
//! Locksmith injects a single 32-byte, base64-encoded `CANARY_MASTER_SEED`.
//! From that one root secret we deterministically derive one Ed25519 keypair
//! and one ML-DSA-65 keypair per `node_id`, using domain-separated,
//! versioned HKDF-SHA-256 info strings (spec §8.2). The resulting `/keys.json`
//! document (spec §8.3) publishes both public keys as base64url (no padding).

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{
    Signature as EdSignature, Signer as _, SigningKey, Verifier as _, VerifyingKey,
};
use fips204::ml_dsa_65::{self, PK_LEN as ML_PK_LEN, SIG_LEN as ML_SIG_LEN};
use fips204::traits::{KeyGen, SerDes, Signer as _, Verifier as _};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::config::is_valid_identifier;

/// HKDF-Extract salt, fixed and versioned per spec §8.2.
const HKDF_SALT: &[u8] = b"caution-canary-v0/root";

/// `key_epoch` is pinned at 0 for V0; rotation is post-V0 (spec §8.2).
pub const KEY_EPOCH: u32 = 0;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid base64 master seed: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    #[error("master seed must decode to exactly 32 bytes, got {0}")]
    InvalidSeedLength(usize),

    #[error("invalid node identifier {0:?}")]
    InvalidNodeId(String),

    #[error("hkdf expand failed: {0:?}")]
    Hkdf(hkdf::InvalidLength),

    #[error("ed25519 error: {0}")]
    Ed25519(#[from] ed25519_dalek::SignatureError),

    #[error("ml-dsa-65 error: {0}")]
    MlDsa(String),

    #[error("invalid {alg} public key length: expected {expected} bytes, got {actual}")]
    InvalidPublicKeyLength {
        alg: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("invalid {alg} signature length: expected {expected} bytes, got {actual}")]
    InvalidSignatureLength {
        alg: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("ml-dsa-65 signature verification failed")]
    MlDsaVerificationFailed,
}

/// A 32-byte master seed, decoded from base64 (spec §8.1). Zeroized on drop.
pub struct MasterSeed([u8; 32]);

impl MasterSeed {
    /// Decode a base64-encoded 32-byte master seed. Accepts standard base64
    /// (with or without padding); the decoded length MUST be exactly 32 bytes.
    pub fn from_base64(s: &str) -> Result<Self, KeyError> {
        let mut bytes = STANDARD.decode(s).or_else(|_| STANDARD_NO_PAD.decode(s))?;
        let len = bytes.len();
        if len != 32 {
            bytes.zeroize();
            return Err(KeyError::InvalidSeedLength(len));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self(arr))
    }
}

impl Drop for MasterSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// One derived hybrid keypair (Ed25519 + ML-DSA-65) for a given `node_id` at
/// `key_epoch = 0`, plus the signing methods over it.
pub struct KeySet {
    node_id: String,
    ed_signing_key: SigningKey,
    ml_private_key: ml_dsa_65::PrivateKey,
    ml_public_key: ml_dsa_65::PublicKey,
}

impl KeySet {
    /// Derive the hybrid keypair for `node_id` from `seed`, per spec §8.2:
    ///
    /// ```text
    /// PRK = HKDF-Extract(salt = "caution-canary-v0/root", IKM = master_seed)
    /// ed_seed = HKDF-Expand(PRK, "signing/ed25519/<node_id>/key-epoch-0", 32)
    /// ml_seed = HKDF-Expand(PRK, "signing/ml-dsa-65/<node_id>/key-epoch-0", 32)
    /// ```
    pub fn derive(seed: &MasterSeed, node_id: &str) -> Result<Self, KeyError> {
        if !is_valid_identifier(node_id) {
            return Err(KeyError::InvalidNodeId(node_id.to_string()));
        }
        let (prk, hk) = Hkdf::<Sha256>::extract(Some(HKDF_SALT), &seed.0);
        let mut prk_bytes: [u8; 32] = prk.into();

        let ed_info = format!("signing/ed25519/{node_id}/key-epoch-{KEY_EPOCH}");
        let ml_info = format!("signing/ml-dsa-65/{node_id}/key-epoch-{KEY_EPOCH}");

        let mut ed_seed = [0u8; 32];
        let mut ml_seed = [0u8; 32];
        hk.expand(ed_info.as_bytes(), &mut ed_seed)
            .map_err(KeyError::Hkdf)?;
        hk.expand(ml_info.as_bytes(), &mut ml_seed)
            .map_err(KeyError::Hkdf)?;
        prk_bytes.zeroize();

        let ed_signing_key = SigningKey::from_bytes(&ed_seed);
        let (ml_public_key, ml_private_key) = ml_dsa_65::KG::keygen_from_seed(&ml_seed);

        ed_seed.zeroize();
        ml_seed.zeroize();

        Ok(Self {
            node_id: node_id.to_string(),
            ed_signing_key,
            ml_private_key,
            ml_public_key,
        })
    }

    /// Sign `msg` with the derived Ed25519 key.
    pub fn sign_ed25519(&self, msg: &[u8]) -> [u8; 64] {
        self.ed_signing_key.sign(msg).to_bytes()
    }

    /// Sign `msg` with the derived ML-DSA-65 key (empty context).
    ///
    /// NOTE: uses `fips204`'s hedged (OS-RNG-randomized) `try_sign`, not
    /// deterministic signing. This is acceptable because verification is
    /// deterministic regardless of how the signature was produced.
    pub fn sign_ml_dsa(&self, msg: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.ml_private_key
            .try_sign(msg, &[])
            .map(|signature| signature.to_vec())
            .map_err(|err| KeyError::MlDsa(err.to_string()))
    }

    /// Deterministic ML-DSA signing for published known-answer vectors only.
    /// Production signing always uses the hedged OS-RNG path above.
    #[cfg(test)]
    pub(crate) fn sign_ml_dsa_with_randomizer(
        &self,
        msg: &[u8],
        randomizer: &[u8; 32],
    ) -> Result<Vec<u8>, KeyError> {
        self.ml_private_key
            .try_sign_with_seed(randomizer, msg, &[])
            .map(|signature| signature.to_vec())
            .map_err(|err| KeyError::MlDsa(err.to_string()))
    }

    pub fn ed25519_public_key_bytes(&self) -> [u8; 32] {
        self.ed_signing_key.verifying_key().to_bytes()
    }

    pub fn ml_dsa_public_key_bytes(&self) -> Vec<u8> {
        self.ml_public_key.clone().into_bytes().to_vec()
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Build the `/keys.json` document (spec §8.3) for this keyset.
    pub fn keys_document(&self) -> KeysDocument {
        KeysDocument {
            protocol: "caution-canary-v0".to_string(),
            node_id: self.node_id.clone(),
            key_epoch: KEY_EPOCH,
            keys: vec![
                KeyEntry {
                    alg: "Ed25519".to_string(),
                    encoding: "base64url".to_string(),
                    public_key: base64url_nopad(&self.ed25519_public_key_bytes()),
                },
                KeyEntry {
                    alg: "ML-DSA-65".to_string(),
                    encoding: "base64url".to_string(),
                    public_key: base64url_nopad(&self.ml_dsa_public_key_bytes()),
                },
            ],
        }
    }
}

/// base64url (no padding) encoding, per spec §8.3.
pub fn base64url_nopad(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Verify an Ed25519 signature given only raw public-key bytes (offline verifier).
pub fn verify_ed25519(pk_bytes: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), KeyError> {
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| KeyError::InvalidPublicKeyLength {
            alg: "Ed25519",
            expected: 32,
            actual: pk_bytes.len(),
        })?;
    let sig_arr: [u8; 64] = sig
        .try_into()
        .map_err(|_| KeyError::InvalidSignatureLength {
            alg: "Ed25519",
            expected: 64,
            actual: sig.len(),
        })?;
    let verifying_key = VerifyingKey::from_bytes(&pk_arr)?;
    let signature = EdSignature::from_bytes(&sig_arr);
    verifying_key.verify(msg, &signature)?;
    Ok(())
}

/// Verify an ML-DSA-65 signature given only raw public-key bytes (offline verifier).
pub fn verify_ml_dsa(pk_bytes: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), KeyError> {
    let pk_arr: [u8; ML_PK_LEN] =
        pk_bytes
            .to_vec()
            .try_into()
            .map_err(|_| KeyError::InvalidPublicKeyLength {
                alg: "ML-DSA-65",
                expected: ML_PK_LEN,
                actual: pk_bytes.len(),
            })?;
    let sig_arr: [u8; ML_SIG_LEN] =
        sig.to_vec()
            .try_into()
            .map_err(|_| KeyError::InvalidSignatureLength {
                alg: "ML-DSA-65",
                expected: ML_SIG_LEN,
                actual: sig.len(),
            })?;
    let public_key =
        ml_dsa_65::PublicKey::try_from_bytes(pk_arr).map_err(|e| KeyError::MlDsa(e.to_string()))?;
    if public_key.verify(msg, &sig_arr, &[]) {
        Ok(())
    } else {
        Err(KeyError::MlDsaVerificationFailed)
    }
}

/// A single entry in the `/keys.json` `keys` array (spec §8.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    pub alg: String,
    pub encoding: String,
    pub public_key: String,
}

/// The `/keys.json` document (spec §8.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeysDocument {
    pub protocol: String,
    pub node_id: String,
    pub key_epoch: u32,
    pub keys: Vec<KeyEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    /// A fixed 32-byte seed (all 0x42) for deterministic known-answer tests.
    fn fixed_seed_b64() -> String {
        STANDARD.encode([0x42u8; 32])
    }

    #[test]
    fn derive_is_deterministic() {
        let seed = MasterSeed::from_base64(&fixed_seed_b64()).unwrap();
        let ks1 = KeySet::derive(&seed, "node-a").unwrap();
        let ks2 = KeySet::derive(&seed, "node-a").unwrap();
        assert_eq!(
            ks1.ed25519_public_key_bytes(),
            ks2.ed25519_public_key_bytes()
        );
        assert_eq!(ks1.ml_dsa_public_key_bytes(), ks2.ml_dsa_public_key_bytes());
    }

    #[test]
    fn different_node_id_yields_different_keys() {
        let seed = MasterSeed::from_base64(&fixed_seed_b64()).unwrap();
        let ks_a = KeySet::derive(&seed, "node-a").unwrap();
        let ks_b = KeySet::derive(&seed, "node-b").unwrap();
        assert_ne!(
            ks_a.ed25519_public_key_bytes(),
            ks_b.ed25519_public_key_bytes()
        );
        assert_ne!(
            ks_a.ml_dsa_public_key_bytes(),
            ks_b.ml_dsa_public_key_bytes()
        );
    }

    /// Known-answer test locking the derivation construction (spec §8.2)
    /// against regression. Vectors generated from THIS implementation using
    /// seed = 32 bytes of 0x42 (base64) and node_id = "caution-canary-demo".
    /// The ML-DSA-65 public key is ~2KB, so we pin its SHA-256 digest instead
    /// of the raw bytes.
    #[test]
    fn known_answer_vectors() {
        let seed = MasterSeed::from_base64(&fixed_seed_b64()).unwrap();
        let ks = KeySet::derive(&seed, "caution-canary-demo").unwrap();

        let ed_pk_b64url = base64url_nopad(&ks.ed25519_public_key_bytes());
        assert_eq!(ed_pk_b64url, "JqM4MS1_-36uIXsvgROUb2CFYlOQXnOgIvpnMW2bDBY");

        let ml_pk_bytes = ks.ml_dsa_public_key_bytes();
        assert_eq!(ml_pk_bytes.len(), ML_PK_LEN);
        let digest = hex::encode(Sha256::digest(&ml_pk_bytes));
        assert_eq!(
            digest,
            "f286ccc0b22313ab1fcbf8115f0282d575b94b58d7b6577175580873b08bec3d"
        );
    }

    #[test]
    fn sign_verify_round_trip() {
        let seed = MasterSeed::from_base64(&fixed_seed_b64()).unwrap();
        let ks = KeySet::derive(&seed, "node-a").unwrap();
        let msg = b"caution canary v0 statement bytes";

        let ed_sig = ks.sign_ed25519(msg);
        let ed_pk = ks.ed25519_public_key_bytes();
        verify_ed25519(&ed_pk, msg, &ed_sig).expect("ed25519 verify should succeed");

        let ml_sig = ks.sign_ml_dsa(msg).unwrap();
        let ml_pk = ks.ml_dsa_public_key_bytes();
        verify_ml_dsa(&ml_pk, msg, &ml_sig).expect("ml-dsa verify should succeed");
    }

    #[test]
    fn sign_verify_rejects_tampered_message() {
        let seed = MasterSeed::from_base64(&fixed_seed_b64()).unwrap();
        let ks = KeySet::derive(&seed, "node-a").unwrap();
        let msg = b"original message".to_vec();
        let mut tampered = msg.clone();
        tampered[0] ^= 0xff;

        let ed_sig = ks.sign_ed25519(&msg);
        let ed_pk = ks.ed25519_public_key_bytes();
        assert!(verify_ed25519(&ed_pk, &tampered, &ed_sig).is_err());

        let ml_sig = ks.sign_ml_dsa(&msg).unwrap();
        let ml_pk = ks.ml_dsa_public_key_bytes();
        assert!(verify_ml_dsa(&ml_pk, &tampered, &ml_sig).is_err());
    }

    #[test]
    fn sign_verify_rejects_wrong_public_key() {
        let seed = MasterSeed::from_base64(&fixed_seed_b64()).unwrap();
        let ks_a = KeySet::derive(&seed, "node-a").unwrap();
        let ks_b = KeySet::derive(&seed, "node-b").unwrap();
        let msg = b"some statement bytes";

        let ed_sig = ks_a.sign_ed25519(msg);
        assert!(verify_ed25519(&ks_b.ed25519_public_key_bytes(), msg, &ed_sig).is_err());

        let ml_sig = ks_a.sign_ml_dsa(msg).unwrap();
        assert!(verify_ml_dsa(&ks_b.ml_dsa_public_key_bytes(), msg, &ml_sig).is_err());
    }

    #[test]
    fn bad_seed_length_errors() {
        let too_short = STANDARD.encode([0x01u8; 16]);
        assert!(matches!(
            MasterSeed::from_base64(&too_short),
            Err(KeyError::InvalidSeedLength(16))
        ));

        let too_long = STANDARD.encode([0x01u8; 33]);
        assert!(matches!(
            MasterSeed::from_base64(&too_long),
            Err(KeyError::InvalidSeedLength(33))
        ));

        assert!(MasterSeed::from_base64("not-valid-base64!!!").is_err());
    }

    #[test]
    fn keys_document_shape_and_encoding() {
        let seed = MasterSeed::from_base64(&fixed_seed_b64()).unwrap();
        let ks = KeySet::derive(&seed, "caution-canary-demo").unwrap();
        let doc = ks.keys_document();

        assert_eq!(doc.protocol, "caution-canary-v0");
        assert_eq!(doc.node_id, "caution-canary-demo");
        assert_eq!(doc.key_epoch, 0);
        assert_eq!(doc.keys.len(), 2);
        assert_eq!(doc.keys[0].alg, "Ed25519");
        assert_eq!(doc.keys[0].encoding, "base64url");
        assert_eq!(doc.keys[1].alg, "ML-DSA-65");
        assert_eq!(doc.keys[1].encoding, "base64url");
        for entry in &doc.keys {
            assert!(!entry.public_key.contains('='), "must omit padding");
        }

        let json = serde_json::to_value(&doc).unwrap();
        assert_eq!(json["protocol"], "caution-canary-v0");
        assert_eq!(json["node_id"], "caution-canary-demo");
        assert_eq!(json["key_epoch"], 0);
        assert_eq!(json["keys"][0]["alg"], "Ed25519");
        assert_eq!(json["keys"][1]["alg"], "ML-DSA-65");
    }

    #[test]
    fn invalid_node_id_is_rejected_before_derivation() {
        let seed = MasterSeed::from_base64(&fixed_seed_b64()).unwrap();
        assert!(matches!(
            KeySet::derive(&seed, "not a valid id"),
            Err(KeyError::InvalidNodeId(_))
        ));
    }
}
