//! `canary-core` — shared trust core for Caution Canary V0.
//!
//! Pure verifier/signer logic: config schema + validation, RFC 8785 canonical
//! JSON and digests, HKDF child-key derivation, hybrid Ed25519 + ML-DSA-65
//! statement signing/verification, and Bootproof evidence verification.
//!
//! This crate never touches NSM/`/dev/nsm`; Bootproof attestation for the Canary
//! enclave itself is produced by the Caution Bootproof service (spec §7.2).

pub mod canonical;
pub mod config;
pub mod evidence;
pub mod keys;
pub mod node;
pub mod state;
pub mod statement;
