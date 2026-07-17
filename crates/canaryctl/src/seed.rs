//! `canaryctl seed generate` (spec §8.1, §15 step 3).
//!
//! Generates the single random 32-byte `CANARY_MASTER_SEED` root secret from
//! the OS CSPRNG and writes it to a local `.env`-style file for later
//! Locksmith encryption. This is the only place `canaryctl` creates secret
//! material.

use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;

const ENV_VAR: &str = "CANARY_MASTER_SEED";

/// Generate a fresh 32-byte master seed and write `CANARY_MASTER_SEED=<b64>`
/// into `env_file`. Refuses to clobber an existing entry unless `force` is
/// set.
pub fn generate(env_file: &Path, force: bool) -> Result<()> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let encoded = STANDARD.encode(seed);

    let existing = if env_file.exists() {
        std::fs::read_to_string(env_file)
            .with_context(|| format!("reading env file {}", env_file.display()))?
    } else {
        String::new()
    };

    let prefix = format!("{ENV_VAR}=");
    let already_has_var = existing.lines().any(|line| line.starts_with(&prefix));
    if already_has_var && !force {
        bail!(
            "{} already contains {ENV_VAR}; pass --force to overwrite it",
            env_file.display()
        );
    }

    let new_line = format!("{prefix}{encoded}");
    let updated = if already_has_var {
        existing
            .lines()
            .map(|line| {
                if line.starts_with(&prefix) {
                    new_line.as_str()
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    } else if existing.is_empty() {
        new_line + "\n"
    } else if existing.ends_with('\n') {
        existing + &new_line + "\n"
    } else {
        existing + "\n" + &new_line + "\n"
    };

    std::fs::write(env_file, updated)
        .with_context(|| format!("writing env file {}", env_file.display()))?;

    eprintln!(
        "Generated a new {ENV_VAR} and wrote it to {}.",
        env_file.display()
    );
    eprintln!(
        "WARNING: never commit this file. This seed is the single root of the \
         Canary signer identity (spec §8.1) — anyone who has it can derive \
         both the Ed25519 and ML-DSA-65 signing keys for this node. Encrypt it \
         with Locksmith before deployment and keep it out of version control."
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A fresh, non-existent path under the OS temp dir for one test.
    fn temp_env_path(name: &str) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("canaryctl-seed-test-{name}-{n}.env"))
    }

    #[test]
    fn writes_new_file() {
        let path = temp_env_path("new");
        generate(&path, false).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("CANARY_MASTER_SEED="));
        let value = contents.trim().strip_prefix("CANARY_MASTER_SEED=").unwrap();
        let decoded = STANDARD.decode(value).unwrap();
        assert_eq!(decoded.len(), 32);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn refuses_to_overwrite_without_force() {
        let path = temp_env_path("noforce");
        generate(&path, false).unwrap();
        let err = generate(&path, false).unwrap_err();
        assert!(err.to_string().contains("--force"));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn force_overwrites_and_rotates_value() {
        let path = temp_env_path("force");
        generate(&path, false).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        generate(&path, true).unwrap();
        let second = std::fs::read_to_string(&path).unwrap();
        assert_ne!(first, second);
        assert_eq!(second.lines().count(), 1);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn preserves_other_lines() {
        let path = temp_env_path("preserve");
        std::fs::write(&path, "OTHER_VAR=hello\n").unwrap();
        generate(&path, false).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("OTHER_VAR=hello"));
        assert!(contents.contains("CANARY_MASTER_SEED="));
        std::fs::remove_file(&path).unwrap();
    }
}
