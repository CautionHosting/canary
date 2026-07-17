//! `canaryctl` — outside-enclave CLI (spec §5.1, §15).
//!
//! Owns config creation/validation, explicit TOFU capture, master-seed
//! generation, and offline verification of signed statements. Never
//! touches NSM/Nitro directly (spec §7.2) — evidence and statement
//! verification both go through `canary-core`.

mod atomic_file;
mod capture;
mod config_cmd;
mod seed;
mod verify;

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};

use config_cmd::{load_or_create_config, upsert_target, validate_and_write, TrustedHashesFile};

#[derive(Parser)]
#[command(name = "canaryctl", about = "Caution Canary operator CLI (V0)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage `canary.json` (spec §6).
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// TOFU-capture live PCR0/1/2 from a target and enroll them (spec §4).
    Capture {
        /// Path to `canary.json`.
        #[arg(long)]
        config: PathBuf,
        /// Target ID to add or replace.
        #[arg(long)]
        id: String,
        /// Human-readable target name.
        #[arg(long)]
        name: String,
        /// Target's Bootproof `/attestation` URL.
        #[arg(long)]
        attestation_url: String,
        /// `node_id` to use if `canary.json` does not exist yet.
        #[arg(long)]
        node_id: Option<String>,
        /// Overwrite an existing target with this id.
        #[arg(long)]
        replace: bool,
        /// Skip the interactive TOFU confirmation prompt. Required for
        /// non-interactive use (spec §4).
        #[arg(long)]
        accept_tofu: bool,
    },
    /// Generate the one root `CANARY_MASTER_SEED` (spec §8.1).
    Seed {
        #[command(subcommand)]
        command: SeedCommand,
    },
    /// Verify a hybrid-signed statement against separately trusted keys (spec §9).
    VerifyStatement {
        /// Path to a local statement JSON file.
        #[arg(long)]
        statement: PathBuf,
        /// Path to a separately trusted `/keys.json` document.
        #[arg(long)]
        keys: PathBuf,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Add or replace a target using independently verified PCRs (spec §15 step 2a).
    Add {
        /// Path to `canary.json`.
        #[arg(long)]
        config: PathBuf,
        /// Target ID to add or replace.
        #[arg(long)]
        id: String,
        /// Human-readable target name.
        #[arg(long)]
        name: String,
        /// Target's Bootproof `/attestation` URL.
        #[arg(long)]
        attestation_url: String,
        /// Path to a `.caution/trusted_hashes.json`-shaped PCRs file.
        #[arg(long)]
        pcrs_file: PathBuf,
        /// `node_id` to use if `canary.json` does not exist yet.
        #[arg(long)]
        node_id: Option<String>,
        /// Overwrite an existing target with this id.
        #[arg(long)]
        replace: bool,
    },
}

#[derive(Subcommand)]
enum SeedCommand {
    /// Generate a random 32-byte master seed into an env file (spec §8.1).
    Generate {
        /// `.env`-style file to write `CANARY_MASTER_SEED=<base64>` into.
        #[arg(long)]
        env_file: PathBuf,
        /// Overwrite an existing `CANARY_MASTER_SEED` entry.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Config {
            command:
                ConfigCommand::Add {
                    config,
                    id,
                    name,
                    attestation_url,
                    pcrs_file,
                    node_id,
                    replace,
                },
        } => config_add(
            &config,
            &id,
            &name,
            &attestation_url,
            &pcrs_file,
            node_id.as_deref(),
            replace,
        ),

        Command::Capture {
            config,
            id,
            name,
            attestation_url,
            node_id,
            replace,
            accept_tofu,
        } => capture::run(
            &config,
            &id,
            &name,
            &attestation_url,
            node_id.as_deref(),
            replace,
            accept_tofu,
        ),

        Command::Seed {
            command: SeedCommand::Generate { env_file, force },
        } => seed::generate(&env_file, force),

        Command::VerifyStatement { statement, keys } => verify::run_offline(&statement, &keys),
    }
}

fn config_add(
    config_path: &Path,
    id: &str,
    name: &str,
    attestation_url: &str,
    pcrs_file: &Path,
    node_id: Option<&str>,
    replace: bool,
) -> Result<()> {
    let pcrs = TrustedHashesFile::load(pcrs_file)?.into_expected_pcrs();

    let target = canary_core::config::Target {
        id: id.to_string(),
        name: name.to_string(),
        attestation_url: attestation_url.to_string(),
        expected_pcrs: pcrs,
    };

    let mut config = load_or_create_config(config_path, node_id)?;
    upsert_target(&mut config, target, replace)?;
    let digest = validate_and_write(config_path, &config)?;

    println!("Wrote {}", config_path.display());
    println!("config_digest: {digest}");
    Ok(())
}
