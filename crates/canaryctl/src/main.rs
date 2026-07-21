//! `canaryctl` — outside-enclave CLI (spec §5.1, §15).
//!
//! Owns config creation/validation, explicit TOFU capture, master-seed
//! generation, and offline verification of signed statements. Never
//! touches NSM/Nitro directly (spec §7.2) — evidence and statement
//! verification both go through `canary-core`.

mod atomic_file;
mod attestation;
mod capture;
mod config_cmd;
mod inspect;
mod live_verify;
mod seed;
mod verify;
mod verify_evidence;

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};

use config_cmd::{load_or_create_config, upsert_target, validate_and_write, TrustedHashesFile};

#[derive(Parser)]
#[command(
    name = "canaryctl",
    version,
    about = "Caution Canary operator CLI (V0)"
)]
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
    /// Verify a V0 evidence bundle against separately trusted PCRs.
    VerifyEvidence {
        /// Path to a local V0 evidence bundle JSON file.
        #[arg(long)]
        evidence: PathBuf,
        /// Path to a separately trusted `.caution/trusted_hashes.json` file.
        #[arg(long)]
        pcrs_file: PathBuf,
    },
    /// Verify fresh Canary node metadata against config and public keys (spec §7.3).
    InspectNode {
        /// Canary origin. HTTPS is required unless --insecure is set.
        #[arg(long)]
        url: String,
        /// Independently verified Canary PCR0/1/2 file.
        #[arg(
            long,
            required_unless_present = "insecure",
            conflicts_with = "insecure"
        )]
        pcrs_file: Option<PathBuf>,
        /// Demo only: allow HTTP and self-pin PCRs from the live attestation.
        #[arg(
            long,
            required_unless_present = "pcrs_file",
            conflicts_with = "pcrs_file"
        )]
        insecure: bool,
        /// Output path for the exact canonical keys document after verification.
        #[arg(long)]
        keys_out: PathBuf,
    },
    /// Verify a live Canary node and all selected target claims end to end.
    Verify {
        /// Canary HTTPS origin, for example https://canary.example.com.
        #[arg(long)]
        url: String,
        /// Independently verified Canary PCR0/1/2 file.
        #[arg(long)]
        pcrs_file: PathBuf,
        /// Verify only this target ID. Repeat to select multiple targets; defaults to all.
        #[arg(long)]
        target: Vec<String>,
        /// Optionally save the exact attestation-bound Canary keys without overwriting.
        #[arg(long)]
        keys_out: Option<PathBuf>,
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

        Command::VerifyEvidence {
            evidence,
            pcrs_file,
        } => verify_evidence::run_offline(&evidence, &pcrs_file),

        Command::InspectNode {
            url,
            pcrs_file,
            insecure,
            keys_out,
        } => inspect::run(&url, pcrs_file.as_deref(), insecure, &keys_out),

        Command::Verify {
            url,
            pcrs_file,
            target,
            keys_out,
        } => live_verify::run(&url, &pcrs_file, &target, keys_out.as_deref()),
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
