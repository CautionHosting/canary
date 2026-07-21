//! `canaryctl` — outside-enclave CLI for configuring and verifying Canary.

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
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};

use config_cmd::{load_or_create_config, upsert_target, validate_and_write, TrustedHashesFile};

const DEFAULT_CONFIG: &str = "canary.json";
const DEFAULT_ENV_FILE: &str = ".env";
const DEFAULT_KEYS_FILE: &str = "canary-keys.json";

#[derive(Parser)]
#[command(
    name = "canaryctl",
    version,
    about = "Caution Canary operator CLI (V0)"
)]
struct Cli {
    /// Emit one machine-readable JSON result object.
    #[arg(long, global = true, conflicts_with = "verbose")]
    json: bool,
    /// Include verification-chain diagnostics and digests.
    #[arg(long, global = true, conflicts_with = "json")]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Add deployments and their expected PCR0/1/2 policy.
    Deployment {
        #[command(subcommand)]
        command: DeploymentCommand,
    },
    /// Create the stable Canary signer identity.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Verify Canary and save its exact signing keys for later verification.
    Enroll(EnrollArgs),
    /// Verify current deployments, or one retained historical attempt.
    Verify(VerifyArgs),
    /// Expert partial checks for standalone protocol artifacts.
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
}

#[derive(Subcommand)]
enum DeploymentCommand {
    /// Add or replace one deployment using trusted PCRs or explicit TOFU.
    Add(DeploymentAddArgs),
}

#[derive(Args)]
struct DeploymentAddArgs {
    /// Path to `canary.json`.
    #[arg(long, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    /// Deployment ID.
    #[arg(long)]
    id: String,
    /// Display name; defaults to the deployment ID.
    #[arg(long)]
    name: Option<String>,
    /// Deployment Bootproof `/attestation` URL.
    #[arg(long = "url")]
    url: String,
    /// Canary node ID, required only when creating a new config.
    #[arg(long)]
    canary_id: Option<String>,
    /// Path to independently trusted PCR0/1/2.
    #[arg(long, conflicts_with = "tofu", required_unless_present = "tofu")]
    pcrs: Option<PathBuf>,
    /// Trust the first live PCR0/1/2 values after explicit confirmation.
    #[arg(long, conflicts_with = "pcrs", required_unless_present = "pcrs")]
    tofu: bool,
    /// Replace an existing deployment with the same ID.
    #[arg(long)]
    replace: bool,
    /// Skip the interactive TOFU confirmation.
    #[arg(long, requires = "tofu")]
    accept_tofu: bool,
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Generate a random master seed for a stable signer identity.
    Create {
        /// `.env`-style file to write the seed into.
        #[arg(long, default_value = DEFAULT_ENV_FILE)]
        env_file: PathBuf,
        /// Replace an existing seed entry.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args)]
struct EnrollArgs {
    /// Canary origin. HTTPS is required unless --insecure is set.
    #[arg(long)]
    url: String,
    /// Independently verified Canary PCR0/1/2 file.
    #[arg(
        long,
        conflicts_with = "insecure",
        required_unless_present = "insecure"
    )]
    pcrs: Option<PathBuf>,
    /// Demo only: allow HTTP and skip Canary attestation.
    #[arg(long, conflicts_with = "pcrs", required_unless_present = "pcrs")]
    insecure: bool,
    /// Destination for the exact enrolled public keys. Refuses overwrite.
    #[arg(long, default_value = DEFAULT_KEYS_FILE)]
    keys: PathBuf,
}

#[derive(Args)]
struct VerifyArgs {
    /// Canary origin. HTTPS is required unless --insecure is set.
    #[arg(long)]
    url: String,
    /// Independently verified Canary PCR0/1/2 file.
    #[arg(
        long,
        conflicts_with = "insecure",
        required_unless_present = "insecure"
    )]
    pcrs: Option<PathBuf>,
    /// Demo only: allow HTTP and skip Canary attestation.
    #[arg(long, conflicts_with = "pcrs", required_unless_present = "pcrs")]
    insecure: bool,
    /// Exact key pin created by `canaryctl enroll`.
    #[arg(long, default_value = DEFAULT_KEYS_FILE)]
    keys: PathBuf,
    /// Verify only this deployment. Repeat to select several current deployments.
    #[arg(long = "deployment")]
    deployments: Vec<String>,
    /// Re-verify one retained attempt; requires exactly one --deployment.
    #[arg(long)]
    attempt: Option<i64>,
}

#[derive(Subcommand)]
enum ArtifactCommand {
    /// Verify a signed statement against separately trusted keys.
    VerifyStatement {
        #[arg(long)]
        statement: PathBuf,
        #[arg(long, default_value = DEFAULT_KEYS_FILE)]
        keys: PathBuf,
    },
    /// Verify an evidence bundle against separately trusted PCRs.
    VerifyEvidence {
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        pcrs: PathBuf,
    },
}

struct Outcome {
    command: &'static str,
    ok: bool,
    result: Value,
    concise: String,
    verbose: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let command = command_name(&cli.command);
    let outcome = execute(cli.command, cli.json, cli.verbose);
    match outcome {
        Ok(outcome) => render(outcome, cli.json, cli.verbose),
        Err(error) => render_error(error, cli.json, command),
    }
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Deployment { .. } => "deployment.add",
        Command::Identity { .. } => "identity.create",
        Command::Enroll(_) => "enroll",
        Command::Verify(_) => "verify",
        Command::Artifact {
            command: ArtifactCommand::VerifyStatement { .. },
        } => "artifact.verify-statement",
        Command::Artifact {
            command: ArtifactCommand::VerifyEvidence { .. },
        } => "artifact.verify-evidence",
    }
}

fn execute(command: Command, json_mode: bool, _verbose: bool) -> Result<Outcome> {
    match command {
        Command::Deployment {
            command: DeploymentCommand::Add(args),
        } => {
            if json_mode && args.tofu && !args.accept_tofu {
                bail!("--json with --tofu requires --accept-tofu to avoid an interactive prompt")
            }
            let name = args.name.as_deref().unwrap_or(&args.id);
            let (digest, mode, captured_pcrs) = match (args.pcrs.as_deref(), args.tofu) {
                (Some(pcrs), false) => (
                    config_add(
                        &args.config,
                        &args.id,
                        name,
                        &args.url,
                        pcrs,
                        args.canary_id.as_deref(),
                        args.replace,
                    )?,
                    "trusted_pcrs",
                    Value::Null,
                ),
                (None, true) => {
                    let capture = capture::run(
                        &args.config,
                        &args.id,
                        name,
                        &args.url,
                        args.canary_id.as_deref(),
                        args.replace,
                        args.accept_tofu,
                    )?;
                    (
                        capture.config_digest,
                        "tofu",
                        json!({"pcr0": capture.pcr0, "pcr1": capture.pcr1, "pcr2": capture.pcr2}),
                    )
                }
                _ => bail!("pass exactly one of --pcrs or --tofu"),
            };
            let verbose = if mode == "tofu" {
                format!(
                    "ADDED deployment {}\n  config: {}\n  mode: TOFU\n  PCR0: {}\n  PCR1: {}\n  PCR2: {}\n  config_digest: {}\n  WARNING: TOFU does not prove reviewed or reproduced source.",
                    args.id,
                    args.config.display(),
                    captured_pcrs["pcr0"].as_str().expect("TOFU capture has PCR0"),
                    captured_pcrs["pcr1"].as_str().expect("TOFU capture has PCR1"),
                    captured_pcrs["pcr2"].as_str().expect("TOFU capture has PCR2"),
                    digest,
                )
            } else {
                format!(
                    "ADDED deployment {}\n  config: {}\n  mode: trusted PCRs\n  config_digest: {}",
                    args.id,
                    args.config.display(),
                    digest,
                )
            };
            Ok(Outcome {
                command: "deployment.add",
                ok: true,
                result: json!({"deployment": args.id, "config": args.config, "mode": mode, "config_digest": digest, "captured_pcrs": captured_pcrs}),
                concise: format!(
                    "ADDED {} -> {} ({}){}",
                    args.id,
                    args.config.display(),
                    if mode == "tofu" {
                        "TOFU"
                    } else {
                        "trusted PCRs"
                    },
                    if mode == "tofu" {
                        "\nWARNING: TOFU does not prove reviewed or reproduced source."
                    } else {
                        ""
                    }
                ),
                verbose: Some(verbose),
            })
        }
        Command::Identity {
            command: IdentityCommand::Create { env_file, force },
        } => {
            seed::generate(&env_file, force)?;
            Ok(Outcome {
                command: "identity.create",
                ok: true,
                result: json!({"env_file": env_file}),
                concise: format!("CREATED {}\nWARNING: never commit this seed file.", env_file.display()),
                verbose: Some(format!("CREATED {}\n  stores CANARY_MASTER_SEED\n  protect it with Locksmith before deployment", env_file.display())),
            })
        }
        Command::Enroll(args) => {
            let enrolled =
                inspect::enroll(&args.url, args.pcrs.as_deref(), args.insecure, &args.keys)?;
            let trust = enrolled.trust_name();
            let identity = enrolled.identity_name();
            let warning = match (trust, identity) {
                ("TOFU", _) => {
                    "\nWARNING: Canary identity and config are not independently authenticated."
                }
                (_, "ephemeral") => "\nWARNING: re-enroll after this Canary restarts.",
                _ => "",
            };
            Ok(Outcome {
                command: "enroll",
                ok: true,
                result: json!({"trust": trust, "identity": identity, "keys": args.keys, "node_id": enrolled.node_id, "config_digest": enrolled.config_digest, "keyset_digest": enrolled.keyset_digest}),
                concise: format!(
                    "ENROLLED {} -> {}\nCanary: {}{}",
                    enrolled.node_id,
                    args.keys.display(),
                    trust,
                    warning,
                ),
                verbose: Some(enrolled.verbose_text(&args.keys)),
            })
        }
        Command::Verify(args) => {
            let outcome = match args.attempt {
                Some(attempt) => {
                    if args.deployments.len() != 1 {
                        bail!("--attempt requires exactly one --deployment")
                    }
                    live_verify::run_history(
                        &args.url,
                        args.pcrs.as_deref(),
                        args.insecure,
                        &args.keys,
                        &args.deployments[0],
                        attempt,
                    )?
                }
                None => live_verify::run(
                    &args.url,
                    args.pcrs.as_deref(),
                    args.insecure,
                    &args.keys,
                    &args.deployments,
                )?,
            };
            Ok(Outcome {
                command: "verify",
                ok: outcome.ok,
                result: outcome.json_result(),
                concise: outcome.concise_text(),
                verbose: Some(outcome.verbose_text()),
            })
        }
        Command::Artifact {
            command: ArtifactCommand::VerifyStatement { statement, keys },
        } => {
            let outcome = verify::run_offline(&statement, &keys)?;
            Ok(Outcome {
                command: "artifact.verify-statement",
                ok: true,
                result: outcome.json_result(),
                concise: outcome.concise_text(),
                verbose: None,
            })
        }
        Command::Artifact {
            command: ArtifactCommand::VerifyEvidence { evidence, pcrs },
        } => {
            let outcome = verify_evidence::run_offline(&evidence, &pcrs)?;
            Ok(Outcome {
                command: "artifact.verify-evidence",
                ok: true,
                result: outcome.json_result(),
                concise: outcome.concise_text(),
                verbose: None,
            })
        }
    }
}

fn render(outcome: Outcome, json_mode: bool, verbose: bool) -> ExitCode {
    if json_mode {
        println!(
            "{}",
            json!({"schema_version": 1, "command": outcome.command, "ok": outcome.ok, "result": outcome.result, "error": Value::Null})
        );
    } else if verbose {
        println!("{}", outcome.verbose.as_deref().unwrap_or(&outcome.concise));
    } else {
        println!("{}", outcome.concise);
    }
    if outcome.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn render_error(error: anyhow::Error, json_mode: bool, command: &'static str) -> ExitCode {
    if json_mode {
        println!(
            "{}",
            json!({"schema_version": 1, "command": command, "ok": false, "result": Value::Null, "error": format!("{error:#}")})
        );
    } else {
        eprintln!("ERROR: {error:#}");
    }
    ExitCode::FAILURE
}

fn config_add(
    config_path: &Path,
    id: &str,
    name: &str,
    attestation_url: &str,
    pcrs_file: &Path,
    node_id: Option<&str>,
    replace: bool,
) -> Result<String> {
    let pcrs = TrustedHashesFile::load(pcrs_file)?.into_expected_pcrs();
    let target = canary_core::config::Target {
        id: id.to_string(),
        name: name.to_string(),
        attestation_url: attestation_url.to_string(),
        expected_pcrs: pcrs,
    };
    let mut config = load_or_create_config(config_path, node_id)?;
    upsert_target(&mut config, target, replace)?;
    validate_and_write(config_path, &config)
}
