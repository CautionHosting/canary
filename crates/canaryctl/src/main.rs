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
mod watch;
mod watch_config;

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
    /// Emit one machine-readable JSON result object for a one-shot command.
    #[arg(long, global = true, conflicts_with = "verbose")]
    json: bool,
    /// Include verification-chain diagnostics for a one-shot command.
    #[arg(long, global = true, conflicts_with = "json")]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Add or replace a monitored target and its expected PCR0/1/2 policy.
    AddTarget(TargetArgs),
    /// Generate the master seed for a stable Canary signing identity.
    CreateSigningSeed(CreateSigningSeedArgs),
    /// Verify Canary and save its authenticated signing keys.
    SaveCanaryKeys(SaveCanaryKeysArgs),
    /// Verify Canary and its current target results.
    Verify(VerifyArgs),
    /// Verify one retained target attempt.
    VerifyAttempt(VerifyAttemptArgs),
    /// Continuously verify Canary and deliver signed per-target webhooks.
    Watch(WatchArgs),
    /// Partially verify a standalone signed statement.
    VerifyStatement(VerifyStatementArgs),
    /// Partially verify a standalone evidence bundle.
    VerifyEvidence(VerifyEvidenceArgs),
    #[command(hide = true)]
    Deployment {
        #[command(subcommand)]
        command: LegacyDeploymentCommand,
    },
    #[command(hide = true)]
    Identity {
        #[command(subcommand)]
        command: LegacyIdentityCommand,
    },
    #[command(hide = true)]
    Enroll(SaveCanaryKeysArgs),
    #[command(hide = true)]
    Artifact {
        #[command(subcommand)]
        command: LegacyArtifactCommand,
    },
}

#[derive(Subcommand)]
enum LegacyDeploymentCommand {
    Add(TargetArgs),
}

#[derive(Args)]
struct TargetArgs {
    /// Path to `canary.json`.
    #[arg(long, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    /// Target ID.
    #[arg(long)]
    id: String,
    /// Display name; defaults to the target ID.
    #[arg(long)]
    name: Option<String>,
    /// Target Bootproof `/attestation` URL.
    #[arg(long, alias = "url")]
    attestation_url: String,
    /// Require enclave-terminated Caddy TLS to match signed attestation metadata.
    #[arg(long, value_parser = ["caddy"], conflicts_with = "tofu")]
    e2e_mode: Option<String>,
    /// Canary node ID, required only when creating a new config.
    #[arg(long)]
    canary_id: Option<String>,
    /// Path to independently trusted target PCR0/1/2.
    #[arg(
        long,
        alias = "pcrs",
        conflicts_with = "tofu",
        required_unless_present = "tofu"
    )]
    expected_pcrs: Option<PathBuf>,
    /// Trust the first live PCR0/1/2 values after explicit confirmation.
    #[arg(
        long,
        conflicts_with = "expected_pcrs",
        required_unless_present = "expected_pcrs"
    )]
    tofu: bool,
    /// Replace an existing target with the same ID.
    #[arg(long)]
    replace: bool,
    /// Skip the interactive TOFU confirmation.
    #[arg(long, requires = "tofu")]
    accept_tofu: bool,
}

#[derive(Subcommand)]
enum LegacyIdentityCommand {
    Create(CreateSigningSeedArgs),
}

#[derive(Args)]
struct CreateSigningSeedArgs {
    /// `.env`-style file to write the seed into.
    #[arg(long, alias = "env-file", default_value = DEFAULT_ENV_FILE)]
    output: PathBuf,
    /// Replace an existing seed entry.
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct CanaryTrustArgs {
    /// Canary origin.
    #[arg(long, alias = "url")]
    canary_url: String,
    /// Independently verified Canary PCR0/1/2 file.
    #[arg(long, alias = "pcrs")]
    expected_pcrs: Option<PathBuf>,
    /// Local TOFU only: skip Canary's own attestation.
    #[arg(long)]
    skip_canary_attestation: bool,
    /// Local only: permit an HTTP Canary origin. Requires --skip-canary-attestation.
    #[arg(long)]
    allow_http: bool,
    #[arg(long, hide = true)]
    insecure: bool,
}

impl CanaryTrustArgs {
    fn resolved(&self) -> Result<ResolvedCanaryTrust<'_>> {
        let skip_canary_attestation = self.skip_canary_attestation || self.insecure;
        let allow_http = self.allow_http || self.insecure;
        if allow_http && !skip_canary_attestation {
            bail!("--allow-http requires --skip-canary-attestation")
        }
        match (self.expected_pcrs.as_deref(), skip_canary_attestation) {
            (Some(expected_pcrs), false) => Ok(ResolvedCanaryTrust {
                canary_url: &self.canary_url,
                expected_pcrs: Some(expected_pcrs),
                skip_canary_attestation,
                allow_http,
            }),
            (None, true) => Ok(ResolvedCanaryTrust {
                canary_url: &self.canary_url,
                expected_pcrs: None,
                skip_canary_attestation,
                allow_http,
            }),
            (Some(_), true) | (None, false) => {
                bail!("pass exactly one of --expected-pcrs or --skip-canary-attestation")
            }
        }
    }
}

struct ResolvedCanaryTrust<'a> {
    canary_url: &'a str,
    expected_pcrs: Option<&'a Path>,
    skip_canary_attestation: bool,
    allow_http: bool,
}

#[derive(Args)]
struct SaveCanaryKeysArgs {
    #[command(flatten)]
    trust: CanaryTrustArgs,
    /// Destination for the authenticated public keys. Refuses overwrite.
    #[arg(long, alias = "keys", default_value = DEFAULT_KEYS_FILE)]
    output: PathBuf,
}

#[derive(Args)]
struct VerificationInputs {
    #[command(flatten)]
    trust: CanaryTrustArgs,
    /// Exact Canary key pin created by `canaryctl save-canary-keys`.
    #[arg(long, alias = "keys", default_value = DEFAULT_KEYS_FILE)]
    trusted_keys: PathBuf,
}

#[derive(Args)]
struct VerifyArgs {
    #[command(flatten)]
    inputs: VerificationInputs,
    /// Verify only this target. Repeat to select several current targets.
    #[arg(long = "target", alias = "deployment", value_name = "TARGET")]
    targets: Vec<String>,
    #[arg(long, hide = true)]
    attempt: Option<i64>,
}

#[derive(Args)]
struct VerifyAttemptArgs {
    #[command(flatten)]
    inputs: VerificationInputs,
    /// Target whose retained attempt should be verified.
    #[arg(long, alias = "deployment")]
    target: String,
    /// Positive retained history ID.
    #[arg(long)]
    attempt: i64,
}

#[derive(Args)]
struct WatchArgs {
    /// Path to the external watcher routing configuration.
    #[arg(long, default_value = "canary-watch.json")]
    config: PathBuf,
    /// Local TOFU only: skip Canary's own attestation.
    #[arg(long)]
    skip_canary_attestation: bool,
    /// Local only: permit an HTTP Canary origin. Requires --skip-canary-attestation.
    #[arg(long)]
    allow_http_canary: bool,
    /// Local only: permit HTTP webhook URLs.
    #[arg(long)]
    allow_http_webhooks: bool,
    #[arg(long, hide = true)]
    insecure: bool,
}

#[derive(Subcommand)]
enum LegacyArtifactCommand {
    VerifyStatement(VerifyStatementArgs),
    VerifyEvidence(VerifyEvidenceArgs),
}

#[derive(Args)]
struct VerifyStatementArgs {
    #[arg(long)]
    statement: PathBuf,
    #[arg(long, alias = "keys", default_value = DEFAULT_KEYS_FILE)]
    trusted_keys: PathBuf,
}

#[derive(Args)]
struct VerifyEvidenceArgs {
    #[arg(long)]
    evidence: PathBuf,
    #[arg(long, alias = "pcrs")]
    expected_pcrs: PathBuf,
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
    let command = canonical_command(cli.command);
    let command_name = command_name(&command);
    let outcome = execute(command, cli.json, cli.verbose);
    match outcome {
        Ok(outcome) => render(outcome, cli.json, cli.verbose),
        Err(error) => render_error(error, cli.json, command_name),
    }
}

fn canonical_command(command: Command) -> Command {
    match command {
        Command::Deployment {
            command: LegacyDeploymentCommand::Add(args),
        } => Command::AddTarget(args),
        Command::Identity {
            command: LegacyIdentityCommand::Create(args),
        } => Command::CreateSigningSeed(args),
        Command::Enroll(args) => Command::SaveCanaryKeys(args),
        Command::Artifact {
            command: LegacyArtifactCommand::VerifyStatement(args),
        } => Command::VerifyStatement(args),
        Command::Artifact {
            command: LegacyArtifactCommand::VerifyEvidence(args),
        } => Command::VerifyEvidence(args),
        command => command,
    }
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::AddTarget(_) | Command::Deployment { .. } => "deployment.add",
        Command::CreateSigningSeed(_) | Command::Identity { .. } => "identity.create",
        Command::SaveCanaryKeys(_) | Command::Enroll(_) => "enroll",
        Command::Verify(_) | Command::VerifyAttempt(_) => "verify",
        Command::Watch(_) => "watch",
        Command::VerifyStatement(_)
        | Command::Artifact {
            command: LegacyArtifactCommand::VerifyStatement(_),
        } => "artifact.verify-statement",
        Command::VerifyEvidence(_)
        | Command::Artifact {
            command: LegacyArtifactCommand::VerifyEvidence(_),
        } => "artifact.verify-evidence",
    }
}

fn execute(command: Command, json_mode: bool, verbose_mode: bool) -> Result<Outcome> {
    match command {
        Command::AddTarget(args) => {
            if json_mode && args.tofu && !args.accept_tofu {
                bail!("--json with --tofu requires --accept-tofu to avoid an interactive prompt")
            }
            let name = args.name.as_deref().unwrap_or(&args.id);
            let (digest, mode, captured_pcrs) = match (args.expected_pcrs.as_deref(), args.tofu) {
                (Some(expected_pcrs), false) => (
                    config_add(&args, name, expected_pcrs)?,
                    "trusted_pcrs",
                    Value::Null,
                ),
                (None, true) => {
                    let capture = capture::run(
                        &args.config,
                        &args.id,
                        name,
                        &args.attestation_url,
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
                _ => bail!("pass exactly one of --expected-pcrs or --tofu"),
            };
            let verbose = if mode == "tofu" {
                format!(
                    "ADDED target {}\n  config: {}\n  mode: TOFU\n  PCR0: {}\n  PCR1: {}\n  PCR2: {}\n  config_digest: {}\n  WARNING: TOFU does not prove reviewed or reproduced source.",
                    args.id,
                    args.config.display(),
                    captured_pcrs["pcr0"].as_str().expect("TOFU capture has PCR0"),
                    captured_pcrs["pcr1"].as_str().expect("TOFU capture has PCR1"),
                    captured_pcrs["pcr2"].as_str().expect("TOFU capture has PCR2"),
                    digest,
                )
            } else {
                format!(
                    "ADDED target {}\n  config: {}\n  mode: trusted PCRs\n  config_digest: {}",
                    args.id,
                    args.config.display(),
                    digest,
                )
            };
            Ok(Outcome {
                command: "deployment.add",
                ok: true,
                result: json!({"deployment": args.id, "config": args.config, "mode": mode, "e2e_mode": args.e2e_mode, "config_digest": digest, "captured_pcrs": captured_pcrs}),
                concise: format!(
                    "ADDED TARGET {} -> {} ({}){}",
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
        Command::CreateSigningSeed(args) => {
            seed::generate(&args.output, args.force)?;
            Ok(Outcome {
                command: "identity.create",
                ok: true,
                result: json!({"env_file": args.output}),
                concise: format!(
                    "CREATED SIGNING SEED {}\nWARNING: never commit this seed file.",
                    args.output.display()
                ),
                verbose: Some(format!(
                    "CREATED SIGNING SEED {}\n  stores CANARY_MASTER_SEED\n  protect it with Locksmith before deployment",
                    args.output.display()
                )),
            })
        }
        Command::SaveCanaryKeys(args) => {
            let resolved = args.trust.resolved()?;
            let saved = inspect::verify_and_save_keys(
                resolved.canary_url,
                resolved.expected_pcrs,
                resolved.skip_canary_attestation,
                resolved.allow_http,
                &args.output,
            )?;
            let trust = saved.trust_name();
            let identity = saved.identity_name();
            let warning = match (trust, identity) {
                ("TOFU", _) => {
                    "\nWARNING: Canary identity and config are not independently authenticated."
                }
                (_, "ephemeral") => "\nWARNING: save this Canary's new keys after it restarts.",
                _ => "",
            };
            Ok(Outcome {
                command: "enroll",
                ok: true,
                result: json!({"trust": trust, "identity": identity, "keys": args.output, "node_id": saved.node_id, "config_digest": saved.config_digest, "keyset_digest": saved.keyset_digest}),
                concise: format!(
                    "VERIFIED AND SAVED CANARY KEYS {} -> {}\nCanary: {}{}",
                    saved.node_id,
                    args.output.display(),
                    trust,
                    warning,
                ),
                verbose: Some(saved.verbose_text(&args.output)),
            })
        }
        Command::Verify(args) => {
            let resolved = args.inputs.trust.resolved()?;
            let outcome = match args.attempt {
                Some(attempt) => {
                    if args.targets.len() != 1 {
                        bail!("--attempt requires exactly one --target")
                    }
                    live_verify::run_history(
                        resolved.canary_url,
                        resolved.expected_pcrs,
                        resolved.skip_canary_attestation,
                        resolved.allow_http,
                        &args.inputs.trusted_keys,
                        &args.targets[0],
                        attempt,
                    )?
                }
                None => live_verify::run(
                    resolved.canary_url,
                    resolved.expected_pcrs,
                    resolved.skip_canary_attestation,
                    resolved.allow_http,
                    &args.inputs.trusted_keys,
                    &args.targets,
                )?,
            };
            Ok(verification_outcome(outcome))
        }
        Command::VerifyAttempt(args) => {
            let resolved = args.inputs.trust.resolved()?;
            let outcome = live_verify::run_history(
                resolved.canary_url,
                resolved.expected_pcrs,
                resolved.skip_canary_attestation,
                resolved.allow_http,
                &args.inputs.trusted_keys,
                &args.target,
                args.attempt,
            )?;
            Ok(verification_outcome(outcome))
        }
        Command::Watch(args) => {
            if json_mode || verbose_mode {
                bail!("--json and --verbose are not supported by the long-running watch command")
            }
            let skip_canary_attestation = args.skip_canary_attestation || args.insecure;
            let allow_http_canary = args.allow_http_canary || args.insecure;
            let allow_http_webhooks = args.allow_http_webhooks || args.insecure;
            if allow_http_canary && !skip_canary_attestation {
                bail!("--allow-http-canary requires --skip-canary-attestation")
            }
            let config = watch_config::WatchConfig::load(&args.config, allow_http_webhooks)?;
            watch::run(
                &config,
                watch::WatchOptions {
                    skip_canary_attestation,
                    allow_http_canary,
                },
            )?;
            Ok(Outcome {
                command: "watch",
                ok: true,
                result: Value::Null,
                concise: "WATCH STOPPED".to_owned(),
                verbose: None,
            })
        }
        Command::VerifyStatement(args) => {
            let outcome = verify::run_offline(&args.statement, &args.trusted_keys)?;
            Ok(Outcome {
                command: "artifact.verify-statement",
                ok: true,
                result: outcome.json_result(),
                concise: outcome.concise_text(),
                verbose: None,
            })
        }
        Command::VerifyEvidence(args) => {
            let outcome = verify_evidence::run_offline(&args.evidence, &args.expected_pcrs)?;
            Ok(Outcome {
                command: "artifact.verify-evidence",
                ok: true,
                result: outcome.json_result(),
                concise: outcome.concise_text(),
                verbose: None,
            })
        }
        Command::Deployment { .. }
        | Command::Identity { .. }
        | Command::Enroll(_)
        | Command::Artifact { .. } => {
            unreachable!("legacy commands are canonicalized before execution")
        }
    }
}

fn verification_outcome(outcome: live_verify::VerificationOutcome) -> Outcome {
    Outcome {
        command: "verify",
        ok: outcome.ok,
        result: outcome.json_result(),
        concise: outcome.concise_text(),
        verbose: Some(outcome.verbose_text()),
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

fn config_add(args: &TargetArgs, name: &str, pcrs_file: &Path) -> Result<String> {
    let pcrs = TrustedHashesFile::load(pcrs_file)?.into_expected_pcrs();
    let target = canary_core::config::Target {
        id: args.id.clone(),
        name: name.to_string(),
        attestation_url: args.attestation_url.clone(),
        e2e_mode: args
            .e2e_mode
            .as_deref()
            .map(|_| canary_core::config::E2eMode::Caddy),
        expected_pcrs: pcrs,
    };
    let mut config = load_or_create_config(&args.config, args.canary_id.as_deref())?;
    upsert_target(&mut config, target, args.replace)?;
    validate_and_write(&args.config, &config)
}
