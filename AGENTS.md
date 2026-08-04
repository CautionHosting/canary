# AGENTS.md

Guidance for AI agents working in the Caution Canary repository.

## What this project is

Caution Canary is a Rust service that continuously monitors public Caution/Bootproof attestation endpoints from inside a Caution enclave. For each configured target, it fetches fresh nonce-bound Nitro attestation evidence, compares PCR0/1/2 against operator-supplied policy, and publishes short-lived signed results (hybrid Ed25519 + ML-DSA-65). `canaryctl` is the operator CLI for configuring targets and independently verifying Canary's output.

The normative design document is `docs/canary-v0-spec.md` — if code and spec disagree for V0, the spec wins.

## Build & test commands

```sh
# Format check (must pass before push)
cargo fmt --all -- --check

# Lint (clippy is deny-on-warnings at the workspace level)
cargo clippy --workspace --all-targets --locked -- -D warnings

# Run all unit + integration tests
cargo test --workspace --locked

# Build the operator CLI
cargo build --release --locked -p canaryctl

# Source checks (runs fmt + clippy + test + git diff --check)
sh scripts/check-source.sh

# Reproducibility check (builds the OCI image twice, compares byte-for-byte)
sh scripts/check-reproducible.sh

# Deployment validation (offline — never contacts Caution or targets)
bash scripts/validate-deployment.sh
```

**Always use `--locked`** for clippy/test/build. The lockfile pins every crate; `cargo build --frozen` (used in the Containerfile) goes further and forbids network access during compilation.

## Workspace layout

Three crates in a Cargo workspace (`resolver = "2"`, edition 2021, MSRV 1.88, license AGPL-3.0-only):

| Crate | Role | Binary |
|---|---|---|
| `canary-core` | Pure trust core: config schema/validation, JCS canonicalization, HKDF key derivation, hybrid signing/verification, Bootproof evidence verification. No I/O, no NSM, no network. | library |
| `canaryd` | The enclave daemon: scheduler, probe runner, SQLite history, Axum HTTP API, server-rendered status page. | `canaryd` |
| `canaryctl` | Operator CLI: `add-target`, `create-signing-seed`, `save-canary-keys`, `verify`, `verify-attempt`, `watch`, `verify-statement`, `verify-evidence`. | `canaryctl` |

`canary-core` is the dependency root — both `canaryd` and `canaryctl` depend on it, never on each other.

## Architecture and data flow

```
canary.json (measured config)
        │
        ▼
   canaryd runtime
   ├── scheduler (fixed cadence, anchored to startup, 0–5s jitter)
   │     ├── probe_target (per target, max 8 concurrent)
   │     │     ├── network::resolve_and_pin (DNS resolve, SSRF filter, pin IP)
   │     │     ├── HTTP POST /attestation (5s connect, 15s total, 256KiB max)
   │     │     └── evidence::verify_evidence (bootproof-sdk, PCR match, nonce, cert chain)
   │     ├── TargetReducer (pure state machine: Pending→Verified/Failed→Stale/Unreachable)
   │     ├── sign_statement (Ed25519 + ML-DSA-65 over JCS-canonical payload)
   │     └── Store::commit (SQLite: 1 transaction = attempt + prune + current)
   │         └── ApiState::publish (atomic snapshot swap after commit)
   │
   ├── Axum API (read-only)
   │     /              → HTML status page
   │     /health        → liveness/readiness
   │     /status.json   → current state summary and runtime hints
   │     /config.json   → ConfigDocument (config + config_digest)
   │     /keys.json     → canonical KeysDocument bytes
   │     /targets/{id}/statement → signed Statement
   │     /targets/{id}/evidence → EvidenceBundle
   │     /targets/{id}/history → HistoryEntry list
   │     /targets/{id}/history/{attempt_id} → HistoricalAttempt
   │
   └── metadata::write_metadata_atomic → internal /metadata.json for Bootproofd attestation

canaryctl (outside enclave)
   ├── add-target          → writes canary.json (trusted PCRs or TOFU)
   ├── create-signing-seed → writes .env (CANARY_MASTER_SEED, 0o600)
   ├── save-canary-keys    → verifies Canary attestation, saves canary-keys.json
   ├── verify          → full chain: Canary attestation → keys → signatures → evidence → PCRs
   └── verify-statement/evidence → partial offline checks on downloaded JSON
```

### Key design principles

- **`canary-core` is pure**: no I/O, no clock, no network, no NSM. All time is injected by callers. This makes the trust logic independently testable.
- **SQLite is ephemeral and non-authoritative**: the database lives at `/tmp/canary/canary.sqlite3` and is wiped on restart. The runtime never reconstructs state from it — every process starts with freshly signed `PENDING` state. SQLite is only a diagnostic/history sink.
- **Snapshots are atomic**: the scheduler publishes a whole `RuntimeSnapshot` to the API only after `Store::commit` succeeds. The API never signs, probes, or mutates.
- **Strict schemas everywhere**: all serde structs use `#[serde(deny_unknown_fields)]`. A misspelled field can never silently weaken policy.
- **Result TTL is 180 seconds** (`RESULT_TTL`). After expiry, state transitions to `STALE` (if <3 consecutive transport failures) or `UNREACHABLE` (if ≥3).
- **Transport failures don't replace fresh evidence**: a timeout while a `VERIFIED` result is still current preserves the verified statement and adds a `transport_warning`.

## Configuration: `canary.json`

The measured configuration file embedded in the enclave image. Schema is in `canary-core/src/config.rs`. Key rules:

- `version` must be `0`
- `node_id` and all target `id` fields must be non-empty ASCII `[A-Za-z0-9_-]`; `node_id` cannot collide with any target `id`
- `attestation_url` must be HTTPS, no credentials, no fragments
- PCR0/1/2 must be 96-char lowercase hex (SHA-384), nonzero (rejects debug/zero PCRs)
- `probe_interval_seconds`: 6–86400 (default 60); `history_limit`: 1–10000 (default 1000)
- 1–100 targets required
- Written by `canaryctl add-target` as pretty JSON with trailing newline; `validate-deployment.sh` verifies the committed file is byte-identical to canonical `add-target` output

## Crypto and signing

- **Master seed**: 32 bytes, base64-encoded, injected via `CANARY_MASTER_SEED` env var (stable mode) or generated fresh from OS CSPRNG (ephemeral mode, `--ephemeral-identity` flag)
- **Key derivation**: HKDF-SHA-256 with fixed salt `caution-canary-v0/root`, domain-separated info strings per `node_id`, `key_epoch = 0` (pinned for V0)
- **KeySet**: one Ed25519 keypair + one ML-DSA-65 keypair per node
- **Statement signing**: signed bytes = `b"caution.canary.statement.v0\0"` + JCS-canonical(payload). Both signatures required for verification.
- **`/keys.json`**: canonicalized once at startup; the same bytes are used for `keyset_digest` binding and served verbatim (never reserialized)
- **IdentitySource** has no `Debug` impl — a stable seed cannot be logged accidentally

## Containerfile and reproducibility

The `Containerfile` has three target stages:

| Stage | Purpose |
|---|---|
| `build` | Compiles `canaryd` with `stagex/pallet-rust`, musl static target, `--frozen`, networkless compilation |
| `local` | Minimal image for local Docker runs (bind-mounts `canary.json`, injects dev seed) |
| `run` | Production/deployment image — includes measured `canary.json` and optional Locksmith artifacts |

**Non-obvious Containerfile details**:

- `SOURCE_DATE_EPOCH=1` is set for reproducibility. The reproducibility script (`check-reproducible.sh`) builds the `run` target twice and compares OCI exports byte-for-byte with `--provenance=false --rewrite-timestamp=true`.
- The `deployment-inputs` stage materializes `/usr/bin`, `/usr/lib`, `/usr/sbin`, `/etc/ssl/certs` because `stagex/core-filesystem` ships `/bin`, `/lib`, `/sbin` as symlinks into `/usr`, but a fully static binary never populates those targets, leaving them dangling. The platform's initramfs packer does `mkdir -p` through the symlinks and fails with ENOENT if they're dangling.
- Locksmith artifacts (`.caution/quorum-bundle.json`, `.caution/secrets/CANARY_MASTER_SEED.asc`) are optional — the same recipe supports both stable and ephemeral identity. When either exists, both are required.
- `.dockerignore` uses an allowlist pattern (`*` then `!` exceptions) — only `Cargo.toml`, `Cargo.lock`, `crates/`, `migrations/`, `canary.json`, and specific `.caution/` files are sent to the builder.
- The `sqlx::migrate!` macro in `canaryd/src/store.rs` resolves `../../migrations` at compile time — the `migrations/` directory must be `COPY`ed into the build context.

## Deployment validation (`scripts/validate-deployment.sh`)

A strict offline pre-release gate. It checks:

1. Required files exist: `caution.hcl`, `canary.json`, `Containerfile`, `.caution/deployment.json`, `.caution/quorum-bundle.json`, `.caution/secrets/CANARY_MASTER_SEED.asc`
2. `caution.hcl` matches the approved V0 release shape (normalizes the two operator-supplied values — `app_sources` URL and `domain` — then diffs against `caution.hcl.template`). Rejects debug mode, STEVE/e2e, custom resources, extra units/enclaves, binary builds, extra secrets.
3. `app_sources` must be a public HTTPS URL (no placeholders, no `example.*`, no `localhost`, no IPs, no credentials/fragments/queries)
4. `canary.json` has the exact V0 schema, ≥2 targets, ≥2 unique HTTPS origins
5. Each target's PCRs match a per-target `.caution/trusted_hashes/{target_id}.json` release-validation file; `caution verify --save-pcrs` produces the singular `.caution/trusted_hashes.json` trusted-PCR input
6. `canary.json` is canonical `canaryctl add-target` output (re-runs `add-target --replace` and compares byte-for-byte)

## Caution deployment

This service is itself deployed on Caution. See `caution.hcl` (production) and `caution.hcl.template` (template to copy). Key points:

- `unit "default"` runs `/app/canaryd`
- Stable identity: `env::vault("CANARY_MASTER_SEED")` + Locksmith artifacts baked into the image
- Ephemeral identity: `args = ["--ephemeral-identity"]` — no Locksmith needed, but keys change on restart
- Deploy via `git push caution main` after `caution init`
- `caution verify --save-pcrs` produces the trusted hashes that feed `canaryctl add-target --expected-pcrs`

## Testing patterns

- **Unit tests** live in `#[cfg(test)] mod tests` within each source file
- **Integration tests** live in `crates/*/tests/`:
  - `canaryd/tests/network_boundary.rs` — DNS/SSRF policy (hermetic, uses `StaticResolver`)
  - `canaryd/tests/phase2_runtime_api.rs` — full runtime + API end-to-end (uses `ProbeRunner` and `RuntimeClock` traits for deterministic injected behavior)
  - `canaryctl/tests/cli.rs` — CLI subprocess tests via `CARGO_BIN_EXE_canaryctl`
- **Test traits for determinism**: `ProbeRunner` (inject probe results), `RuntimeClock` (inject time), `Resolver` (inject DNS answers), `ProbeTransport` (inject HTTP responses). Production always uses the `Production*` / `System*` variants.
- Temp files use an `AtomicU64` counter for unique paths within the OS temp dir

## Gotchas and non-obvious patterns

- **`canary-core` never touches NSM or `/dev/nsm`** — attestation for the Canary enclave itself is produced by the Caution Bootproof service, not by this code. The evidence module is verifier-only.
- **The unsigned Bootproof manifest is never used as policy** — it's copied into `EvidenceBundle` for diagnostics only. Verification decisions come from the signed COSE document.
- **`/keys.json` is canonicalized once and served as raw bytes** — handlers never reserialize the key document, so the `keyset_digest` in metadata always matches what clients receive.
- **`IdentitySource` has no `Debug` impl** — prevents accidental logging of the stable master seed. The seed is wrapped in `Zeroizing<String>`.
- **`atomic_file::write`** uses same-directory temp file + `rename` + `fsync`, with 0o600 mode for secrets and 0o644 for config. Used by `canaryctl` for all file writes.
- **Scheduler cadence is anchored to process startup**, not to probe completion — slow targets can't drift the schedule. Jitter is 0–5s, applied per-schedule-number.
- **`probe_interval_seconds` minimum is 6** — it must exceed the 5-second max jitter so successive anchored due times can't move backwards.
- **`serde_json` uses `preserve_order` feature** at the workspace level, but JCS canonicalization (`serde_jcs`) sorts keys independently for digest computation.
- **Clippy `all = deny`** at the workspace lint level — all warnings are build failures.
- **PCR values are SHA-384** (96 hex chars, 48 bytes), but the `config_digest` and `keyset_digest` are SHA-256 (64 hex chars, 32 bytes, `sha256:` prefix).
- **`validate-deployment.sh` requires ≥2 unique HTTPS origins** in `canary.json` — a single-target Canary is rejected for production release.
- **`caution.hcl` must not contain `cache = false`** in production — the template has it, but the actual `caution.hcl` omits it (uses Caution's default `cache = true`). The validator diffs against the template after normalizing only the two operator-supplied values.
