# Caution Canary

Canary is a small Rust service that runs inside a Caution enclave. It repeatedly
challenges Caution/Bootproof attestation endpoints, checks PCR0/1/2 against a static
measured configuration, and publishes short-lived statements signed with Ed25519 and
ML-DSA-65.

## Current status

- Implemented: offline trust core, multi-target monitor, hardened target client,
  ephemeral SQLite history, read-only API, hybrid signing, attested metadata and node
  inspection.
- Deployment tooling: digest-pinned StageX `Containerfile`, strict deployment
  validation, reproducibility check, evaluator script and Caution configuration
  templates.
- Operator inputs are intentionally absent: final `canary.json`, final `caution.hcl`,
  Caution deployment metadata, quorum bundle and encrypted seed.
- This repository does not claim that the live Phase 3 acceptance run has occurred.
  Its evidence must be recorded under
  [`docs/evidence/v0/`](docs/evidence/v0/README.md).

The normative design and 14 acceptance criteria are in
[`docs/canary-v0-spec.md`](docs/canary-v0-spec.md).

## Evaluator quickstart

### Prerequisites

- Linux amd64 with Rust, Docker Buildx, `jq`, Git and the Caution CLI.
- A public source repository URL and public Canary domain.
- Two distinct public target `/attestation` URLs and independently verified PCR files.
- An authenticated Caution account, deployment SSH access, Keymaker URL and authorized
  passkey/Locksmith operator.
- Controlled replay and outage targets for the failure and recovery demonstration.

Build the operator CLI and add it to the current shell:

```sh
cargo build --release --locked -p canaryctl
export PATH="$PWD/target/release:$PATH"
canaryctl --help
```

### 1. Create the measured deployment inputs

Copy and review the Caution template, replacing both public placeholders:

```sh
cp caution.hcl.template caution.hcl
$EDITOR caution.hcl
```

Do not deploy the template unchanged. `canary.json.template` illustrates the schema
only; let `canaryctl config add` create the final measured `canary.json`.

Preferred enrollment starts with separately reproduced target PCRs. Save each result
before the next `caution verify --save-pcrs` overwrites it:

```sh
mkdir -p .caution/trusted_hashes

caution verify --attestation-url https://payments.example.com/attestation --save-pcrs
cp .caution/trusted_hashes.json .caution/trusted_hashes/payments-prod.json

caution verify --attestation-url https://ledger.example.com/attestation --save-pcrs
cp .caution/trusted_hashes.json .caution/trusted_hashes/ledger-prod.json

canaryctl config add \
  --config canary.json --node-id caution-canary-demo \
  --id payments-prod --name "Payments production" \
  --attestation-url https://payments.example.com/attestation \
  --pcrs-file .caution/trusted_hashes/payments-prod.json

canaryctl config add \
  --config canary.json \
  --id ledger-prod --name "Ledger production" \
  --attestation-url https://ledger.example.com/attestation \
  --pcrs-file .caution/trusted_hashes/ledger-prod.json
```

For a separate TOFU demonstration only:

```sh
canaryctl capture \
  --config canary-tofu-demo.json --node-id caution-canary-tofu-demo \
  --id tofu-target --name "TOFU demonstration only" \
  --attestation-url https://tofu.example.com/attestation
```

`capture` verifies fresh Bootproof evidence and asks before recording the observed
PCRs. It proves continuity from that enrolled endpoint, not that the PCRs reproduce
reviewed source. Canary never silently updates an enrolled baseline.

### 2. Generate and encrypt the one root seed

```sh
canaryctl seed generate --env-file .env

# PAUSE: authorized Keymaker/Locksmith operator required.
caution secret keygen canary.asc \
  --name "Canary POC" --email canary@example.com --shoot-self-in-foot
export KEYMAKER_URL=https://<keymaker-host>
caution secret new canary.asc --threshold 1 --max 1
caution secret encrypt --env-file .env CANARY_MASTER_SEED
```

This is a POC-only 1-of-1 quorum with an unencrypted development keyring. Never commit
`.env` or `canary.private.asc`, and do not use this arrangement in production.

### 3. Initialize, validate and reproduce

```sh
# PAUSE: authenticated Caution account, passkey and deployment SSH key required.
caution init

./scripts/validate-deployment.sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
./scripts/check-reproducible.sh
caution apps build --no-cache
```

The reproducibility script performs two uncached Linux amd64 OCI builds with fixed
timestamps, disabled non-deterministic provenance metadata and a byte-for-byte
comparison. This demonstrates local determinism; an independent evaluator and
`caution verify` are still required.

### 4. Deploy, verify and send the shard

Commit only public/measured inputs, deployment metadata, the public quorum bundle and
the encrypted secret:

```sh
git add canary.json Containerfile caution.hcl .caution/deployment.json \
  .caution/quorum-bundle.json .caution/secrets/CANARY_MASTER_SEED.asc \
  .caution/trusted_hashes
git commit -m "Deploy Canary V0 POC"
git push caution main

caution verify --save-pcrs

# PAUSE: authorized Locksmith operator required.
caution secret send-shard --keyring canary.private.asc
```

The saved PCRs now describe the deployed Canary, not either monitored target.

### 5. Inspect and verify public artifacts

Inspect fresh Canary attestation before trusting the served hybrid keys:

```sh
canaryctl inspect-node \
  --url https://<canary-host> \
  --pcrs-file .caution/trusted_hashes.json \
  --keys-out trusted-keys.json

curl -fsS https://<canary-host>/targets/payments-prod/statement -o statement.json
curl -fsS https://<canary-host>/targets/payments-prod/evidence -o evidence.json

canaryctl verify-statement \
  --statement statement.json \
  --keys trusted-keys.json

canaryctl verify-evidence \
  --evidence evidence.json \
  --pcrs-file .caution/trusted_hashes/payments-prod.json
```

`inspect-node` verifies that fresh Canary attestation binds the measured config digest
and exact served keyset digest. Downloading keys and statements from the same
uninspected node proves only self-consistency.

Standalone evidence verification checks the document and PCRs at its recorded
`observed_at`; freshness also requires the trusted statement that binds the same
evidence digest and observation time.

For a guided transcription of this flow, set `CANARY_HOST`, `PAYMENTS_URL`,
`LEDGER_URL`, `PAYMENTS_PCRS` and `LEDGER_PCRS`, then run:

```sh
./scripts/demo-v0.sh
```

The script pauses for secret, passkey and deployment actions. It does not generate,
read or print the master seed or private keyring.

## Exact V0 claim and limits

A `VERIFIED` `caution.canary.pcr-match.v0` statement means:

> At the stated time, this Canary obtained valid fresh nonce-bound AWS Nitro evidence
> from the target, and PCR0/1/2 matched the values embedded in the Canary's measured
> configuration.

It does not prove source reproduction unless the preferred enrollment workflow was
completed. It also does not prove that normal traffic reached the same enclave, cover
every load-balanced replica, assess application correctness or provide uninterrupted
history between probes. Enumerate replica endpoints when each replica must be covered.

The statement envelope requires both Ed25519 and ML-DSA-65 verification. It is
hybrid post-quantum signed, not quantum-proof, because Nitro's attestation chain
remains classical.

Current Caution egress is a boolean gate. The broad TCP/443 rule enables outbound
access, while Canary enforces target restrictions through measured configuration,
fresh DNS resolution, prohibited-address rejection and socket pinning. This does not
protect against host/platform compromise and remains an explicit V0 exception.

## Runtime and public interfaces

- `canaryd` reads `/app/canary.json` and only `CANARY_MASTER_SEED` as secret input.
- It writes attested metadata to `/metadata.json` and current-lifetime SQLite state to
  `/tmp/canary/canary.sqlite3`.
- Targets start as signed `PENDING`, probe immediately and then every 60 seconds with
  bounded jitter and concurrency.
- A transport failure preserves a still-fresh definitive result with a warning.
  Persistent failure becomes `UNREACHABLE` only after three failures and TTL expiry;
  one valid probe recovers immediately.
- Restart wipes history, returns targets to `PENDING` and triggers immediate probes.
- Canary verifies Bootproof over HTTPS and never calls `/dev/nsm`, Nitro drivers or
  attestation-generation APIs directly.
- Caution Bootproofd, not `canaryd`, owns `POST /attestation`.

Available `canaryctl` commands are `config add`, `capture`, `seed generate`,
`inspect-node`, `verify-statement` and `verify-evidence`. Use `canaryctl --help` for
the exact interface.

| Endpoint | Purpose |
|---|---|
| `GET /` | Multi-target status page |
| `GET /health` | Liveness and readiness |
| `GET /status.json` | Current per-target states |
| `GET /targets/{id}/statement` | Latest hybrid-signed statement |
| `GET /targets/{id}/evidence` | Latest Bootproof evidence bundle |
| `GET /targets/{id}/history` | Current-enclave-lifetime history |
| `GET /config.json` | Measured config and digest |
| `GET /keys.json` | Hybrid public key set |

All application endpoints are public in V0. Treat target names, URLs, PCRs, public
keys and evidence as public information.

V0 intentionally has no durable storage, webhooks, mutable configuration API,
customer signatures, timestamping or automatic replica discovery. Public
interoperability vectors are under
[`crates/canary-core/tests/data`](crates/canary-core/tests/data/README.md).

Run and record the mismatch, replay, outage, expiry, recovery, restart, configuration
change and TOFU scenarios using the matrix in
[`docs/evidence/v0/README.md`](docs/evidence/v0/README.md). A config change is a source
change and requires a newly measured deployment.

## License

This workspace is `AGPL-3.0-only`; see [LICENSE.md](LICENSE.md). The pinned
`bootproof-sdk` source is also AGPL-3.0.
