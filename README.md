# Caution Canary

Canary continuously checks public Caution/Bootproof attestation endpoints. It
compares fresh nonce-bound AWS Nitro evidence with configured PCR0/1/2 values and
publishes short-lived statements signed with Ed25519 and ML-DSA-65.

Canary supports 1–100 targets. It serves a public status page and JSON API on port
8080.

## Requirements

- Rust 1.88 or newer to build `canaryctl`.
- Docker with BuildKit and linux/amd64 support for the local image.
- One or more publicly reachable HTTPS Bootproof `/attestation` endpoints.
- For Caution deployment: the Caution CLI and account, a public source repository,
  a public DNS name, a Keymaker URL, and a Locksmith shard-holder keyring.

The StageX image is linux/amd64. Docker Desktop can emulate it on Apple Silicon.

## Build the operator CLI

```sh
cargo build --release --locked -p canaryctl
export PATH="$PWD/target/release:$PATH"
```

`canaryctl --help` lists the available commands.

## Configure targets

`canary.json` contains a stable ID for this Canary and the expected PCR0/1/2 values
for every target. Create it with one of the following enrollment methods.

### Independently reproduced PCRs

Use `caution verify` to reproduce the target and save its PCRs, then add the target:

```sh
mkdir -p .caution/trusted_hashes
caution verify \
  --attestation-url https://payments.example.com/attestation \
  --save-pcrs
cp .caution/trusted_hashes.json \
  .caution/trusted_hashes/payments-prod.json

canaryctl config add \
  --config canary.json \
  --node-id company-canary \
  --id payments-prod \
  --name "Payments production" \
  --attestation-url https://payments.example.com/attestation \
  --pcrs-file .caution/trusted_hashes/payments-prod.json
```

`--node-id` is required only when creating the file. For each additional target,
save its PCRs under a distinct name and repeat `config add` without `--node-id`.
Updating an existing target requires `--replace`.

### Trust on first use

This path needs no Caution account. It records the PCRs returned by the live target
after interactive confirmation:

```sh
canaryctl capture \
  --config canary.json \
  --node-id company-canary \
  --id payments-prod \
  --name "Payments production" \
  --attestation-url https://payments.example.com/attestation
```

TOFU verifies fresh Bootproof evidence but does not reproduce the target from
source. It establishes continuity from the captured PCRs.

Target IDs and `node_id` may contain ASCII letters, digits, `-`, and `_`. Target
URLs must use HTTPS, and every PCR must be a nonzero lowercase 96-character
SHA-384 hex value. Canary rejects target DNS answers for loopback, private,
link-local, multicast, and other non-public address ranges.

## Run locally with Docker, without Caution

Generate a development seed, build the local image target, and run it with the
configuration mounted read-only:

```sh
canaryctl seed generate --env-file .env

docker buildx build \
  --load \
  --platform linux/amd64 \
  --target local \
  --tag caution-canary:local \
  --file Containerfile \
  .

docker run --rm --platform linux/amd64 \
  --publish 127.0.0.1:8080:8080 \
  --env-file .env \
  --volume "$PWD/canary.json:/app/canary.json:ro" \
  caution-canary:local
```

In another shell:

```sh
curl -fsS http://localhost:8080/health
curl -fsS http://localhost:8080/status.json
```

The status page is at <http://localhost:8080/>. The local container probes and
verifies configured targets, but it does not expose its own `/attestation` endpoint;
Caution adds that endpoint through Bootproofd.

The local SQLite database is `/tmp/canary/canary.sqlite3` and is discarded with the
container. Never commit `.env`: it contains the root seed for this Canary's signing
keys.

## Deploy on Caution

### 1. Create the deployment configuration

```sh
cp caution.hcl.template caution.hcl
$EDITOR caution.hcl
```

Replace the source repository URL and public HTTPS domain. `caution.hcl` deploys
Canary itself; monitored targets remain in `canary.json`.

### 2. Authenticate and initialize

First-time accounts register with an access code. Existing accounts log in:

```sh
caution register --alpha-code YOUR_ACCESS_CODE  # first time only
# or: caution login

caution ssh-keys add --from-agent
caution init
```

`caution init` validates `caution.hcl`, creates `.caution/deployment.json`, and adds
the `caution` Git remote.

### 3. Encrypt the master seed with Locksmith

Generate the seed if `.env` does not already exist:

```sh
canaryctl seed generate --env-file .env
```

Create a quorum from a shard-holder public keyring, then encrypt the seed:

```sh
export KEYMAKER_URL=https://keymaker.example.com
caution secret new keyring.asc --threshold 2 --max 3
caution secret encrypt --env-file .env CANARY_MASTER_SEED
```

`--max` must equal the number of eligible certificates in `keyring.asc`. Each
certificate needs signing, encryption, and authentication subkeys. See the
[Caution key services guide](https://docs.caution.co/concepts/key-services/) for
production shard-holder setup. Do not commit `.env` or private keyrings.

### 4. Commit and deploy

Commit the measured configuration, deployment metadata, public quorum bundle, and
encrypted seed:

```sh
git add canary.json Containerfile caution.hcl .caution/deployment.json \
  .caution/quorum-bundle.json \
  .caution/secrets/CANARY_MASTER_SEED.asc
git commit -m "Deploy Canary"
git push caution main
```

From a non-`main` local branch, use `git push caution HEAD:main`. The Git push is
the deployment action; `caution apps build` only builds an image for local
inspection.

### 5. Verify and release the seed

```sh
caution verify --save-pcrs
caution secret send-shard
```

Each authorized shard holder repeats `caution secret send-shard` until the quorum
is met. Canary starts after Locksmith releases `CANARY_MASTER_SEED` inside the
enclave.

## Verify a deployed Canary

Verify fresh Canary attestation before trusting its public signing keys:

```sh
canaryctl inspect-node \
  --url https://canary.example.com \
  --pcrs-file .caution/trusted_hashes.json \
  --keys-out trusted-keys.json
```

Then verify a target statement and its linked evidence:

```sh
curl -fsS https://canary.example.com/targets/payments-prod/statement -o statement.json
curl -fsS https://canary.example.com/targets/payments-prod/evidence -o evidence.json

canaryctl verify-statement \
  --statement statement.json \
  --keys trusted-keys.json

canaryctl verify-evidence \
  --evidence evidence.json \
  --pcrs-file .caution/trusted_hashes/payments-prod.json
```

`inspect-node` without `--pcrs-file` checks self-consistency only. It does not
establish that the Canary image matches independently reproduced PCRs.

## HTTP API

| Endpoint | Purpose |
|---|---|
| `GET /` | Multi-target status page |
| `GET /health` | Liveness and readiness |
| `GET /status.json` | Current state for every target |
| `GET /targets/{id}/statement` | Latest hybrid-signed statement |
| `GET /targets/{id}/evidence` | Latest Bootproof evidence bundle |
| `GET /targets/{id}/history` | Up to 100 observations from the current database |
| `GET /config.json` | Measured target configuration and digest |
| `GET /keys.json` | Ed25519 and ML-DSA-65 public keys |

All endpoints are public. Treat target names, URLs, PCRs, keys, and evidence as
public information.

## Runtime behavior and limits

- Targets are probed immediately, then every 60 seconds with 0–5 seconds of jitter.
  At most eight probes run concurrently; each attempt times out after 15 seconds.
- A definitive result is valid for 180 seconds. Transport failures can preserve a
  still-valid result with a warning; successful verification recovers immediately.
- Every process start publishes fresh `PENDING` statements and probes immediately.
  Existing history remains only if the same SQLite database remains available.
  Replacing the container or enclave discards `/tmp` history.
- A local bind-mounted `canary.json` change requires a container restart. A Caution
  deployment embeds the file, so changing it requires rebuilding and redeploying.
- Canary has no durable storage, mutable configuration API, alerts, webhooks,
  timestamp authority, automatic replica discovery, or application traffic-path
  binding.
- A `VERIFIED` result means fresh Nitro evidence matched the configured PCR0/1/2.
  It does not prove application correctness or that all load-balanced replicas were
  observed. Configure each replica endpoint when each replica must be covered.

## License

This workspace is licensed under `AGPL-3.0-only`; see [LICENSE.md](LICENSE.md).
