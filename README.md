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

## Start with the status UI

Once Canary is running, open its root URL first:

```text
https://canary.example.com/
```

The dashboard is the guided entry point. Select **Inspect** on any target to see:

- The current target state and what the badge does—and does not—prove.
- The hybrid-signed **statement**, which records Canary's conclusion.
- The linked **evidence**, which is the raw nonce-bound Nitro proof Canary evaluated.
- Process-lifetime **history**, which is useful unsigned diagnostic context rather
  than cryptographic proof.
- A ready-to-copy `canaryctl verify` command for independent local verification.

The original JSON endpoints remain linked throughout the UI. The page itself does not
perform browser-side cryptographic verification; use the displayed `canaryctl` command
to verify the Canary node, statement, and evidence chain locally.

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

The generated `canary.json` also carries global runtime policy. For example:

```json
{
  "version": 0,
  "node_id": "company-canary",
  "probe_interval_seconds": 120,
  "history_limit": 2000,
  "targets": [
    {
      "id": "payments-prod",
      "name": "Payments production",
      "attestation_url": "https://payments.example.com/attestation",
      "expected_pcrs": {
        "0": "<96 lowercase hex characters>",
        "1": "<96 lowercase hex characters>",
        "2": "<96 lowercase hex characters>"
      }
    }
  ]
}
```

Edit `probe_interval_seconds` to change the cadence for every target. It defaults to
60 seconds and accepts 6–86,400. The example uses two minutes. Claims still expire
after 180 seconds, so long intervals intentionally leave targets `STALE` between
probes. `history_limit` is the retained and returned row count per target; it defaults
to 1,000 and accepts 1–10,000. Both fields are measured policy included in
`config_digest`; changing either requires a restart locally or a rebuild/redeploy on
Caution.

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
  --env RUST_LOG=info \
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

The normal operator command verifies the Canary node and every configured target end
to end:

```sh
canaryctl verify \
  --url https://canary.example.com \
  --pcrs-file .caution/trusted_hashes.json
```

Add `--target payments-prod` to select one target; repeat it to select several.
`--keys-out trusted-keys.json` optionally saves the exact attestation-bound key
document, but the combined command otherwise keeps it in memory.

For the Canary node, `--pcrs-file` supplies the independently reproduced PCR0/1/2
expected from its fresh Nitro attestation. The CLI verifies the AWS chain, COSE
signature, certificate time, nonce and exact PCR values before trusting the attested
config and key digests. It then verifies each target statement and its linked evidence
against the target PCR policy in that attested config.

These two commands cover different links in the trust chain: `caution verify
--save-pcrs` establishes the expected PCR identity of the deployed Canary image;
`canaryctl verify` consumes that trusted file and verifies the live Canary
attestation, attested config and keys, signed target statements, and linked target
evidence. Both are required for end-to-end verification.

The lower-level command verifies fresh Canary attestation and saves its public signing
keys:

```sh
canaryctl inspect-node \
  --url https://canary.example.com \
  --pcrs-file .caution/trusted_hashes.json \
  --keys-out trusted-keys.json
```

For an out-of-Caution test/demo deployment only, `inspect-node --insecure` permits an
HTTP origin and self-pins PCR0/1/2 from the fresh attestation:

```sh
canaryctl inspect-node \
  --url http://localhost:1111 \
  --insecure \
  --keys-out demo-keys.json
```

It still verifies the AWS certificate chain, COSE signature, certificate time, fresh
nonce, and config/key binding. It does **not** establish the Canary workload identity;
the exported keys are suitable only for the test/demo flow.

Then the offline commands can verify a downloaded target statement and evidence:

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

`verify` and `verify-evidence` always require independently trusted PCR files.
`inspect-node` requires exactly one of `--pcrs-file` or the explicit demo-only
`--insecure` mode; there is no implicit trust downgrade.

## HTTP API

| Endpoint | Purpose |
|---|---|
| `GET /` | Multi-target status page |
| `GET /health` | Liveness and readiness |
| `GET /status.json` | Current state for every target |
| `GET /targets/{id}/statement` | Latest hybrid-signed statement |
| `GET /targets/{id}/evidence` | Latest Bootproof evidence bundle |
| `GET /targets/{id}/history` | Up to configured `history_limit` observations; default 1,000 |
| `GET /config.json` | Measured target configuration and digest |
| `GET /keys.json` | Ed25519 and ML-DSA-65 public keys |

All endpoints are public. Treat target names, URLs, PCRs, keys, and evidence as
public information.

### `config_digest` and signed outputs

`config_digest` is `sha256:` plus the SHA-256 of the RFC 8785 canonical form of the
fully parsed `canary.json`, including defaulted global settings. It prevents a result
from being moved between different target policies or runtime configurations.

```sh
curl -fsS https://canary.example.com/config.json
curl -fsS https://canary.example.com/status.json
curl -fsS https://canary.example.com/targets/payments-prod/statement
curl -fsS https://canary.example.com/targets/payments-prod/evidence
curl -fsS https://canary.example.com/targets/payments-prod/history
curl -fsS https://canary.example.com/keys.json
```

- `/config.json` and `/status.json` expose the current `config_digest`, but those JSON
  responses are not independently signed.
- `/targets/{id}/statement` carries `payload.config_digest`; the entire payload is
  signed with both Ed25519 and ML-DSA-65.
- History rows carry the digest for correlation, but history is diagnostic and
  unsigned.
- Evidence does not duplicate `config_digest`. Its digest and observation time are
  bound by the signed statement, which is in turn bound to the config digest.
- `/keys.json` has no config digest. Its exact keyset digest and the config digest are
  jointly bound into the fresh Canary Nitro attestation.

Therefore no extra config signature is needed: `canaryctl verify` checks the fresh
node attestation, config/key bindings, signed statement, and linked evidence as one
chain. Raw `curl` output alone is diagnostic and should not be treated as verified.

## Runtime behavior and limits

- Targets are probed immediately, then every configured `probe_interval_seconds`
  (default 60) with 0–5 seconds of jitter. At most eight probes run concurrently;
  each attempt times out after 15 seconds.
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
