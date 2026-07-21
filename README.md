# Caution Canary

Canary continuously checks public Caution/Bootproof attestation endpoints. It
compares fresh nonce-bound AWS Nitro evidence with configured PCR0/1/2 values and
publishes short-lived statements signed with Ed25519 and ML-DSA-65.

Canary supports 1–100 targets and serves a public status page and JSON API on port
8080. A `VERIFIED` target means fresh Nitro evidence matched that target's configured
PCR0/1/2. It does not prove application correctness or cover replicas that were not
configured as targets; configure each replica endpoint when every replica matters.

## Choose a workflow

| Mode | Canary trust | Intended use |
|---|---|---|
| Caution deployment | Fresh Canary attestation, independently reproduced Canary PCR0/1/2, and attested config and signing keys | Production verification |
| Local Docker | Explicit TOFU pin of the initial signer and an unattested local config | Development and evaluation |

Both modes verify hybrid-signed statements and replay their linked target evidence
against the configured target PCR policy. Local mode proves continuity with the
signer enrolled on first use; it does not authenticate the initial signer,
configuration, target PCR policy, or running Canary workload.

## Requirements

- Rust 1.88 or newer to build `canaryctl`.
- One or more publicly reachable HTTPS Bootproof `/attestation` endpoints.
- For local use: Docker with BuildKit and linux/amd64 support.
- For Caution deployment: the Caution CLI and account, a public source repository,
  and a public DNS name. Stable identity additionally requires a Keymaker URL and
  Locksmith shard-holder keyring; ephemeral identity does not.

The StageX image is linux/amd64. Docker Desktop can emulate it on Apple Silicon.

## Install `canaryctl`

```sh
cargo build --release --locked -p canaryctl
export PATH="$PWD/target/release:$PATH"
```

`canaryctl --help` lists the available commands.

## Configure targets

`canary.json` contains a stable ID for this Canary and the expected PCR0/1/2 values
for every target. Create it with one of the following enrollment methods.

### Preferred: independently reproduced target PCRs

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
probes. `history_limit` is the retained row count per target; it defaults to 1,000 and
accepts 1–10,000. Changing either field requires a restart locally or a
rebuild/redeploy on Caution.

### Target PCR trust on first use

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

## Run Canary

### Local Docker

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

The status page is at <http://localhost:8080/>. Local Docker has no Canary attestation
endpoint, so verification uses the explicit `--insecure` TOFU workflow below.

Local history is discarded with the container. Never commit `.env`: it contains the
root seed for this Canary's signing keys.

### Caution deployment

#### 1. Create the deployment configuration

```sh
cp caution.hcl.template caution.hcl
$EDITOR caution.hcl
```

Replace the source repository URL and public HTTPS domain. `caution.hcl` deploys
Canary itself; monitored targets remain in `canary.json`. Then choose exactly one
identity mode:

- **Ephemeral identity** — easiest for demos and disposable monitors. Replace the
  template's `env` block with `args = ["--ephemeral-identity"]`. It needs no Locksmith,
  but every process restart creates new signing keys.
- **Stable identity** — keep the template's `env::vault("CANARY_MASTER_SEED")` block
  and complete the Locksmith steps below. It preserves the signer across restarts and
  redeployments.

The daemon rejects `--ephemeral-identity` when `CANARY_MASTER_SEED` is also present.
Changing identity mode requires a rebuild/redeploy and new Canary PCRs.

#### 2. Authenticate and initialize

First-time accounts register with an access code. Existing accounts log in:

```sh
caution register --alpha-code YOUR_ACCESS_CODE  # first time only
# or: caution login

caution ssh-keys add --from-agent
caution init
```

`caution init` validates `caution.hcl`, creates `.caution/deployment.json`, and adds
the `caution` Git remote.

#### 3. Optional: provision the stable identity with Locksmith

Skip this section for ephemeral identity.

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

#### 4. Commit and deploy

For ephemeral identity, commit only the measured configuration and deployment metadata:

```sh
git add canary.json Containerfile caution.hcl .caution/deployment.json
git commit -m "Deploy ephemeral Canary"
git push caution main
```

For stable identity, also commit the public quorum bundle and encrypted seed:

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

#### 5. Verify, then release the stable seed if applicable

```sh
caution verify --save-pcrs
```

Ephemeral Canary starts immediately and needs no further release step. For stable
identity, each authorized shard holder runs `caution secret send-shard` until the
quorum is met; Canary then starts after Locksmith releases `CANARY_MASTER_SEED` inside
the enclave.

## Inspect the status UI

Open the root URL after Canary starts:

```text
https://canary.example.com/
```

For local Docker, use <http://localhost:8080/>. The dashboard shows every target's
current state. Select **Inspect** to view its hybrid-signed statement, linked raw
evidence, process-lifetime history, retained artifacts, and ready-to-copy verification
commands.

Treat the UI as status only; use `canaryctl` for independent verification.

## Verify independently

### Caution deployment

Before running `verify`, obtain the two explicit trust inputs: independently
reproduced PCR0/1/2 for the **Canary deployment itself**, and the Canary public keys
authenticated by a fresh attestation.

First reproduce the node PCRs:

```sh
caution verify --save-pcrs
```

Then authenticate and save the Canary public keys:

```sh
canaryctl inspect-node \
  --url https://canary.example.com \
  --pcrs-file .caution/trusted_hashes.json \
  --keys-out canary-keys.json
```

Keep `canary-keys.json` as an integrity-critical public trust artifact. Enrollment
refuses to overwrite it. With stable identity, an intentional seed/key rotation
requires separately reviewed re-enrollment. With ephemeral identity, every process
restart intentionally invalidates the old pin: retain it for historical statements
and enroll the new process into a new file. Do not add an overwrite shortcut.

Every subsequent live verification requires both explicit trust inputs:

```sh
canaryctl verify \
  --url https://canary.example.com \
  --pcrs-file .caution/trusted_hashes.json \
  --keys canary-keys.json
```

Add `--target payments-prod` to select one target; repeat it to select several. With no
selection, every target in the attested config is verified.

`verify` checks the Canary against the expected deployment PCRs and enrolled keys,
requires both statement signatures, and independently replays each statement's linked
target evidence. Any stale, negative, mismatched, or unverifiable result exits
non-zero.

For ephemeral identity this authenticates the **current process keyset**, not a durable
deployment identity. Do not put multiple ephemeral Canary replicas behind one URL:
each process has different keys and a verifier can receive inconsistent documents.

### Local Docker: TOFU key enrollment

There is no Canary attestation outside Caution. Enroll the initially observed keyset
once, explicitly as TOFU:

```sh
canaryctl inspect-node \
  --url http://localhost:8080 \
  --insecure \
  --keys-out canary-keys.json
```

Then require that pin on every verification:

```sh
canaryctl verify \
  --url http://localhost:8080 \
  --insecure \
  --keys canary-keys.json
```

This still verifies both statement signatures and replays the complete target
evidence check against PCR0/1/2 from the served config. It proves continuity with the
signer enrolled by the first command. It does **not** prove that the initial signer,
served config, configured target PCR policy, or running Canary workload was authentic;
an attacker present during TOFU enrollment can establish their own key and policy.
The `--insecure` flag also permits HTTP and deliberately skips only Canary's own
attestation; it does not disable statement signature, evidence-link, target Nitro, or
target PCR verification.

### Result meanings

`verify` is a one-shot verification of each target's **current published signed
claim**. It is not necessarily the latest network attempt: a transport failure may
leave the previous definitive claim current while that evidence remains fresh. The
signed observation, issuance, and expiry times identify exactly what was checked;
they are not independent timestamp-authority proof. Multiple targets are verified
independently, not as one atomic snapshot.

| Result | Meaning |
|---|---|
| `PASS — FULL ATTESTED CHAIN VERIFIED` | Canary measurements, attested config and keys, current statements, and linked target evidence verified |
| `PASS — VERIFIED AGAINST TOFU SIGNER + UNATTESTED CONFIG` | Chain verified against the pinned development signer and its unauthenticated policy |
| `AUTHENTICATED_NEGATIVE` | Canary trust chain is valid, but at least one signed target state is not `VERIFIED` |
| `SIGNED_NEGATIVE` | Equivalent negative result under the TOFU signer |
| `ERROR` | A required artifact could not be fetched, parsed, matched, or verified |

Only the two `PASS` results exit zero. Stable deployments report `STABLE — EXTERNAL
SEED`; ephemeral deployments report `EPHEMERAL — CURRENT PROCESS` and warn that a
restart creates new keys. Local mode reports its unattested configuration and unknown
identity lifecycle explicitly.

### Offline artifact verification

Verify a downloaded target statement and evidence:

```sh
curl -fsS https://canary.example.com/targets/payments-prod/statement -o statement.json
curl -fsS https://canary.example.com/targets/payments-prod/evidence -o evidence.json

canaryctl verify-statement \
  --statement statement.json \
  --keys canary-keys.json

canaryctl verify-evidence \
  --evidence evidence.json \
  --pcrs-file .caution/trusted_hashes/payments-prod.json
```

`verify-evidence` always requires independently trusted target PCRs. `verify` and
`verify-history` additionally require the enrolled Canary `--keys` file. Live commands
require exactly one of `--pcrs-file` or explicit demo-only `--insecure`; there is no
implicit trust downgrade.

### Historical replay

Take the attempt ID from the history endpoint or UI and replay its retained statement
and evidence:

```sh
canaryctl verify-history \
  --url https://canary.example.com \
  --pcrs-file .caution/trusted_hashes.json \
  --keys canary-keys.json \
  --target payments-prod \
  --attempt 42
```

This verifies the retained artifacts at their recorded times. Reproducing a negative
result confirms the historical record; it does not make the target healthy. Attempts
without decodable evidence cannot be replayed.

## Useful HTTP endpoints

| Endpoint | Purpose |
|---|---|
| `GET /` | Multi-target status page |
| `GET /health` | Liveness and readiness |
| `GET /status.json` | Current state for every target |
| `GET /targets/{id}/statement` | Latest hybrid-signed statement |
| `GET /targets/{id}/evidence` | Latest Bootproof evidence bundle |
| `GET /targets/{id}/history` | Retained target observations |
| `GET /targets/{id}/history/{attempt_id}` | Exact retained statement and evidence for local replay |
| `GET /config.json` | Measured target configuration and digest |
| `GET /keys.json` | Ed25519 and ML-DSA-65 public keys |

All endpoints are public. Treat target names, URLs, PCRs, keys, and evidence as
public information.

## Operational notes

- Targets are probed immediately, then every `probe_interval_seconds` (default 60).
  Results expire after 180 seconds.
- History is process-local and is lost when the container or enclave is replaced.
- Ephemeral identity creates new keys on restart; enroll the new keyset before live
  verification resumes.
- A local bind-mounted `canary.json` change requires a container restart. A Caution
  deployment embeds the file, so changing it requires rebuilding and redeploying.
- Canary has no durable storage, mutable configuration API, alerts, webhooks,
  timestamp authority, automatic replica discovery, or application traffic-path
  binding.

## License

This workspace is licensed under `AGPL-3.0-only`; see [LICENSE.md](LICENSE.md).
