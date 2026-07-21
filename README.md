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
  and a public DNS name. Stable identity additionally requires a Keymaker URL and
  Locksmith shard-holder keyring; ephemeral identity does not.

The StageX image is linux/amd64. Docker Desktop can emulate it on Apple Silicon.

## Start with the status UI

Once Canary is running, open its root URL first:

```text
https://canary.example.com/
```

The dashboard is the guided entry point. Select **Inspect** on any target to see:

- The monitored targets and their current server-side results before any explanatory
  material.
- The current target state and what the badge does—and does not—prove.
- The hybrid-signed **statement**, which records Canary's conclusion.
- The linked **evidence**, which is the raw nonce-bound Nitro proof Canary evaluated.
- Process-lifetime **history** summaries plus the exact retained artifacts for each
  decodable attempt.
- Ready-to-copy `canaryctl verify` and `verify-history` commands for independent
  local verification.

The page reports `nitro_enclave` when `/dev/nsm` is visible to `canaryd`, otherwise
`non_enclave`, and shows the matching verification workflow. This is a local runtime
hint, not cryptographic proof: an untrusted process can lie about its environment.
Only the external `canaryctl` flow with a fresh attestation and independently
reproduced PCRs proves that a Caution-hosted Canary is running in the expected
enclave.

The header also shows `sha256:<hex>` for the exact running `canaryd` executable. It is
useful for build/runtime correlation but is self-reported and is not a replacement
for the Canary deployment PCR0/1/2, which measure the complete enclave image and boot
chain.

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
Caution adds that endpoint through Bootproofd. The page reports `non_enclave` and
offers the explicit `--insecure` TOFU workflow even if a local reverse proxy happens
to serve it over HTTPS.

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
Canary itself; monitored targets remain in `canary.json`. Then choose exactly one
identity mode:

- **Ephemeral identity** — easiest for demos and disposable monitors. Replace the
  template's `env` block with `args = ["--ephemeral-identity"]`. Canary generates its
  signing seed with the OS CSPRNG inside `canaryd`, keeps private material only in
  memory, and starts without Locksmith. Every process restart creates new keys.
- **Stable identity** — keep the template's `env::vault("CANARY_MASTER_SEED")` block
  and complete the Locksmith steps below. The same seed preserves the signer across
  restarts and redeployments.

The daemon rejects `--ephemeral-identity` when `CANARY_MASTER_SEED` is also present.
The selected command and Locksmith inclusion are part of the reproduced Caution
deployment, so changing modes changes the Canary PCRs.

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

### 3. Optional: provision the stable identity with Locksmith

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

### 4. Commit and deploy

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

### 5. Verify, then release the stable seed if applicable

```sh
caution verify --save-pcrs
```

Ephemeral Canary starts immediately and needs no further release step. For stable
identity, each authorized shard holder runs `caution secret send-shard` until the
quorum is met; Canary then starts after Locksmith releases `CANARY_MASTER_SEED` inside
the enclave.

Inside AWS Nitro, `/dev/nsm` is visible and the page offers the attested PCR-based
workflow. That display choice remains only a hint; the verifier outside the enclave
establishes the actual guarantee.

## Verify a deployed Canary

### Caution deployment: measured key enrollment, then full verification

Before running `verify`, obtain the two explicit trust inputs: independently
reproduced PCR0/1/2 for the **Canary deployment itself**, and the Canary public keys
authenticated by a fresh attestation.

First reproduce the node PCRs:

```sh
caution verify --save-pcrs
```

Then create `canary-keys.json`. This performs a fresh nonce-bound Canary
attestation, checks it against those PCRs, checks the attested config, keyset digest
and identity mode, and atomically saves the exact canonical public-key document:

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

`verify` performs the following checks in order:

1. Fresh Canary AWS/Nitro chain, COSE signature, certificate time, nonce and exact
   Canary PCR0/1/2.
2. Attested `config_digest`, `keyset_digest`, node ID, key epoch and identity mode
   against the live canonical documents.
3. Exact live keyset equality with the operator-enrolled `--keys` file.
4. Both Ed25519 and ML-DSA-65 signatures on each current Canary statement, plus
   statement freshness, target origin, node identity and config-digest binding.
5. Exact statement-to-evidence digest and observation-time binding, followed by local
   replay of the target Nitro chain, signature, nonce and target PCR0/1/2 policy.

Canary signs the **statement**, not the evidence bytes directly. The statement contains
the evidence digest and observation time, which prevents substituting another evidence
bundle. Any missing signature, stale statement, key/config mismatch, evidence mismatch,
negative target result or unverifiable target exits non-zero.

This proves that the current endpoint is serving a freshly attested Canary enclave
with the independently expected deployment measurements; that the served config and
signing keys are bound into that attestation; and that every selected target result is
hybrid-signed and linked to locally replayed target evidence. It does not prove
application correctness, cover replicas that were not configured as targets, or turn
the page's executable hash into an independent trust root.

For ephemeral identity this authenticates the **current process keyset**, not a durable
deployment identity. Do not put multiple ephemeral Canary replicas behind one URL:
each process has different keys and a verifier can receive inconsistent documents.

### Non-Caution development: explicit TOFU key enrollment and continuity

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

### Reading `canaryctl verify` output

`verify` is a one-shot verification of each target's **current published signed
claim**. It is not necessarily the latest network attempt: a transport failure may
leave the previous definitive claim current while that evidence remains fresh. The
signed observation, issuance and expiry times below identify exactly what was checked.
These are Canary-signed freshness fields, not an independent timestamp-authority
proof. Multiple targets are fetched and checked independently rather than as one
atomic aggregate snapshot. Use `verify-history` to replay one specific completed
attempt.

A successful development run looks like this:

```text
CANARY VERIFY
  Scope                   CURRENT PUBLISHED CLAIMS
  Started at              2026-07-21T15:02:14Z
  Targets                 ALL CONFIGURED (1)

CANARY NODE
  Trust mode              DEVELOPMENT / TOFU
  Canary attestation      SKIPPED — --insecure
  Canary workload PCRs    NOT VERIFIED
  Transport policy        HTTP ALLOWED
  Config authenticity     NOT VERIFIED — SELF-CONSISTENT ONLY
  Signing keys            NOT ATTESTED — TOFU PIN
  Identity lifecycle      UNKNOWN — UNATTESTED
  Pinned key continuity   PASS
  Pinned keys             canary-keys.json
  Node ID                 caution-canary-demo
  Config digest           sha256:000fabc4d0353229f9ea9e6e9c48da1dcf1b2095307171b0622e88cf657eeb21
  Keyset digest           sha256:14f692fc0b6cbb42ecab1760f9f6439712517365ee40ec6394d468ee314be0bd

TARGET pq-demo
  Claim                   CURRENT PUBLISHED
  Target origin           https://pq-ceremony.example
  PCR policy source       UNATTESTED CONFIG — TOFU SIGNER
  Checked at              2026-07-21T15:02:14Z
  Evidence observed at    2026-07-21T15:01:53Z
  Statement issued at     2026-07-21T15:01:54Z
  Statement expires at    2026-07-21T15:04:53Z
  Statement signatures    PASS — ED25519 + ML-DSA-65
  Statement freshness     PASS AT CHECKED TIME
  Statement/config binding PASS
  Statement/evidence link PASS — sha256:...
  Evidence replay         PASS AT OBSERVED TIME
  Target Nitro + PCRs     PASS
  Signed status           VERIFIED
  Signed reason           ALL_CHECKS_PASSED

RESULT: PASS — VERIFIED AGAINST TOFU SIGNER + UNATTESTED CONFIG
```

The important fields are:

- **Canary workload PCRs**: whether a fresh Canary attestation matched independently
  reproduced PCR0/1/2. This is deliberately absent in development mode.
- **Config authenticity**: in Caution mode, the image measurement covers the embedded
  `canary.json` and fresh attestation binds its parsed `config_digest`. In development
  mode the digest only proves internal consistency.
- **PCR policy source**: whether the target PCR0/1/2 policy came from that measured and
  attested config or from an unauthenticated development config.
- **Statement signatures**: both Ed25519 and ML-DSA-65 signatures over the canonical
  statement payload were required; one valid signature is insufficient.
- **Statement freshness**: the signed envelope was checked against the CLI's clock and
  is inside its issuance/expiry window. This does not turn a signed `STALE` target
  status into `VERIFIED`.
- **Statement/evidence link**: the signed statement's evidence digest and observation
  time matched the exact evidence bundle fetched by the CLI.
- **Evidence replay**: Nitro verification was rerun at the signed observation time so
  the certificate/document is evaluated at the time it was captured.
- **Target Nitro + PCRs**: the combined Bootproof verifier accepted the AWS chain,
  COSE signature, nonce and configured target PCR0/1/2. The CLI intentionally reports
  this combined result rather than inventing unsupported per-subcheck output.

In an attested Caution run, the node and final lines instead read:

```text
CANARY NODE
  Trust mode              ATTESTED
  Canary attestation      PASS — FRESH NONCE-BOUND
  Canary workload PCRs    PASS — PCR0/1/2
  Expected Canary PCRs    .caution/trusted_hashes.json
  Transport policy        HTTPS ONLY
  Config authenticity     PASS — MEASURED + ATTESTED
  Signing keys            PASS — ATTESTED KEYSET
  Identity lifecycle      STABLE — EXTERNAL SEED
  Pinned key continuity   PASS
  ...

TARGET pq-demo
  PCR policy source       MEASURED + ATTESTED CONFIG
  ...

RESULT: PASS — FULL ATTESTED CHAIN VERIFIED
```

An ephemeral deployment instead prints `EPHEMERAL — CURRENT PROCESS`, reports that a
restart creates new keys, and still exits successfully while the enrolled pin matches
that process.

Exit/result meanings:

- `PASS — FULL ATTESTED CHAIN VERIFIED`: the Canary identity, measured config,
  signing keys, current statements and linked target evidence all verified.
- `PASS — VERIFIED AGAINST TOFU SIGNER + UNATTESTED CONFIG`: the cryptographic chain
  is consistent with the pinned development signer and its policy, but neither is an
  independently authenticated trust root.
- `AUTHENTICATED_NEGATIVE`: the attested Canary chain is valid, but at least one
  signed current target state is not `VERIFIED`.
- `SIGNED_NEGATIVE`: the same negative result under the TOFU development signer.
- `ERROR`: a required chain link could not be fetched, parsed, matched or verified.

Only the two `PASS` results exit zero; the development result must be interpreted with
its explicit trust limitation.

Then the offline commands can verify a downloaded target statement and evidence:

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

To investigate a past probe, take its numeric ID from the history endpoint (or
the UI's History tab) and replay the exact retained statement and evidence:

```sh
canaryctl verify-history \
  --url https://canary.example.com \
  --pcrs-file .caution/trusted_hashes.json \
  --keys canary-keys.json \
  --target payments-prod \
  --attempt 42
```

This verifies the historical statement as of its signed issuance time, checks it
against the currently attested Canary config and keys, and reruns the retained
nonce-bound target evidence at its recorded observation time. A reproduced negative
result such as `INVALID_SIGNATURE` is a successful forensic replay, not a healthy
target result. The attempt timestamp and other history summary fields remain unsigned.
Transport failures and responses without a decodable attestation document have no
target evidence to replay.

## HTTP API

| Endpoint | Purpose |
|---|---|
| `GET /` | Multi-target status page |
| `GET /health` | Liveness and readiness |
| `GET /status.json` | Current state for every target plus runtime environment and binary digest |
| `GET /targets/{id}/statement` | Latest hybrid-signed statement |
| `GET /targets/{id}/evidence` | Latest Bootproof evidence bundle |
| `GET /targets/{id}/history` | Up to configured `history_limit` observations; default 1,000 |
| `GET /targets/{id}/history/{attempt_id}` | Exact retained statement and evidence for local replay |
| `GET /config.json` | Measured target configuration and digest |
| `GET /keys.json` | Ed25519 and ML-DSA-65 public keys |

All endpoints are public. Treat target names, URLs, PCRs, keys, and evidence as
public information.

`status.json.runtime.environment` is either `nitro_enclave` or `non_enclave`, based
on local `/dev/nsm` availability. `status.json.runtime.binary_digest` is the SHA-256
of the executable file opened through `current_exe()` at startup.
`status.json.runtime.identity_mode` is `stable` or `ephemeral`. These fields are
self-reported status metadata. The identity mode is independently trustworthy only
when the same value is checked in fresh signed node metadata; none of these status
fields substitutes for fresh attestation and expected PCR verification.

### `config_digest` and signed outputs

`config_digest` is `sha256:` plus the SHA-256 of the RFC 8785 canonical form of the
fully parsed `canary.json`, including defaulted global settings. It prevents a result
from being moved between different target policies or runtime configurations.

For a Caution deployment, `canary.json` is copied into the enclave image before its
PCRs are produced, so independently reproduced Canary PCR0/1/2 cover the configuration
file as part of the complete image. At runtime, canaryd separately calculates
`config_digest` from the parsed/defaulted configuration and writes it into
`/metadata.json`; Bootproofd places that metadata in signed Nitro `user_data`.
`inspect-node` checks that this attested digest equals the exact canonical
`/config.json` served to the verifier. The PCR measurement and `config_digest` are
complementary bindings, not two representations of the same hash.

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
- History rows carry the digest for correlation but remain unsigned. A history-detail
  response also returns the exact signed statement and retained evidence, which must
  be verified with `canaryctl verify-history` before it is trusted.
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
- Stable mode re-derives the same signing keys from `CANARY_MASTER_SEED`. Ephemeral
  mode generates new keys on every process start, so previously enrolled live-verifier
  pins fail closed until the operator enrolls a new output file.
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
