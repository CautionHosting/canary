# Caution Canary

Canary is a small Rust service designed to run inside a Caution enclave. It repeatedly
challenges one or more Caution/Bootproof attestation endpoints, checks PCR0/1/2 against
a static measured configuration, and publishes short-lived statements signed with
both Ed25519 and ML-DSA-65.

V0 is a standalone POC delivered in three internal implementation phases. This
checkout contains the offline trust core, working monitor, read-only API, ephemeral
history, attested metadata and node inspection. The Phase 3 evaluator flow below
defines the required reproducibility, deployment and live-evidence gates; it is not
evidence that a live deployment has occurred. The complete design is in
[docs/canary-v0-spec.md](docs/canary-v0-spec.md).

## Read this before enrolling PCRs

There are two valid enrollment workflows, but they provide different assurance.

### Preferred: independently verify first

Run Caution's reproduction check and save its verified PCRs:

```sh
caution verify \
  --attestation-url https://payments.example.com/attestation \
  --save-pcrs
```

Then import `.caution/trusted_hashes.json`:

```sh
canaryctl config add \
  --config canary.json \
  --node-id caution-canary-demo \
  --id payments-prod \
  --name "Payments production" \
  --attestation-url https://payments.example.com/attestation \
  --pcrs-file .caution/trusted_hashes.json
```

### Fast POC: capture the live values

```sh
canaryctl capture \
  --config canary.json \
  --node-id caution-canary-demo \
  --id payments-prod \
  --name "Payments production" \
  --attestation-url https://payments.example.com/attestation
```

**This is trust on first use (TOFU).** The command verifies fresh Bootproof evidence,
shows the observed PCRs, and asks before recording them. It proves only that future
observations continue to match the values explicitly enrolled from that live endpoint.

It does **not** prove that those values match reviewed or independently reproduced
source. Run `caution verify` first for that stronger workflow. Canary never silently
updates an enrolled PCR baseline.

## V0 system target

- `canaryd`: enclave service, scheduler, Bootproof verifier, signer, SQLite
  history, read-only API and minimal status page.
- `canaryctl`: config creation/TOFU capture, seed generation and offline statement
  and evidence verification, plus attested node inspection.
- Bootproofd: Caution-provided `/attestation` for the Canary node itself.
- Locksmith: injects one random 32-byte `CANARY_MASTER_SEED`.
- StageX: produces the pinned, reproducible Rust application image.
- SQLite: lives under `/tmp` inside the enclave and is wiped on enclave restart.

One Canary node can monitor multiple enclaves. Add each target to `canary.json` with a
unique ID. Every target receives an independent state, evidence bundle and signed
statement. A load-balanced URL still samples only the replica that answers; enumerate
replica endpoints when coverage of each replica matters.

Canary uses normal Bootproof HTTP requests and the verifier side of `bootproof-sdk`.
It does not call `/dev/nsm`, Nitro drivers or NSM APIs directly.

## Exact V0 claim

A `VERIFIED` `caution.canary.pcr-match.v0` statement means:

> At the stated time, this Canary obtained valid fresh nonce-bound AWS Nitro evidence
> from the target, and PCR0/1/2 matched the values embedded in the Canary's measured
> configuration.

It does not prove source reproduction unless the preferred enrollment workflow was
completed. It also does not prove normal traffic reached the same enclave, cover every
load-balanced replica, assess application correctness, or provide uninterrupted
history between probes.

The Canary statements use a hybrid Ed25519 + ML-DSA-65 envelope. They should be called
hybrid post-quantum signed, not quantum-proof, because Nitro's attestation chain is
still classical.

## Operator commands

The commands available now are `config add`, `capture`, `seed generate`,
`inspect-node`, offline `verify-statement`, and offline `verify-evidence`. Check the
exact interface with `canaryctl --help`.

Offline statement verification requires public keys obtained through a separately
trusted channel; fetching the statement and its keys from the same unverified node
would prove only self-consistency:

```sh
canaryctl verify-statement \
  --statement statement.json \
  --keys trusted-keys.json
```

Evidence verification likewise requires PCR0/1/2 obtained through a separately
trusted channel:

```sh
canaryctl verify-evidence \
  --evidence evidence.json \
  --pcrs-file .caution/trusted_hashes.json
```

The bundle's `observed_at` selects the certificate-validation time so historical
evidence can be reproduced offline. A standalone bundle does not prove that its nonce
or observation time was fresh. For freshness, also verify a trusted hybrid statement
that binds the same `evidence_digest` and `observed_at`.

Public interoperability vectors for both artifacts live under
[`crates/canary-core/tests/data`](crates/canary-core/tests/data/README.md).

## Phase 2 runtime contract

`canaryd` reads the measured config from `/app/canary.json`, reads only
`CANARY_MASTER_SEED` for its root secret, writes Bootproof `user_data` to
`/metadata.json`, stores current-lifetime diagnostics in
`/tmp/canary/canary.sqlite3`, and listens on port 8080. It starts every target as a
signed `PENDING` result, then probes immediately and every 60 seconds with bounded
jitter and concurrency.

The target client permits HTTPS only, resolves and pins a fresh public address for
every probe, rejects mixed or prohibited DNS answers and redirects, and bounds
connection time, total time and response size. A transport failure does not replace
a still-fresh definitive statement; the warning is exposed separately.

## Full V0 evaluator flow

This is the only Phase 3 operator flow. It is deliberately a transcription of the
normal Caution and Canary commands, not a second deployment system. Substitute real,
separately verified values for every `<...>` placeholder. Do not treat the examples as
live evidence.

### Preconditions and pauses

- A public source URL and Canary domain/URL, two distinct public target attestation
  URLs, and their independently reproduced PCR0/1/2 files are required for the
  acceptance POC. Before `caution init`, create a reviewed root `caution.hcl` from
  `caution.hcl.template` and replace its source/domain placeholders; do not deploy the
  template unchanged. `canary.json.template` illustrates the schema only; let
  `canaryctl config add` create the measured root `canary.json`.
- A Linux amd64 builder with Docker Buildx, the Caution CLI, a registered/logged-in
  Caution account, deployment SSH access, a FIDO2/WebAuthn passkey, Keymaker URL and
  authorized operator credentials are required for deployment. `caution register`,
  `caution login`, `caution init`, and Locksmith shard handling pause for operator
  control; do not wrap them in CI or a script.
- A controlled replay source and a controlled target outage are required to run the
  replay, outage, expiry and recovery scenarios. They cannot be demonstrated against
  an arbitrary production target.
- No current checkout can complete the live steps without those external inputs. Keep
  the resulting secret material, private keyring and credentials outside Git.

### 1. Enroll two targets

Preferred enrollment uses target PCRs that were reproduced and verified separately.
Save each target's `caution verify --save-pcrs` output under its target ID before the
next verification overwrites it. The deployment validator checks these public
provenance files against the measured config:

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

For a separate demonstration only, `capture` creates a TOFU baseline. It verifies a
fresh live document and asks for confirmation, but the source assurance is weaker:
the enrolled PCRs have not thereby been reproduced from reviewed source. Do not use
this output as the preferred POC baseline.

```sh
canaryctl capture \
  --config canary-tofu-demo.json --node-id caution-canary-tofu-demo \
  --id tofu-target --name "TOFU demonstration only" \
  --attestation-url https://tofu.example.com/attestation
```

### 2. Generate and encrypt the one seed

```sh
canaryctl seed generate --env-file .env

# PAUSE: Keymaker URL, passkey and authorized Locksmith operator required.
caution secret keygen canary.asc \
  --name "Canary POC" --email canary@example.com --shoot-self-in-foot
export KEYMAKER_URL=https://<keymaker-host>
caution secret new canary.asc --threshold 1 --max 1
caution secret encrypt --env-file .env CANARY_MASTER_SEED
```

This POC-only 1-of-1 quorum uses an unencrypted development keyring. Never commit
`.env` or `canary.private.asc`; do not use this quorum arrangement for production.

### 3. Initialize, validate, build and reproduce

Initialize the Caution deployment under operator control, then run the repository
gates. The reproducibility script makes two no-cache Linux amd64 OCI exports with
`SOURCE_DATE_EPOCH=1` and `rewrite-timestamp=true`, disables non-deterministic Buildx
provenance metadata, compares the exports byte-for-byte and prints their SHA-256
values. The local Caution build is an additional packaging gate.
Record the commands, input digests, build logs and hashes in
[`docs/evidence/v0/`](docs/evidence/v0/README.md); do not record a seed, credential,
private keyring or plaintext shard.

```sh
# PAUSE: passkey, Caution account, deployment SSH key and public domain required.
caution init
./scripts/validate-deployment.sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
./scripts/check-reproducible.sh
caution apps build --no-cache
```

The two-build result is only a local determinism check. A separate evaluator and
`caution verify` are needed before making an independent reproducibility claim.

### 4. Commit, deploy and verify the Canary

Commit only measured/public inputs, the Caution deployment record, quorum bundle and
encrypted secret files. The push is the deployment operation.

```sh
git add canary.json Containerfile caution.hcl .caution/deployment.json \
  .caution/quorum-bundle.json .caution/secrets/CANARY_MASTER_SEED.asc \
  .caution/trusted_hashes
git commit -m "Deploy Canary V0 POC"
git push caution main

caution verify --save-pcrs
# PAUSE: submit the shard only under authorized Keymaker/operator control.
caution secret send-shard --keyring canary.private.asc
```

`caution verify --save-pcrs` reproduces the deployed Canary measurement and produces
the PCR file required to independently inspect its attestation. It does not replace
the preferred enrollment verification performed for each target.

### 5. Inspect, retrieve and verify offline

After the shard starts `canaryd`, inspect its fresh attestation before trusting the
served keys. Then download artifacts and verify both independently, from local files:

```sh
canaryctl inspect-node \
  --url https://<canary-host> \
  --pcrs-file .caution/trusted_hashes.json \
  --keys-out trusted-keys.json

curl -fsS https://<canary-host>/targets/payments-prod/statement -o statement.json
curl -fsS https://<canary-host>/targets/payments-prod/evidence -o evidence.json
canaryctl verify-statement --statement statement.json --keys trusted-keys.json
canaryctl verify-evidence --evidence evidence.json \
  --pcrs-file .caution/trusted_hashes/payments-prod.json
```

`inspect-node` checks the signed binding between the measured config digest and exact
hybrid keyset digest. Its `trusted-keys.json` is the separately trusted input for the
offline statement check; downloading statement and keys from an uninspected node proves
only self-consistency.

### 6. Record the failure and lifecycle matrix

Run and record every scenario against controlled fixtures or explicitly authorized
targets. A command failure is evidence of a failed gate, not a reason to weaken it.

| Scenario | Required observable result |
|---|---|
| Two independent targets | Separate statements, evidence and histories; no aggregate claim |
| Matching fresh evidence | `VERIFIED` |
| PCR/certificate/signature/format failure | Immediate `FAILED` |
| Replay or wrong nonce | Never `VERIFIED` |
| One or two transport failures while fresh | Existing fresh success remains, with a warning |
| Three transport failures after success expiry | `UNREACHABLE` |
| Expired result without persistent outage | `STALE` |
| One later valid probe | Immediate recovery to `VERIFIED` |
| Canary restart | History erased, `PENDING`, then immediate probes |
| Metadata/config/key mismatch or prohibited network target | Inspection or request fails closed |

The POC intentionally has no PostgreSQL, webhooks, webhook secret, OpenTimestamps,
customer countersignature, live configuration API or durable history. A config change
is a source change: commit it and deploy a newly measured Canary image.

## Read-only endpoints

| Endpoint | Purpose |
|---|---|
| `GET /` | Multi-target status page |
| `GET /health` | Liveness and readiness status |
| `GET /status.json` | Current states |
| `GET /targets/{id}/statement` | Latest hybrid-signed statement |
| `GET /targets/{id}/evidence` | Latest Bootproof evidence bundle |
| `GET /targets/{id}/history` | Current-enclave-lifetime history |
| `GET /config.json` | Measured config and digest |
| `GET /keys.json` | Hybrid public key set |

The read-only API is public in V0. Target names, URLs, PCRs, public keys and evidence
must therefore be treated as public information.

Canary's own `POST /attestation` is served separately by Caution Bootproofd; it is not
part of the `canaryd` router.

## License

This workspace is distributed under `AGPL-3.0-only`; see [LICENSE.md](LICENSE.md).
That choice is explicit because the pinned `bootproof-sdk` source is AGPL-3.0.
