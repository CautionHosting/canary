# Caution Canary

Canary continuously checks public Caution/Bootproof attestation endpoints. For each
deployment, it fetches fresh nonce-bound Nitro evidence, compares PCR0/1/2 with the
policy you supplied, and publishes a short-lived result signed with Ed25519 and
ML-DSA-65.

`canaryctl` independently verifies the Canary trust input, both signatures, and the
linked Nitro evidence. A `VERIFIED` deployment means its most recent fresh evidence
matched its configured PCR0/1/2. It does not prove application correctness, traffic
routing, or coverage of replicas that are not configured separately.

## Quick start

### 1. Install `canaryctl`

```sh
cargo build --release --locked -p canaryctl
export PATH="$PWD/target/release:$PATH"
```

You need a public HTTPS Bootproof `/attestation` endpoint for each deployment. Local
use additionally needs Docker with BuildKit and linux/amd64 support.

### 2. Add a deployment

Preferred: reproduce the deployment with Caution and save its PCRs before adding it:

```sh
caution verify \
  --attestation-url https://payments.example.com/attestation \
  --save-pcrs

canaryctl deployment add \
  --config canary.json \
  --canary-id company-canary \
  --id payments-prod \
  --name "Payments production" \
  --url https://payments.example.com/attestation \
  --pcrs .caution/trusted_hashes.json
```

`--canary-id` is required only when creating `canary.json`. Add each further
deployment with a unique ID; use `--replace` to change an existing one.

For a local evaluation, use explicit deployment TOFU instead:

```sh
canaryctl deployment add \
  --config canary.json \
  --canary-id company-canary \
  --id payments-prod \
  --name "Payments production" \
  --url https://payments.example.com/attestation \
  --tofu
```

TOFU verifies fresh Nitro evidence before displaying candidate PCRs, but it does not
show that those PCRs came from reviewed or independently reproduced source. Confirm
the values carefully; scripted use requires explicit `--accept-tofu`.

### 3. Run Canary

For local development, create a signing seed and run the local image:

```sh
canaryctl identity create --env-file .env

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

Never commit `.env`; it contains the root signing seed. Local history is discarded
when the container stops.

For a Caution deployment, copy and complete `caution.hcl.template`, then run
`caution init`, commit the measured inputs, and `git push caution main`. Choose one
identity mode:

- **Ephemeral:** set `args = ["--ephemeral-identity"]` for a disposable monitor.
  A restart creates a new signing keyset.
- **Stable:** create the seed with `canaryctl identity create`, encrypt
  `CANARY_MASTER_SEED` through Locksmith, and release the required shards after
  deployment. The signing keyset survives restarts.

After deploying Canary, reproduce and save its own PCRs:

```sh
caution verify --save-pcrs
```

### 4. Enroll Canary, then verify deployments

For Caution, enroll Canary's attested public keys once:

```sh
canaryctl enroll \
  --url https://canary.example.com \
  --pcrs .caution/trusted_hashes.json \
  --keys canary-keys.json

canaryctl verify \
  --url https://canary.example.com \
  --pcrs .caution/trusted_hashes.json \
  --keys canary-keys.json
```

Keep `canary-keys.json` as an integrity-critical public trust file. Enrollment never
overwrites it. Select specific deployments with repeated `--deployment payments-prod`.

Outside Caution there is no Canary attestation. Pin the first observed keyset only
with the explicit local TOFU mode:

```sh
canaryctl enroll \
  --url http://localhost:8080 \
  --insecure \
  --keys canary-keys.json

canaryctl verify \
  --url http://localhost:8080 \
  --insecure \
  --keys canary-keys.json
```

`--insecure` skips only Canary's own attestation. It still checks both statement
signatures, deployment Nitro evidence, and deployment PCR0/1/2, but it does not
authenticate the original Canary identity or its configured deployment policy.

## Web UI

Open `https://canary.example.com/` (or `http://localhost:8080/` locally) for current
status. Each deployment has a compact overview and history view with ready-to-copy
local `canaryctl verify` commands. Statement, evidence, and history JSON remain
available as secondary inspection artifacts.

Treat the page as a status surface. Run `canaryctl` with your own PCR and key inputs
for independent verification.

## Advanced checks

Replay one retained attempt for one deployment:

```sh
canaryctl verify \
  --url https://canary.example.com \
  --pcrs .caution/trusted_hashes.json \
  --keys canary-keys.json \
  --deployment payments-prod \
  --attempt 42
```

Download and inspect a protocol artifact only when needed for debugging or evaluation:

```sh
curl -fsS https://canary.example.com/targets/payments-prod/statement -o statement.json
curl -fsS https://canary.example.com/targets/payments-prod/evidence -o evidence.json

canaryctl artifact verify-statement \
  --statement statement.json \
  --keys canary-keys.json

canaryctl artifact verify-evidence \
  --evidence evidence.json \
  --pcrs .caution/trusted_hashes/payments-prod.json
```

These are partial checks. Use `canaryctl verify` for the complete current or
historical verification path. `--verbose` shows detailed chain diagnostics; `--json`
emits one machine-readable result.

## Practical trust limits

- Expected deployment PCRs are an operator-supplied policy. TOFU establishes
  continuity, not source reproduction.
- Every result requires Ed25519 and ML-DSA-65 signatures. Nitro's upstream attestation
  chain remains AWS-rooted and classical.
- Deployment names, URLs, PCRs, keys, statements, evidence, and metadata are public.
- History is process-local and is not a durable audit log.
- Canary has no application-traffic binding, automatic replica discovery, or
  application-correctness proof.

For the protocol and exact security requirements, see
[the V0 specification](docs/canary-v0-spec.md).

## License

This workspace is licensed under `AGPL-3.0-only`; see [LICENSE.md](LICENSE.md).
