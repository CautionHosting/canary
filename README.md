# Caution Canary

Canary continuously checks public Caution/Bootproof attestation endpoints. For each
target, it fetches fresh nonce-bound Nitro evidence, compares PCR0/1/2 with the
policy you supplied, and publishes a short-lived result signed with Ed25519 and
ML-DSA-65.

`canaryctl` independently verifies the Canary trust input, both signatures, and the
linked Nitro evidence. A `VERIFIED` target means its most recent fresh evidence
matched its configured PCR0/1/2. Targets configured with `"e2e_mode": "caddy"` also bind
the attested Caddy certificate fingerprint to the leaf certificate from that exact
`/attestation` TLS response. It does not prove application correctness or coverage
of replicas that are not configured separately.

## Build `canaryctl`

```sh
cargo build --release --locked -p canaryctl
export PATH="$PWD/target/release:$PATH"
```

The public command surface is flat: `add-target`, `create-signing-seed`,
`save-canary-keys`, `verify`, `verify-attempt`, `watch`, `verify-statement`, and
`verify-evidence`. Legacy command and flag spellings remain hidden compatibility
aliases for one release; new scripts must use the names documented here.

You need a public HTTPS Bootproof `/attestation` endpoint for each target. Local
use additionally needs Docker with BuildKit and linux/amd64 support.

## Core flow

### 1. Configure monitored targets

Preferred: reproduce the target workload with Caution and save its PCRs before adding it:

```sh
caution verify \
  --attestation-url https://payments.example.com/attestation \
  --save-pcrs

canaryctl add-target \
  --config canary.json \
  --canary-id company-canary \
  --id payments-prod \
  --name "Payments production" \
  --attestation-url https://payments.example.com/attestation \
  --expected-pcrs .caution/trusted_hashes.json
```

`--canary-id` is required only when creating `canary.json`. Add each further target
with a unique ID; use `--replace` to change an existing one.

For an enclave-terminated Caddy target, add the opt-in binding profile:

```sh
canaryctl add-target \
  --config canary.json \
  --canary-id company-canary \
  --id payments-prod \
  --attestation-url https://payments.example.com/attestation \
  --e2e-mode caddy \
  --expected-pcrs .caution/trusted_hashes.json
```

This profile requires independently supplied PCR0/1/2; it cannot be combined with
TOFU. Missing, malformed, or unequal authenticated Caddy metadata produces an
immediate signed `FAILED / TLS_BINDING_MISMATCH`. The next successful scheduled probe
restores `VERIFIED`; there is no renewal grace period.

For a local evaluation, use explicit target TOFU instead:

```sh
canaryctl add-target \
  --config canary.json \
  --canary-id company-canary \
  --id payments-prod \
  --name "Payments production" \
  --attestation-url https://payments.example.com/attestation \
  --tofu
```

TOFU verifies fresh Nitro evidence before displaying candidate PCRs, but it does not
show that those PCRs came from reviewed or independently reproduced source. Confirm
the values carefully; scripted use requires explicit `--accept-tofu`.

### 2. Run Canary

For local development, create a signing seed and run the local image:

```sh
canaryctl create-signing-seed --output .env

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

For a Caution deployment, copy `caution.hcl.template` to `caution.hcl`, set its public
source URL and HTTPS domain, then choose one identity mode:

- **Ephemeral:** set `args = ["--ephemeral-identity"]` for a disposable monitor.
  A restart creates a new signing keyset.
- **Stable:** keep the `env::vault("CANARY_MASTER_SEED")` block and prepare the
  encrypted seed:

  ```sh
  canaryctl create-signing-seed --output .env
  caution secret keygen canary.asc \
    --name "Canary POC" --email canary@example.com --shoot-self-in-foot
  export KEYMAKER_URL=https://keymaker.example.com
  caution secret new canary.asc --threshold 1 --max 1
  caution secret encrypt --env-file .env CANARY_MASTER_SEED
  ```

  This 1-of-1 key is for evaluation only. Use separate protected shard holders in
  production.

Initialize after selecting the identity mode. Commit `canary.json`, `caution.hcl`,
deployment metadata, and—only in stable mode—the public quorum bundle and encrypted
seed. Never commit `.env` or `canary.private.asc`.

```sh
caution init
git add canary.json caution.hcl .caution/deployment.json
# Stable mode only:
git add .caution/quorum-bundle.json .caution/secrets/CANARY_MASTER_SEED.asc
git commit -m "Configure Canary deployment"
git push caution main
caution verify --save-pcrs
```

In stable mode, release the seed only after verification:

```sh
caution secret send-shard --keyring canary.private.asc
```

The stable signing keyset survives restarts. An ephemeral Canary creates a new keyset
and requires a newly saved key pin after every restart.

### 3. Inspect current status

Open `https://canary.example.com/` (or `http://localhost:8080/` locally). Targets
and their current state appear first, followed by independent verification commands
and Canary runtime details.

Each target inspector shows authenticated observed PCR0/1/2 beside the configured
expected values and their match result. Retained history rows can expand the same
measurements for that exact attempt. Statement, raw evidence, decoded claims, and
history JSON remain available as secondary inspection artifacts.

![Canary status dashboard](readme_images/canaryd.png)

![Target compact overview](readme_images/probe-demo.png)

![Target history view](readme_images/history-demo.png)

For a reported Nitro runtime, the browser evidence check starts as `NOT RUN` and
makes no attestation request until selected. It generates a fresh nonce, uses
WebCrypto to check certificate signatures to the pinned AWS Nitro root, certificate
dates, COSE ES384, and nonce binding, then displays observed Canary PCR0/1/2 as
`EVIDENCE CHECKED`.

This convenience check does not implement the full X.509 policy validation used by
`canaryctl` and does not compare independently supplied expected Canary PCR policy.
The `/dev/nsm` result is self-reported, and the page and JavaScript come from the same
origin being checked.

### 4. Verify independently

For Caution, verify Canary and save its authenticated public keys once:

```sh
canaryctl save-canary-keys \
  --canary-url https://canary.example.com \
  --expected-pcrs .caution/trusted_hashes.json \
  --output canary-keys.json

canaryctl verify \
  --canary-url https://canary.example.com \
  --expected-pcrs .caution/trusted_hashes.json \
  --trusted-keys canary-keys.json
```

`save-canary-keys` writes `canary-keys.json` only after the fresh Canary attestation,
expected PCR0/1/2, and attested config/key binding verify successfully.

Keep `canary-keys.json` as an integrity-critical public trust file. The command never
overwrites it. Select specific targets with repeated `--target payments-prod`.
Successful verification displays authenticated observed PCR0/1/2 in the normal
output. `--verbose` displays full observed and expected values; `--json` provides the
same values and match booleans under `pcrs`. Results without authenticated evidence
emit `pcrs: null`. Caddy-profile results additionally expose the signed `tls`
comparison. `canaryctl verify` independently replays Nitro evidence and expected-PCR
policy before accepting either the successful binding or a binding mismatch.

The local Docker flow has no Canary attestation. Pin its first observed keyset only
with the explicit local TOFU mode:

```sh
canaryctl save-canary-keys \
  --canary-url http://localhost:8080 \
  --skip-canary-attestation \
  --allow-http \
  --output canary-keys.json

canaryctl verify \
  --canary-url http://localhost:8080 \
  --skip-canary-attestation \
  --allow-http \
  --trusted-keys canary-keys.json
```

`--skip-canary-attestation` selects explicit TOFU; `--allow-http` separately permits
the local HTTP origin. Verification still requires the saved Canary keys and checks
both signatures on every result. For a `VERIFIED` result it also checks the linked
target Nitro evidence and PCR0/1/2. It does not authenticate the original Canary
identity or configured target policy.

## Optional webhook watcher

The external watcher is optional. Run it when different Canary targets need
different notification routes:

```sh
cp canary-watch.example.json canary-watch.json
export PQ_WEBHOOK_SECRET="$(openssl rand -base64 32)"
canaryctl watch \
  --config canary-watch.json \
  --skip-canary-attestation \
  --allow-http-canary \
  --allow-http-webhooks
```

Each target can fan out to multiple webhooks. The watcher performs the same complete
live verification as `canaryctl verify` before sending a target event; it does not
probe target attestation endpoints itself. It also sends signed heartbeats and
Canary-wide outage or trust-failure events. Webhook secrets are base64-encoded
32-byte HMAC keys loaded from the named environment variables and never belong in
the config file. On a normal host, inject them with its secret manager. If the
watcher is deployed as its own Caution application, expose each name through
`env::vault(...)` and protect the encrypted values with Locksmith; this does not
change the Canary deployment.

`canary-watch.json` is deliberately separate from measured `canary.json`, so changing
alert routing does not rebuild the Canary enclave. Relative PCR and key paths resolve
from the watcher config's directory. Restart the watcher after editing its config.
For local testing, `--allow-http-webhooks` permits HTTP receivers. If Canary itself is
local, omit `canary.pcrs`, pass `--skip-canary-attestation`, and add
`--allow-http-canary` when its origin is HTTP. None of these local-only flags belongs
in production.

Every POST contains `schema_version`, `event`, `event_id`, `timestamp`, `canary`, and
`data`. Verify the receiver-facing headers against the exact request body:

- `X-Canary-Event-Id`
- `X-Canary-Timestamp`
- `X-Canary-Signature: v1=<hex HMAC-SHA256(timestamp + "." + body)>`

Retries reuse the same event ID, timestamp, body, and signature. Target events are
`target.status_changed`, `target.read_failed`, and `target.read_recovered`; watcher
events are `canary.unavailable`, `canary.verification_failed`, `canary.recovered`,
and `watcher.heartbeat`.

## Advanced checks

Replay one retained attempt for one target:

```sh
canaryctl verify-attempt \
  --canary-url https://canary.example.com \
  --expected-pcrs .caution/trusted_hashes.json \
  --trusted-keys canary-keys.json \
  --target payments-prod \
  --attempt 42
```

Download and inspect a protocol artifact only when needed for debugging or evaluation:

```sh
curl -fsS https://canary.example.com/targets/payments-prod/statement -o statement.json
curl -fsS https://canary.example.com/targets/payments-prod/evidence -o evidence.json

canaryctl verify-statement \
  --statement statement.json \
  --trusted-keys canary-keys.json

canaryctl verify-evidence \
  --evidence evidence.json \
  --expected-pcrs .caution/trusted_hashes.json
```

These are partial checks. Use `canaryctl verify` for complete current verification or
`canaryctl verify-attempt` for one retained attempt. `--verbose` shows detailed chain
diagnostics; `--json` emits one machine-readable result. `verify-evidence` is intentionally
attestation/PCR-only: an offline evidence bundle has no TLS connection to compare.

The ignored live Caddy acceptance test uses the production probe path and requires an
independently trusted PCR file:

```sh
CADDY_E2E_URL=https://app.example.com/attestation \
CADDY_E2E_PCRS=/path/to/trusted_hashes.json \
cargo test --locked -p canaryd --test caddy_nitro_live -- --ignored --nocapture
```

## Practical trust limits

- Expected target PCRs are an operator-supplied policy. TOFU establishes
  continuity, not source reproduction.
- Every result requires Ed25519 and ML-DSA-65 signatures. Nitro's upstream attestation
  chain remains AWS-rooted and classical.
- Target names, URLs, PCRs, keys, statements, evidence, and metadata are public.
- History is enclave/container-local and is not a durable audit log.
- Caddy mode binds only the exact attestation HTTPS connection it observed. It does
  not discover replicas or prove application correctness.
- Multiple network vantage points require separate Canary deployments with the same
  target policy. Traffic quarantine remains an external action driven by the signed
  failure or watcher event.

For the protocol and exact security requirements, see
[the V0 specification](docs/canary-v0-spec.md).

## License

This workspace is licensed under `AGPL-3.0-only`; see [LICENSE.md](LICENSE.md).
