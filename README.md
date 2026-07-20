# Caution Canary

Canary is a small Rust service designed to run inside a Caution enclave. It repeatedly
challenges one or more Caution/Bootproof attestation endpoints, checks PCR0/1/2 against
a static measured configuration, and publishes short-lived statements signed with
both Ed25519 and ML-DSA-65.

V0 is a standalone POC delivered in three internal implementation phases. This
checkout contains Phase 1's offline trust core and Phase 2's working monitor,
read-only API, ephemeral history, attested metadata and node inspection. Reproducible
enclave packaging and the deployment demonstration remain Phase 3 work. The complete
design is in
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

## Full V0 bootstrap (Phase 3 deployment pending)

The following is the target evaluator flow. The monitor, migrations, inspection and
application endpoints are implemented. `caution.hcl`, final StageX packaging and the
live Caution deployment demonstration remain Phase 3 work.

The repository will contain `canary.json`, `Containerfile`, `caution.hcl`, the Rust
workspace and embedded SQLite migrations.

1. Enroll one or more targets using the preferred or TOFU flow above. Repeat the
   command with another unique target ID to monitor another enclave.

2. Generate the one root seed locally:

   ```sh
   canaryctl seed generate --env-file .env
   ```

   Never commit `.env`.

3. For the POC, create a 1-of-1 Locksmith quorum and encrypt the seed:

   ```sh
   caution secret keygen canary.asc \
     --name "Canary POC" --email canary@example.com --shoot-self-in-foot
   export KEYMAKER_URL=https://<keymaker-host>
   caution secret new canary.asc --threshold 1 --max 1
   caution secret encrypt --env-file .env CANARY_MASTER_SEED
   ```

   `--shoot-self-in-foot` creates an unencrypted development keyring. Do not use it
   for production and do not commit `canary.private.asc`.

4. Initialize and deploy the Caution app:

   ```sh
   caution init
   git push caution main
   caution verify --save-pcrs
   caution secret send-shard --keyring canary.private.asc
   ```

   The verification reproduces the deployed Canary measurement and saves the trusted
   hashes required by `send-shard`.

5. After the shard starts `canaryd`, inspect its attested bindings:

   ```sh
   canaryctl inspect-node \
     --url https://<canary-host> \
     --pcrs-file .caution/trusted_hashes.json \
     --keys-out trusted-keys.json
   ```

   `inspect-node` fetches a fresh Canary Bootproof attestation and checks that its
   signed metadata binds the served config digest and hybrid keyset digest. The config
   is part of the measured image; the Locksmith-derived runtime keys are bound through
   attestation `user_data`.

6. Download a target statement and verify it against the exact key document saved
   after its digest was checked by `inspect-node`:

   ```sh
   curl -fsS https://<canary-host>/targets/payments-prod/statement -o statement.json
   canaryctl verify-statement \
     --statement statement.json \
     --keys trusted-keys.json
   ```

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
