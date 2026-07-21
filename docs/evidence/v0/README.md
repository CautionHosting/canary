# Canary V0 evaluator evidence record

This directory stores public, reproducible Phase 3 evidence. It is an evidence index,
not a claim that the POC has been deployed or that every criterion has passed.

Never commit or attach a master seed, `.env`, private Keymaker/Locksmith keyring,
plaintext shard, access code, credential, session material, private target URL or raw
operator log containing any of those values. PCRs, public config, public keysets,
attestations and statements are public V0 outputs, but review them for unrelated
infrastructure metadata before publication.

## Record layout

Create one directory per evaluation, named `YYYY-MM-DD-<commit>-<evaluator>`, with
only public files:

```text
YYYY-MM-DD-<commit>-<evaluator>/
  README.md                 # completed record below
  source.txt                # commit, clean-tree status, repository URL
  inputs.sha256             # Containerfile, Cargo.lock, canary.json, HCL and StageX inputs
  build-a.log               # no-cache build; demonstrates compilation was not cached
  build-b.log               # independently repeated no-cache build
  canary-a.oci.tar.sha256
  canary-b.oci.tar.sha256
  repro.txt                 # cmp exit status and OCI digest equality
  pcrs/                     # public, separately verified target and Canary PCR files
  public/                   # config.json, keys.json, statements, evidence, histories
  commands/                 # stdout/stderr and exit codes, scrubbed of secrets
  scenarios.md              # completed scenario matrix
```

Record source commit (full SHA), source remote, evaluator and UTC time; exact StageX
image digests; hashes of `Containerfile`, `Cargo.lock`, `canary.json`, `caution.hcl`
and any vendored inputs; both normalized OCI SHA-256 values; deployed Canary and each
target PCR0/1/2; public URLs/outputs; and every command plus exit code. State whether
each PCR file came from `caution verify --save-pcrs` for a reproduced target or from a
TOFU demonstration. Do not label TOFU as independently reproduced.

## Required command-result index

The completed record links to scrubbed output and exit status for:

- `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings`, and
  `cargo test --workspace --locked`.
- `scripts/validate-deployment.sh` and `caution apps build --no-cache`.
- Both clean Linux amd64 OCI builds, their `cmp` result and OCI SHA-256.
  The build logs must show `SOURCE_DATE_EPOCH=1`, timestamp rewriting, and disabled
  Buildx provenance metadata for the byte-level comparison.
- `caution init`, deployment push, and `caution verify --save-pcrs` for Canary and
  each preferred-flow target.
- `canaryctl enroll` with independently verified Canary PCRs.
- Download plus offline `canaryctl artifact verify-statement` and
  `artifact verify-evidence` for each target. The saved public keys must be the exact
  document verified by `enroll`.
- Standalone source/dependency audit showing no STEVE dependency/configuration and no
  direct NSM/Nitro attestation-generation path.

Interactive passkey, Keymaker and shard actions may be recorded as an operator
attestation with UTC time and result, but never by saving private material or a replay
of a credential-bearing terminal session.

## Scenario matrix

Use one row per run; link the public artifact, scrubbed command output or controlled
fixture that supports it. `Pass` requires the stated result, `Fail` records the
observed result and next action, and `Not run` is not completion evidence.

| Scenario | Expected result | Result | Evidence link |
|---|---|---|---|
| Two configured targets | Separate per-target statements/evidence/history |  |  |
| Fresh matching document | `VERIFIED` |  |  |
| Wrong PCR | Immediate `FAILED` |  |  |
| Replayed document/wrong nonce | Never `VERIFIED` |  |  |
| Invalid certificate/signature/format | Immediate `FAILED` |  |  |
| One/two transport failures while fresh | Success retained with warning |  |  |
| Three failures after TTL | `UNREACHABLE` |  |  |
| Expiry without persistent outage | `STALE` |  |  |
| Valid probe after failure/outage | Immediate recovery |  |  |
| Canary restart | History wiped, `PENDING`, immediate probes |  |  |
| Metadata/config/key mismatch | `enroll` rejects it |  |  |
| Config redeploy | New config digest/measurement; stable signer with retained seed |  |  |
| SSRF controls | Prohibited address, redirect, oversized body and rebinding rejected |  |  |
| TOFU demonstration | Explicit weaker-source-assurance warning retained |  |  |

## Normative acceptance traceability

Link each spec criterion to the applicable artifact above. The canonical requirements
are [spec §17](../../canary-v0-spec.md#17-acceptance-criteria); do not replace these
links with an evaluator assertion.

| Criterion | Required evidence link |
|---:|---|
| [1](../../canary-v0-spec.md#17-acceptance-criteria) | Two-target public outputs and independent histories |
| [2](../../canary-v0-spec.md#17-acceptance-criteria) | Fresh matching evidence scenario |
| [3](../../canary-v0-spec.md#17-acceptance-criteria) | Replay/wrong-nonce scenario |
| [4](../../canary-v0-spec.md#17-acceptance-criteria) | PCR/certificate/signature/format scenarios |
| [5](../../canary-v0-spec.md#17-acceptance-criteria) | Transport, TTL and `UNREACHABLE` scenario |
| [6](../../canary-v0-spec.md#17-acceptance-criteria) | One-probe recovery scenario |
| [7](../../canary-v0-spec.md#17-acceptance-criteria) | Expired/single-signature offline-verifier test |
| [8](../../canary-v0-spec.md#17-acceptance-criteria) | Independent `enroll` result |
| [9](../../canary-v0-spec.md#17-acceptance-criteria) | Before/after config deployment record |
| [10](../../canary-v0-spec.md#17-acceptance-criteria) | Restart lifecycle record |
| [11](../../canary-v0-spec.md#17-acceptance-criteria) | SSRF/DNS-rebinding evidence |
| [12](../../canary-v0-spec.md#17-acceptance-criteria) | Source/dependency audit |
| [13](../../canary-v0-spec.md#17-acceptance-criteria) | Two OCI builds and `caution verify` |
| [14](../../canary-v0-spec.md#17-acceptance-criteria) | README/CLI TOFU warning capture |
