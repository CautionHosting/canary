# Caution Canary — Product Brief

IMPORTANT LLM INSTRUCTION: always check the latest version and comments at https://codeberg.org/caution/internal/issues/28 


## Thesis

**Caution Canary turns point-in-time enclave verification into an always-on assurance service.** It continuously checks that a customer application remains reachable inside genuine confidential-compute hardware, matches an explicitly approved release reproducible from source, and—where STEVE is enabled—controls the key used for application traffic.

Canary is initially operated by Caution. Over time, customers, auditors and independent organizations can run verifier nodes and co-sign results.

## Problem

Remote attestation is usually performed once: at deployment, secret release or connection time. Afterward, customers lack a simple answer to: **“Is the application serving users now still the exact application we reviewed and approved?”**

Ordinary uptime monitoring only proves that an endpoint responds. Standard attestation proves that some measured workload exists, but usually does not connect it to complete, reviewable source. Neither produces a durable, externally consumable record of an application’s verified state.

## Product

For every monitored deployment, Canary maintains a customer-approved verification policy containing the source commit, build inputs, expected measurements, deployment endpoints and required security properties. Caution reproduces the release once, then independent verifier workers periodically:

1. Send a fresh nonce to the application’s attestation endpoint.
2. Validate the hardware certificate chain, signature, freshness and measurements.
3. Compare the deployment against the approved release—not whatever release the deployment currently claims is valid.
4. Where STEVE is enabled, prove that the attested enclave controls the key used for an encrypted application session.
5. Emit a short-lived, signed verification result and alert on mismatch, staleness or loss of coverage.

Customers receive a dashboard, public or private verification URL, API, webhooks and historical evidence. Statuses distinguish `VERIFIED`, `FAILED`, `UNREACHABLE` and `STALE`; a cryptographic mismatch is not presented as ordinary downtime.

## Independent client verification

Canary provides the independent reference channel used by Caution widgets, SDKs and STEVE:

- The application’s fresh attestation says **what the enclave claims to be running**.
- Canary’s signed statement says **what that application is approved to run and what external verifiers recently observed**.

Before displaying a verified state or establishing a STEVE session, a client retrieves a signed, expiring Canary statement, verifies it using pinned verifier keys, requests fresh evidence directly from the application, and compares the application identity, domain, measurements and STEVE service key. This prevents the application’s own attestation endpoint from defining both the observed state and the policy against which it is judged.

Statements include the application and domain identity, approved release and manifest digest, expected measurements, attested service-key fingerprint, evidence digest, observation and expiry times, verifier identities and signatures. Clients may cache an unexpired statement if Canary is temporarily unavailable.

Initially, Caution signs these statements. The envelope supports multiple signatures from the beginning so customers can later require a configurable quorum of Caution, customer, auditor or independent verifier nodes without changing the client protocol.

A badge alone is not a security boundary: application-hosted JavaScript can be replaced by a compromised host. High-assurance delivery therefore uses an independently hosted cross-origin widget, a signed and enforced service worker, a browser extension, or an independently distributed SDK.

## Relationship to the Reproducer

Canary and the Reproducer are separate, modular services with a signed interface between them:

- The **deployment builder** produces the enclave image that will run.
- The **Reproducer** independently builds the same immutable source commit and pinned inputs, then signs a reproduction statement containing the resulting measurements, manifest digest and build provenance.
- The **release policy** records which reproduced release the customer authorizes.
- **Canary** consumes that policy and continuously compares live evidence against it; Canary does not build applications itself.

When a user runs `git push caution main`, Caution can start the deployment build and an isolated reproduction build in parallel. The application remains `PENDING_REPRODUCTION` until the independent result arrives. If the measurements match and the release is authorized, Canary begins monitoring automatically. Higher-assurance customers may additionally block traffic or secret release until reproduction succeeds.

Reproduction must be independent in more than name: it should run on separate infrastructure and credentials, fetch the immutable commit itself, and use pinned build inputs. A successful reproduction proves that source and inputs produce particular measurements; it does **not** prove that the source is safe or that the release was authorized. Therefore, Canary must not automatically approve every successfully reproduced `git push`. Authorization comes from an explicit customer signature or a narrowly defined release policy.

Canary also works without Caution’s hosted Reproducer by accepting customer-supplied or third-party signed reference statements. In that mode it can prove that production matches approved measurements, but it must not claim independent source reproduction. The statement format supports multiple reproducers later, allowing customers to require a reproduction quorum without changing Canary.

### Hosted Reproducer backend: ReprOS

Caution’s hosted Reproducer uses [ReprOS](https://codeberg.org/stagex/repros) as the isolated build backend. ReprOS is a deterministic, minimal, immutable Linux distribution designed for reproducing container builds; a `git push` triggers a one-time-use QEMU VM that runs the build command and signs outputs with a key held on the host, not in the build VM. This gives the Reproducer ephemeral isolation, a minimal attack surface, and bit-for-bit deterministic outputs — satisfying the independence requirement above without Caution building custom build-isolation infrastructure.

ReprOS does not natively produce enclave measurements or Canary-format statements, so a thin Caution adapter layer bridges the two: a Caution-provided build script produces the EIF and an unsigned reproduction statement inside the VM, ReprOS’s native signing flow signs it, and the adapter re-wraps the result as a JWS and POSTs it to Canary’s reproducer endpoint. Reproducer signing keys are deliberately separate from Canary’s own status-signing keys so a compromise of one principal cannot forge the other’s evidence.

The detailed hosted Reproducer architecture, statement format and key-separation model
are post-V0 work. V0 uses measured static PCR configuration and does not accept
customer-supplied approval statements or require a hosted Reproducer.

## Customer value

- **Continuous assurance:** Know when production stops matching the reviewed release.
- **Independent evidence:** Give users, auditors and counterparties signed results they can verify without trusting the deployment operator.
- **Faster response:** Alert immediately on unauthorized releases, debug mode, invalid attestations or measurement drift.
- **Commercial trust layer:** Let wallets, oracles, payment systems, AI agents and sensitive-data applications expose verifiability as a product property.
- **Policy enforcement later:** Use Canary results to gate Locksmith secrets, revoke access or reject traffic after verification failure.

## What Caution must own vs. leverage

| Capability | Approach | Why |
|---|---|---|
| Reproducible release verification | **Build in Caution** | This is Caution’s core source-to-runtime guarantee. |
| Reproducer-to-Canary interface | **Build as a signed, open format** | Keeps both services independent and allows customer or third-party reproducers later. |
| Approved release policy and signatures | **Build in Caution** | Prevents a compromised deployment from redefining what “expected” means. |
| Nitro/Bootproof verification | **Build from the existing Caution verifier** | Keeps CLI and managed verification behavior identical and auditable. |
| STEVE traffic binding | **Build in Caution/STEVE** | Polling `/attestation` alone does not prove that the same enclave serves application traffic. |
| Signed result format and canonical status | **Build in Caution** | These are security claims, not generic monitoring events. |
| Alerts, on-call and incident workflows | **Integrate OneUptime** | OneUptime already provides workflows, escalation, incidents and notification channels. |
| Ordinary operational status pages | **Integrate OneUptime initially** | Avoid rebuilding commodity reliability tooling; keep cryptographic detail on a Caution verification page. |
| Transparency log | **Reuse the Sigstore/Rekor model after MVP** | Append-only evidence and external witnesses improve auditability without inventing a new ledger. |
| Continuous-attestation patterns | **Learn from Keylime** | Keylime validates the verifier/registrar/policy model, but targets TPM/host integrity rather than reproducible enclave applications. |
| Kubernetes attestation and secret gating | **Interoperate or learn from Contrast/Trustee** | Their manifest and admission models are useful, but they are cluster-local authorization systems rather than external verification products. |

**Recommendation:** use OneUptime as Canary’s operational shell, not its security core. Canary sends state transitions to OneUptime for alerts and incidents. OneUptime must never decide whether an enclave is cryptographically verified. Do not fork or embed its full platform for the MVP.

Canary exposes a generic signed event webhook with stable reason codes such as `PCR_MISMATCH`, `ATTESTATION_INVALID`, `REPRODUCTION_MISMATCH`, `UNREACHABLE` and `RESULT_STALE`. OneUptime can initially route these events to PagerDuty, Slack, email and other incident systems. Direct native integrations can follow where customer demand justifies them; Canary should not embed PagerDuty-specific logic into its verification core.

## Differentiation

Periodic attestation is not new. Canary’s differentiation is the combination:

1. **Approved source → reproducible full-stack build → expected measurement.** Caution verifies the application, runtime, OS and kernel—not only an image supplied by the operator.
2. **Always-on external verification.** Results are refreshed, signed, timestamped and consumable by humans and software.
3. **Service binding through STEVE.** Canary can verify control of the key used on the application path, not merely the existence of a good enclave behind a separate attestation route.
4. **Independent policy distribution.** Widgets, SDKs and STEVE receive approved reference values from Canary rather than trusting the application to define its own expected state.
5. **General-purpose product.** Unlike service-specific client verification such as Tinfoil’s AI stack, Canary covers customer-operated applications and BYOC deployments.
6. **Progressive trust reduction.** It can begin as a Caution-managed service and evolve into a multi-operator verifier network without requiring a blockchain or token.

Compared with adjacent systems:

- **OneUptime** monitors availability and operations; Canary verifies cryptographic deployment state.
- **Keylime** continuously attests hosts and runtime files; Canary connects approved application source to enclave production state.
- **Contrast and Trustee** use attestation for cluster admission or secret release; Canary provides external, continuously refreshed assurance.
- **Tinfoil** strongly verifies its own AI connections; Canary is an infrastructure product for arbitrary third-party applications.
- **Sigstore/Rekor** records supply-chain evidence; Canary adds live runtime evidence and can reuse its transparency pattern.

## MVP

- One declared enclave per deployment
- Parallel deployment and isolated reproduction builds after `git push caution main`
- Signed reproduction statement and customer-approved release policy with source commit and expected PCRs
- Verification every 60 seconds; results expire after 180 seconds
- Fresh-nonce Nitro verification from at least two Caution-controlled regions
- Signed verification results and retained evidence digests
- Signed, expiring client statements with an envelope supporting multiple verifier signatures
- `VERIFIED`, `FAILED`, `UNREACHABLE` and `STALE` states
- Caution verification page, embeddable cross-origin widget, API and generic signed event webhook
- OneUptime integration for incidents, escalation and ordinary status communication
- STEVE consumes Canary reference statements and performs a bound encrypted canary request where enabled

## Boundaries and positioning

Canary proves the state observed at specific times; it cannot prove uninterrupted state between checks. It does not detect malicious approved source, runtime exploits that leave boot measurements unchanged, hardware compromise or every request’s execution path. Load-balanced deployments require explicit replica enumeration before Canary can claim coverage of every replica.

Launch it as **Caution Canary: Continuous Verification**. Calling it a “verifier network” should wait until customers or independent parties actually operate nodes.

## Success criterion

Within minutes of enabling Canary, a customer can share a signed status showing that production matched an explicitly approved source release moments ago. Their users and STEVE clients can independently compare that statement with fresh application evidence—and the customer receives an actionable alert when it is no longer true.

---

### Reference systems

- [Caution application verification](https://docs.caution.co/guides/verify-an-app/)
- [IETF RATS architecture](https://datatracker.ietf.org/doc/rfc9334/)
- [OneUptime](https://github.com/oneuptime/oneuptime)
- [Keylime](https://keylime.readthedocs.io/en/latest/design/security.html)
- [Contrast attestation](https://docs.edgeless.systems/contrast/architecture/attestation/overview)
- [Confidential Containers Trustee](https://confidentialcontainers.org/docs/attestation/)
- [Tinfoil verification](https://docs.tinfoil.sh/verification/verification-in-tinfoil)
- [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/)
