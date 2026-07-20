# Public interoperability and Bootproof fixtures

## Bootproof Nitro document

`aws-test.cbor.b64` is a base64 representation of Bootproof's public
`crates/bootproof-sdk/src/format/data/aws-test.cbor` fixture at commit
`78f531a2c245404a9d8879fb71cc397096ae0077`, the same revision pinned by this
workspace. Its decoded SHA-256 is
`6afe913ae239fc83c44fd21c367f6ca9bf1b1b31d737c4720fd42cd49deb2c47`.

It is checked in so Canary's positive, nonce-replay and PCR-mismatch tests do
not depend on a sibling checkout or network access.

`evidence-v0-vector.json` wraps that same signed document in the frozen Caution
Canary V0 evidence schema. It includes the original nonce, separately published
PCR values in the tests, the validation time used by Bootproof's fixture, and
canonical evidence/manifest digests. It is safe for interoperability tests; it
is historical evidence, not a current freshness proof.

## Hybrid statement vector

`statement-v0-vector.json` is a language-neutral, byte-for-byte known-answer
vector for:

- master-seed child-key derivation;
- the exact domain-separated canonical payload bytes;
- Ed25519 and ML-DSA-65 public keys and signatures; and
- strict hybrid statement verification.

The vector intentionally publishes its test-only master seed and fixed ML-DSA
randomizer. They are not deployment secrets. Production ML-DSA signing remains
hedged with OS randomness; the fixed randomizer exists only to make the public
known-answer signature reproducible.

## License and provenance

The Bootproof document originates from the AGPL-3.0 Bootproof repository at the
commit above. These fixtures and the rest of this workspace are distributed
under `AGPL-3.0-only`; see the repository `LICENSE.md`.
