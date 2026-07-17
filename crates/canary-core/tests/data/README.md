# Bootproof Nitro test fixture

`aws-test.cbor.b64` is a base64 representation of Bootproof's public
`crates/bootproof-sdk/src/format/data/aws-test.cbor` fixture at commit
`78f531a2c245404a9d8879fb71cc397096ae0077`, the same revision pinned by this
workspace. Its decoded SHA-256 is
`6afe913ae239fc83c44fd21c367f6ca9bf1b1b31d737c4720fd42cd49deb2c47`.

It is checked in so Canary's positive, nonce-replay and PCR-mismatch tests do
not depend on a sibling checkout or network access.
