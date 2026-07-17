# syntax=docker/dockerfile:1.7

# Digests verified against StageX main's authoritative digest files on
# 2026-07-17. Re-check them before a release build.
FROM --platform=linux/amd64 stagex/pallet-rust@sha256:59d4d0c9e232a05ecb99348f7216b521af1b914a430059dbdb9130018f2afde1 AS build

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

ENV SOURCE_DATE_EPOCH=1
ENV CARGO_TARGET_DIR=/target
ENV CARGO_INCREMENTAL=0
ENV RUSTFLAGS="-C codegen-units=1 -C target-feature=+crt-static -C strip=symbols --remap-path-prefix=/app=. --remap-path-prefix=/target=target"

# Dependency acquisition is locked but networked; compilation is frozen and
# networkless. Fully vendoring the git dependency is a pre-release hardening
# step, not needed for this Phase 1 build skeleton.
RUN cargo fetch --locked --target "$(uname -m)-unknown-linux-musl"
RUN --network=none set -eux; \
    triple="$(uname -m)-unknown-linux-musl"; \
    cargo build --frozen --release --target "${triple}" --bin canaryd; \
    install -Dm755 "/target/${triple}/release/canaryd" /canaryd

FROM --platform=linux/amd64 stagex/core-filesystem@sha256:cd3a66471ce1f630fa77d5c9bd9829f9f9fab6302a1aaa64d67b74f1f069b750 AS run
COPY --from=build /canaryd /app/canaryd
ENTRYPOINT ["/app/canaryd"]
