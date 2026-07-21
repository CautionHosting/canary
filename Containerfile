# syntax=docker/dockerfile:1.7

# Digests verified against StageX main's authoritative digest files on
# 2026-07-21. Re-check them before a release build.
ARG SOURCE_DATE_EPOCH=1
FROM --platform=linux/amd64 stagex/pallet-rust@sha256:59d4d0c9e232a05ecb99348f7216b521af1b914a430059dbdb9130018f2afde1 AS build

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
ENV CARGO_TARGET_DIR=/target
ENV CARGO_INCREMENTAL=0
ENV RUSTFLAGS="-C codegen-units=1 -C target-feature=+crt-static -C strip=symbols --remap-path-prefix=/app=. --remap-path-prefix=/target=target"

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# sqlx::migrate! resolves this directory while compiling canaryd.
COPY migrations ./migrations

# Dependency acquisition is locked but networked; compilation is frozen and
# networkless. The lockfile pins every fetched crate and checksum.
RUN cargo fetch --locked --target "$(uname -m)-unknown-linux-musl"
RUN --network=none <<-'EOF'
	set -eux
	triple="$(uname -m)-unknown-linux-musl"
	cargo build --frozen --release --target "${triple}" --bin canaryd
	install -Dm755 "/target/${triple}/release/canaryd" /staged/app/canaryd
EOF

FROM --platform=linux/amd64 stagex/core-filesystem@sha256:cd3a66471ce1f630fa77d5c9bd9829f9f9fab6302a1aaa64d67b74f1f069b750 AS local

# Local Docker runs inject a development seed and bind-mount canary.json.
# No Caution deployment metadata or Locksmith artifacts enter this image.
USER 0:0
COPY --from=build /staged/app/canaryd /app/canaryd
ENTRYPOINT ["/app/canaryd"]

FROM build AS deployment-inputs

# canary.json is always measured. Locksmith inputs are optional so the same
# reproducible recipe supports both stable and ephemeral identity deployments.
# When either Locksmith artifact exists, require and stage both.
COPY canary.json /inputs/canary.json
RUN --mount=type=bind,source=.,target=/context,ro <<-'EOF'
	set -eux
	install -Dm644 /inputs/canary.json /staged/app/canary.json
	bundle=/context/.caution/quorum-bundle.json
	secret=/context/.caution/secrets/CANARY_MASTER_SEED.asc
	if [ -e "${bundle}" ] || [ -e "${secret}" ]; then
		test -f "${bundle}"
		test -f "${secret}"
		install -Dm644 "${bundle}" /staged/etc/caution/bundle.json
		install -Dm644 "${secret}" /staged/etc/caution/secrets/CANARY_MASTER_SEED.asc
	fi
EOF

FROM --platform=linux/amd64 stagex/core-filesystem@sha256:cd3a66471ce1f630fa77d5c9bd9829f9f9fab6302a1aaa64d67b74f1f069b750 AS run

# core-filesystem defaults to an unprivileged user and already provides /tmp
# as 1777. canaryd atomically creates /metadata.json, so it deliberately runs
# as numeric root. This final stage is copy-only because it contains no shell.
USER 0:0
COPY --from=deployment-inputs /staged/ /

ENTRYPOINT ["/app/canaryd"]
