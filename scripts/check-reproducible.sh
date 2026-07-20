#!/bin/sh
# Build the measured runtime image twice and compare the OCI exports exactly.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

required_inputs='
canary.json
.caution/quorum-bundle.json
.caution/secrets/CANARY_MASTER_SEED.asc
'

for input in $required_inputs; do
	if [ ! -f "$repo_root/$input" ]; then
		printf 'error: required operator-owned deployment input is missing: %s\n' "$input" >&2
		exit 1
	fi
done

if ! command -v docker >/dev/null 2>&1; then
	printf '%s\n' 'error: docker with buildx is required for reproducibility verification' >&2
	exit 1
fi
if ! docker buildx version >/dev/null 2>&1; then
	printf '%s\n' 'error: docker buildx is required for reproducibility verification' >&2
	exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1"; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1"; }
else
	printf '%s\n' 'error: sha256sum or shasum is required for reproducibility verification' >&2
	exit 1
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/canary-repro.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

for build in first second; do
	artifact="$work_dir/canary-${build}.oci.tar"
	printf 'Building %s OCI artifact: %s\n' "$build" "$artifact"
	SOURCE_DATE_EPOCH=1 docker buildx build \
		--no-cache \
		--platform linux/amd64 \
		--target run \
		--build-arg SOURCE_DATE_EPOCH=1 \
		--provenance=false \
		--output "type=oci,dest=${artifact},rewrite-timestamp=true" \
		-f "$repo_root/Containerfile" \
		"$repo_root"
done

printf '%s\n' 'OCI SHA-256:'
sha256 "$work_dir/canary-first.oci.tar"
sha256 "$work_dir/canary-second.oci.tar"

if ! cmp -s "$work_dir/canary-first.oci.tar" "$work_dir/canary-second.oci.tar"; then
	printf '%s\n' 'error: OCI exports differ; reproducibility check failed' >&2
	exit 1
fi

printf '%s\n' 'REPRODUCIBLE: OCI exports are byte-for-byte identical'
