#!/usr/bin/env bash
# Validate the measured deployment inputs after `caution init` and before `git push`.
# This script never contacts Caution or target endpoints.
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly CONFIG="$ROOT/canary.json"
readonly CAUTION_CONFIG="$ROOT/caution.hcl"
readonly CAUTION_TEMPLATE="$ROOT/caution.hcl.template"
readonly DEPLOYMENT="$ROOT/.caution/deployment.json"
readonly QUORUM_BUNDLE="$ROOT/.caution/quorum-bundle.json"
readonly ENCRYPTED_SEED="$ROOT/.caution/secrets/CANARY_MASTER_SEED.asc"

die() {
  printf 'deployment validation failed: %s\n' "$*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || die "missing ${1#"$ROOT/"}"
}

for command in jq cargo cmp cp diff grep mktemp rm sed tr wc; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

require_file "$CAUTION_CONFIG"
require_file "$CONFIG"
require_file "$ROOT/Containerfile"
require_file "$DEPLOYMENT"
require_file "$QUORUM_BUNDLE"
require_file "$ENCRYPTED_SEED"
jq -e 'type == "object"' "$DEPLOYMENT" >/dev/null \
  || die ".caution/deployment.json must be a JSON object"
jq -e 'type == "object"' "$QUORUM_BUNDLE" >/dev/null \
  || die ".caution/quorum-bundle.json must be a JSON object"
grep -q '^-----BEGIN PGP MESSAGE-----$' "$ENCRYPTED_SEED" \
  || die "CANARY_MASTER_SEED.asc is not an armored encrypted message"
shopt -s nullglob
encrypted_secrets=("$ROOT"/.caution/secrets/*.asc)
[[ "${#encrypted_secrets[@]}" -eq 1 && "${encrypted_secrets[0]}" == "$ENCRYPTED_SEED" ]] \
  || die "only .caution/secrets/CANARY_MASTER_SEED.asc may be present"

# The release HCL has one intentionally narrow shape. Normalize only the two
# operator-supplied public values, then compare it to the reviewed template.
# This rejects debug, STEVE/e2e, custom resources, extra units/enclaves, build
# binaries, extra secrets, and any other unreviewed deployment feature.
source_url="$(sed -nE 's/^      "(https:\/\/[^"[:space:]]+)",$/\1/p' "$CAUTION_CONFIG")"
[[ "$(printf '%s\n' "$source_url" | sed '/^$/d' | wc -l | tr -d ' ')" == "1" ]] \
  || die "caution.hcl must contain exactly one public HTTPS app_sources value"
[[ "$source_url" != *REPLACE* && "$source_url" != *example.* && "$source_url" != *localhost* ]] \
  || die "caution.hcl app_sources still contains a placeholder or non-public URL"
[[ "$source_url" != *"@"* && "$source_url" != *"#"* && "$source_url" != *"?"* ]] \
  || die "caution.hcl app_sources must not contain credentials, a fragment, or a query"
source_host="${source_url#https://}"
source_host="${source_host%%/*}"
[[ "$source_host" == *.* && "$source_host" != *":"* && "$source_host" != .* && "$source_host" != *. ]] \
  || die "caution.hcl app_sources must use a public HTTPS hostname on the default port"
[[ "$source_host" =~ [A-Za-z] ]] \
  || die "caution.hcl app_sources must use a repository hostname, not an IP address"
source_path="${source_url#"https://$source_host"}"
[[ "$source_path" == /* && "$source_path" != / ]] \
  || die "caution.hcl app_sources must include a repository path"
case "$source_host" in
  *.example|*.invalid|*.localhost|*.local|*.internal|*.test|10.*|127.*|169.254.*|192.168.*)
    die "caution.hcl app_sources uses a reserved or non-public hostname"
    ;;
esac

domain="$(sed -nE 's/^      domain = "([^"]+)"$/\1/p' "$CAUTION_CONFIG")"
[[ "$(printf '%s\n' "$domain" | sed '/^$/d' | wc -l | tr -d ' ')" == "1" ]] \
  || die "caution.hcl must contain exactly one HTTP domain"
[[ "$domain" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] \
  || die "caution.hcl domain must be a lowercase public DNS name"
[[ "$domain" != *replace* && "$domain" != *example.* && "$domain" != *localhost* ]] \
  || die "caution.hcl domain still contains a placeholder or non-public domain"

normalized_hcl="$(mktemp)"
tmp_dir="$(mktemp -d)"
cleanup() {
  rm -f "$normalized_hcl"
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

sed -E \
  -e 's#^      "https://[^"[:space:]]+",$#      "https://REPLACE_WITH_PUBLIC_SOURCE_URL",#' \
  -e 's#^      domain = "[^"]+"$#      domain = "REPLACE_WITH_PUBLIC_HTTPS_DOMAIN"#' \
  "$CAUTION_CONFIG" >"$normalized_hcl"
diff -u "$CAUTION_TEMPLATE" "$normalized_hcl" >/dev/null \
  || die "caution.hcl differs from the approved V0 release shape"

# Require JSON syntax and the exact V0 schema before asking canaryctl to perform
# its authoritative strict parse/validation pass below.
jq -e '
  type == "object" and
  (keys | sort) == ["node_id", "targets", "version"] and
  .version == 0 and
  (.node_id | type == "string" and length > 0) and
  (.targets | type == "array" and length >= 2) and
  all(.targets[];
    type == "object" and
    ((keys | sort) == ["attestation_url", "expected_pcrs", "id", "name"] or
     (keys | sort) == ["attestation_url", "e2e_mode", "expected_pcrs", "id", "name"]) and
    (.e2e_mode == null or .e2e_mode == "tls") and
    (.expected_pcrs | type == "object" and (keys | sort) == ["0", "1", "2"])
  )
' "$CONFIG" >/dev/null || die "canary.json has the wrong V0 shape or fewer than two targets"

# Each target must come from its own Caution `verify --save-pcrs` result. Match
# every recorded PCR value, not merely the target count, before invoking the
# authoritative canaryctl parser.
while IFS= read -r target_id; do
  [[ "$target_id" =~ ^[A-Za-z0-9_-]+$ ]] \
    || die "target id is not a canonical V0 identifier: $target_id"
  pcrs_file="$ROOT/.caution/trusted_hashes/${target_id}.json"
  require_file "$pcrs_file"
  jq -e '(.pcr0 | type == "string") and (.pcr1 | type == "string") and (.pcr2 | type == "string")' \
    "$pcrs_file" >/dev/null || die "invalid PCR file ${pcrs_file#"$ROOT/"}"
  jq -e --arg id "$target_id" --slurpfile expected "$pcrs_file" '
    ($expected[0] | {pcr0, pcr1, pcr2}) as $pcrs |
    any(.targets[]; .id == $id and .expected_pcrs == {
      "0": $pcrs.pcr0, "1": $pcrs.pcr1, "2": $pcrs.pcr2
    })
  ' "$CONFIG" >/dev/null || die "PCR file for $target_id does not match canary.json"
done < <(jq -r '.targets[].id' "$CONFIG")

origin_count="$(jq -r '
  [.targets[].attestation_url |
    capture("^(?<origin>https://[^/?#]+)(?:/|$)").origin] |
  unique | length
' "$CONFIG")" || die "every target attestation_url must have an HTTPS origin"
[[ "$origin_count" -ge 2 ]] || die "canary.json must configure at least two unique HTTPS origins"

# `add-target --replace` parses the full config with canaryctl's strict
# deny-unknown-fields schema, then rewrites a temporary copy. A byte-for-byte
# comparison proves the committed file is canonical `add-target` output.
first_id="$(jq -r '.targets[0].id' "$CONFIG")"
first_name="$(jq -r '.targets[0].name' "$CONFIG")"
first_url="$(jq -r '.targets[0].attestation_url' "$CONFIG")"
first_e2e_mode="$(jq -r '.targets[0].e2e_mode // empty' "$CONFIG")"
e2e_args=()
if [[ "$first_e2e_mode" == "tls" ]]; then
  e2e_args=(--e2e-mode tls)
fi
cp "$CONFIG" "$tmp_dir/canary.json"
jq '{pcr0: .targets[0].expected_pcrs["0"], pcr1: .targets[0].expected_pcrs["1"], pcr2: .targets[0].expected_pcrs["2"]}' \
  "$CONFIG" >"$tmp_dir/pcrs.json"
(
  cd "$ROOT"
  cargo run --quiet --locked -p canaryctl -- add-target \
    --config "$tmp_dir/canary.json" \
    --id "$first_id" \
    --name "$first_name" \
    --attestation-url "$first_url" \
    "${e2e_args[@]}" \
    --expected-pcrs "$tmp_dir/pcrs.json" \
    --replace >/dev/null
) || die "canaryctl rejected canary.json"
cmp -s "$CONFIG" "$tmp_dir/canary.json" \
  || die "canary.json was not produced by canonical canaryctl add-target output"

printf 'deployment inputs are release-valid\n'
