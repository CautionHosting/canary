#!/usr/bin/env sh
# Canary V0 evaluator transcription. See README.md; it calls no deployment interface
# other than the documented `git push caution main`.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

fail() {
  printf '%s\n' "error: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

pause() {
  printf '\n%s\n' "$1"
  printf '%s' 'Press Enter when the interactive/operator-controlled step is complete, or Ctrl-C to stop: '
  IFS= read -r _
}

for command in caution canaryctl cargo docker git curl cmp cp mkdir; do
  need "$command"
done

: "${CANARY_HOST:?set CANARY_HOST to the public Canary HTTPS origin}"
: "${PAYMENTS_URL:?set PAYMENTS_URL to the first target /attestation URL}"
: "${LEDGER_URL:?set LEDGER_URL to the second target /attestation URL}"
: "${PAYMENTS_PCRS:?set PAYMENTS_PCRS to independently verified target PCRs}"
: "${LEDGER_PCRS:?set LEDGER_PCRS to independently verified target PCRs}"

case "$CANARY_HOST" in https://*) ;; *) fail 'CANARY_HOST must start with https://' ;; esac
case "$PAYMENTS_URL" in https://*) ;; *) fail 'PAYMENTS_URL must start with https://' ;; esac
case "$LEDGER_URL" in https://*) ;; *) fail 'LEDGER_URL must start with https://' ;; esac
[ "$PAYMENTS_URL" != "$LEDGER_URL" ] || fail 'the two target URLs must be distinct'
[ -f "$PAYMENTS_PCRS" ] || fail "missing PAYMENTS_PCRS: $PAYMENTS_PCRS"
[ -f "$LEDGER_PCRS" ] || fail "missing LEDGER_PCRS: $LEDGER_PCRS"
[ -f Containerfile ] || fail 'missing root Containerfile'
[ -f caution.hcl ] || fail 'missing reviewed root caution.hcl (do not deploy a template)'
for artifact in trusted-keys.json statement.json evidence.json; do
  [ ! -e "$artifact" ] || fail "refusing to overwrite public artifact: $artifact"
done

printf '%s\n' 'Use independently reproduced PCR files. TOFU capture is intentionally not automated here.'
mkdir -p .caution/trusted_hashes
for target_id in payments-prod ledger-prod; do
  case "$target_id" in
    payments-prod) source_pcrs=$PAYMENTS_PCRS ;;
    ledger-prod) source_pcrs=$LEDGER_PCRS ;;
  esac
  destination_pcrs=".caution/trusted_hashes/$target_id.json"
  if [ -e "$destination_pcrs" ]; then
    cmp -s "$source_pcrs" "$destination_pcrs" \
      || fail "refusing to replace PCR provenance file: $destination_pcrs"
  else
    cp "$source_pcrs" "$destination_pcrs"
  fi
done
canaryctl config add --config canary.json --node-id caution-canary-demo \
  --id payments-prod --name 'Payments production' --attestation-url "$PAYMENTS_URL" \
  --pcrs-file "$PAYMENTS_PCRS"
canaryctl config add --config canary.json --id ledger-prod --name 'Ledger production' \
  --attestation-url "$LEDGER_URL" --pcrs-file "$LEDGER_PCRS"

pause 'PAUSE: run the README seed-generation and 1-of-1 Locksmith commands manually with a passkey and authorized Keymaker operator. Then run caution init. This script never reads, prints, or writes secrets.'

./scripts/validate-deployment.sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
./scripts/check-reproducible.sh
caution apps build --no-cache

pause 'PAUSE: review and commit only the public, measured, deployment, quorum-bundle and encrypted-seed inputs listed in the README. The next command deploys to Caution.'
git push caution main
caution verify --save-pcrs
pause 'PAUSE: run caution secret send-shard --keyring canary.private.asc manually under authorized Keymaker/operator control; wait for canaryd to become ready.'

canaryctl inspect-node --url "$CANARY_HOST" --pcrs-file .caution/trusted_hashes.json \
  --keys-out trusted-keys.json
curl -fsS "$CANARY_HOST/targets/payments-prod/statement" -o statement.json
curl -fsS "$CANARY_HOST/targets/payments-prod/evidence" -o evidence.json
canaryctl verify-statement --statement statement.json --keys trusted-keys.json
canaryctl verify-evidence --evidence evidence.json --pcrs-file "$PAYMENTS_PCRS"

printf '%s\n' 'Record command results and controlled replay/outage/lifecycle scenarios in docs/evidence/v0/.'
