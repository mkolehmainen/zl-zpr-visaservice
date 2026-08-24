#!/usr/bin/env bash
# Runs the per-key tag encoding test: alice (color:red + #device.hardened) is
# allowed to web1, while bob (no tag) and carol (no color) get no match.
set -euo pipefail

ZPT_BIN=$(realpath "$(dirname $0)/../target/debug/zpt")
INPUT=$(realpath "$(dirname $0)/pregen/tag-test.zpt")

out=$("$ZPT_BIN" -i "$INPUT" --json)

# Each eval must produce exactly one object with the expected decision.
check() {
  local instruction=$1 decision=$2
  if [ "$(jq -s "[.[] | select(.kind==\"EVAL\" and .instruction==$instruction and .decision==\"$decision\")] | length" <<<"$out")" != "1" ]; then
    echo "FAILED ON EVAL $instruction (expected $decision)"
    exit 1
  fi
}

check 1 ALLOW
check 2 NO_MATCH
check 3 NO_MATCH

# The allow must come from the hardened-device rule, i.e. the tag was matched.
if ! jq -e -s 'any(.[]; .kind=="EVAL" and .instruction==1 and (.visa.zpl // "" | test("hardened devices")))' <<<"$out" >/dev/null; then
  echo "FAILED ON TAG RULE CHECK"
  exit 1
fi

echo "SUCCESS"
