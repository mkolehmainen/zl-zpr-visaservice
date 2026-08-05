#!/usr/bin/env bash
set -euo pipefail

ZPT_BIN=$(realpath "$(dirname $0)/../target/debug/zpt")
INPUT=$(realpath "$(dirname $0)/pregen/zpt-test-connect.zpt")

PROG_CMD=("$ZPT_BIN" -i "$INPUT" --json)

# Extract first and second JSON objects from NDJSON output
obj1="$("${PROG_CMD[@]}" | sed -n '1p')"
obj2="$("${PROG_CMD[@]}" | sed -n '2p')"

echo "TESTING CONNECT SHOULD SUCCEED AS A SERVICE PROVIDER"
jq -e \
    '.kind == "APPROVE_CONNECTION"
     and .actor.attrs["zpr.services"].value == ["bas"]' \
    >/dev/null <<<"$obj1"
echo "TEST OK"

echo "TESTING CONNECT WITHOUT A MATCHING JOIN POLICY SHOULD SUCCEED AS AN ADAPTER"
jq -e \
    '.kind == "APPROVE_CONNECTION"
     and .actor.attrs["zpr.role"].value == ["adapter"]
     and (.actor.attrs | has("zpr.services") | not)' \
    >/dev/null <<<"$obj2"
echo "TEST OK"

echo "OK"
