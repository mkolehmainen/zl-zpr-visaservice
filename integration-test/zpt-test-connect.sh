#!/usr/bin/env bash
set -euo pipefail

ZPT_BIN=$(realpath "$(dirname $0)/../target/debug/zpt")
INPUT=$(realpath "$(dirname $0)/pregen/zpt-test-connect.zpt")

PROG_CMD=("$ZPT_BIN" -i "$INPUT" --json)

# Extract the JSON objects from NDJSON output
obj1="$("${PROG_CMD[@]}" | sed -n '1p')"
obj2="$("${PROG_CMD[@]}" | sed -n '2p')"
obj3="$("${PROG_CMD[@]}" | sed -n '3p')"
obj4="$("${PROG_CMD[@]}" | sed -n '4p')"

echo "TESTING CONNECT SHOULD SUCCEED AS A SERVICE PROVIDER"
jq -e \
    '.kind == "APPROVE_CONNECTION"
     and .actor.attrs["zpr.services"].value == ["bas"]
     and .actor.identity_keys == ["device.zpr.adapter.cn"]' \
    >/dev/null <<<"$obj1"
echo "TEST OK"

echo "TESTING CONNECT WITHOUT A MATCHING JOIN POLICY SHOULD SUCCEED AS AN ADAPTER"
jq -e \
    '.kind == "APPROVE_CONNECTION"
     and .actor.attrs["zpr.role"].value == ["adapter"]
     and (.actor.attrs | has("zpr.services") | not)' \
    >/dev/null <<<"$obj2"
echo "TEST OK"

echo "TESTING POLICY-DECLARED IDENTITY ATTRIBUTE JOINS THE BUILTIN CN IDENTITY"
# Assert on identity_keys only: user.bas_id:1233 also satisfies provider
# conditions, so zpr.services will differ from the first object.
jq -e \
    '.kind == "APPROVE_CONNECTION"
     and .actor.identity_keys == ["device.zpr.adapter.cn", "user.bas_id"]' \
    >/dev/null <<<"$obj3"
echo "TEST OK"

echo "TESTING DEVICE-ONLY ACTOR DOES NOT MATCH A BARE 'allow users' RULE (FAIL-CLOSED)"
# Compiler >= 0.16 emits `has user.zpr.authority` for bare user specs (#144);
# an actor with only device.zpr.authority must get NO_MATCH, not ALLOW (#324).
jq -e \
    '.kind == "EVAL" and .decision == "NO_MATCH"' \
    >/dev/null <<<"$obj4"
echo "TEST OK"

echo "OK"
