#!/usr/bin/env bash
# C5 OIDC connect-path integration test (zipline#11), modeled on
# zpt-test-connect.sh: three APPROVE_CONNECTION shapes (device-only,
# user-only, both) plus evals pinning which policies match each shape.
set -euo pipefail

ZPT_BIN=$(realpath "$(dirname $0)/../target/debug/zpt")
INPUT=$(realpath "$(dirname $0)/pregen/zpt-test-oidc.zpt")

PROG_CMD=("$ZPT_BIN" -i "$INPUT" --json)

# Cache the NDJSON output once; pick objects by line.
OUTPUT="$("${PROG_CMD[@]}")"
line() { sed -n "${1}p" <<<"$OUTPUT"; }

echo "TESTING DEVICE-ONLY CONNECT: CN IDENTITY, NO USER ATTRS"
jq -e \
    '.kind == "APPROVE_CONNECTION"
     and .actor.identity_keys == ["device.zpr.adapter.cn"]
     and .actor.attrs["device.zpr.authority"].value == ["zpr-bootstrap"]
     and ([.actor.attrs | keys[] | select(startswith("user."))] | length == 0)' \
    >/dev/null <<<"$(line 1)"
echo "TEST OK"

echo "TESTING USER-ONLY CONNECT: SUB IDENTITY, AUTHORITY google, UNAUTHD CN SCRUBBED"
jq -e \
    '.kind == "APPROVE_CONNECTION"
     and .actor.identity_keys == ["user.oidc-subject"]
     and .actor.attrs["user.zpr.authority"].value == ["google"]
     and .actor.attrs["user.domain"].value == ["example.com"]
     and (.actor.attrs | has("device.zpr.adapter.cn") | not)' \
    >/dev/null <<<"$(line 2)"
echo "TEST OK"

echo "TESTING BOTH-NAMESPACE CONNECT: BOTH IDENTITY KEYS, BOTH AUTHORITIES"
jq -e \
    '.kind == "APPROVE_CONNECTION"
     and .actor.identity_keys == ["device.zpr.adapter.cn", "user.oidc-subject"]
     and .actor.attrs["device.zpr.authority"].value == ["zpr-bootstrap"]
     and .actor.attrs["user.zpr.authority"].value == ["google"]' \
    >/dev/null <<<"$(line 3)"
echo "TEST OK"

echo "TESTING USER-ONLY MATCHES THE DOMAIN RULE AND THE BARE USERS RULE"
jq -e '.kind == "EVAL" and .decision == "ALLOW"
       and (.visa.zpl | contains("domain:'"'"'example.com'"'"' users"))' \
    >/dev/null <<<"$(line 4)"
jq -e '.kind == "EVAL" and .decision == "ALLOW"
       and (.visa.zpl | contains("allow users to access services"))' \
    >/dev/null <<<"$(line 5)"
echo "TEST OK"

echo "TESTING BOTH MATCHES THE DOMAIN RULE AND THE BARE USERS RULE"
jq -e '.kind == "EVAL" and .decision == "ALLOW"
       and (.visa.zpl | contains("domain:'"'"'example.com'"'"' users"))' \
    >/dev/null <<<"$(line 6)"
jq -e '.kind == "EVAL" and .decision == "ALLOW"
       and (.visa.zpl | contains("allow users to access services"))' \
    >/dev/null <<<"$(line 7)"
echo "TEST OK"

echo "TESTING DEVICE-ONLY DOES NOT MATCH USER RULES (FAIL-CLOSED, #144)"
jq -e '.kind == "EVAL" and .decision == "NO_MATCH"' >/dev/null <<<"$(line 8)"
echo "TEST OK"

echo "TESTING DEVICE RULE MATCHES DEVICE-ONLY (BARE USERS RULE DOES NOT)"
jq -e '.kind == "EVAL" and .decision == "ALLOW"
       and (.visa.zpl | contains("devices to access Devy"))' \
    >/dev/null <<<"$(line 9)"
# Exactly one hit for the device-only eval: the bare users rule must not fire.
test "$(jq -rs '[.[] | select(.kind=="EVAL" and .instruction==7)] | length' <<<"$OUTPUT")" = "1"
echo "TEST OK"

echo "TESTING BOTH MATCHES THE DEVICE RULE AND THE BARE USERS RULE"
jq -e '.kind == "EVAL" and .decision == "ALLOW"
       and (.visa.zpl | contains("devices to access Devy"))' \
    >/dev/null <<<"$(line 10)"
jq -e '.kind == "EVAL" and .decision == "ALLOW"
       and (.visa.zpl | contains("allow users to access services"))' \
    >/dev/null <<<"$(line 11)"
echo "TEST OK"

echo "OK"
