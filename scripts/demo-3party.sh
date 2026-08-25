#!/usr/bin/env bash
# demo-3party.sh — End-to-end 3-party MPC demo via real TCP+Coordinator.
# Usage:  ./scripts/demo-3party.sh [api_url]
# Requires: coordinator running at $API_URL (default http://127.0.0.1:8080)
set -euo pipefail
API_URL="${1:-${OSMOSMPC_API_URL:-http://127.0.0.1:8080}}"
API_KEY="${OSMOSMPC_API_KEY:-changeme}"
HDR=(-H "x-api-key: $API_KEY" -H "authorization: Bearer $API_KEY" -H "content-type: application/json")

echo "== Osmiridium 3-party demo =="
echo "API: $API_URL"

echo "-- health --"
curl -fsS "$API_URL/health" && echo

echo "-- create session --"
SESSION_ID=$(curl -fsS "${HDR[@]}" -X POST "$API_URL/sessions" -d '{"name":"demo-3party","num_parties":3}' | jq -r '.id // .session_id')
if [[ -z "$SESSION_ID" || "$SESSION_ID" == "null" ]]; then echo "create failed"; exit 1; fi
echo "session: $SESSION_ID"

echo "-- add participants --"
for i in 0 1 2; do
  curl -fsS "${HDR[@]}" -X POST "$API_URL/sessions/$SESSION_ID/participants" \
    -d "{\"party_id\":$i,\"name\":\"party-$i\",\"endpoint\":\"127.0.0.1:$((9000+i))\",\"role\":\"DataProvider\"}" && echo " party $i ok"
done

echo "-- execute --"
curl -fsS "${HDR[@]}" -X POST "$API_URL/sessions/$SESSION_ID/execute" -d '{}' | jq .

echo "-- results --"
curl -fsS "${HDR[@]}" "$API_URL/sessions/$SESSION_ID/results" | jq .

echo "== done: session $SESSION_ID =="
