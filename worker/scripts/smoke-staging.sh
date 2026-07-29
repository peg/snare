#!/bin/sh
set -eu

base_url="${1:-https://staging.snare.sh}"
worker_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
device_secret=$(openssl rand -hex 32)
token_id="snare-test-$(openssl rand -hex 12)"
device_id=""

case "$base_url" in
  https://*) ;;
  *) echo "staging base URL must use HTTPS" >&2; exit 1 ;;
esac

for command_name in curl jq openssl; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "missing required command: $command_name" >&2
    exit 1
  }
done

cleanup() {
  if [ -z "$device_id" ]; then
    return
  fi

  revoke_payload=$(jq -nc \
    --arg token_id "$token_id" \
    --arg device_id "$device_id" \
    '{token_id: $token_id, device_id: $device_id}')
  curl -fsS \
    -H "Authorization: Bearer $device_secret" \
    -H "Content-Type: application/json" \
    --data "$revoke_payload" \
    "$base_url/api/revoke" >/dev/null 2>&1 || true

  event_keys=$(
    cd "$worker_dir"
    npx wrangler kv key list \
      --binding SNARE_KV \
      --env staging \
      --remote \
      --prefix "event:$token_id:" 2>/dev/null \
      | jq -r '.[].name' 2>/dev/null || true
  )
  for event_key in $event_keys; do
    (
      cd "$worker_dir"
      npx wrangler kv key delete "$event_key" \
        --binding SNARE_KV \
        --env staging \
        --remote >/dev/null 2>&1
    ) || true
  done

  (
    cd "$worker_dir"
    npx wrangler kv key delete "device:$device_id" \
      --binding SNARE_KV \
      --env staging \
      --remote >/dev/null 2>&1
  ) || true
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

device_payload=$(jq -nc --arg secret "$device_secret" '{device_secret: $secret}')
device_response=$(curl -fsS \
  -H "Content-Type: application/json" \
  --data "$device_payload" \
  "$base_url/api/devices")
device_id=$(printf '%s' "$device_response" | jq -er '.device_id')

register_payload=$(jq -nc \
  --arg token_id "$token_id" \
  --arg device_id "$device_id" \
  '{
    token_id: $token_id,
    webhook_url: "use-global",
    device_id: $device_id,
    canary_type: "generic",
    label: "staging-e2e"
  }')
curl -fsS \
  -H "Authorization: Bearer $device_secret" \
  -H "Content-Type: application/json" \
  --data "$register_payload" \
  "$base_url/api/register" >/dev/null

curl -fsS \
  -A "Snare-Staging-Smoke/1.0" \
  "$base_url/c/$token_id" >/dev/null

attempt=1
while [ "$attempt" -le 30 ]; do
  if events_response=$(curl -fsS \
    -H "Authorization: Bearer $device_secret" \
    -H "X-Snare-Device-ID: $device_id" \
    "$base_url/api/events/$token_id" 2>/dev/null); then
    if printf '%s' "$events_response" | jq -e --arg token "$token_id" '
      .events | any(.token == $token and .is_test == true)
    ' >/dev/null; then
      echo "Staging registration, callback, storage, and authenticated event read passed."
      exit 0
    fi
  fi
  attempt=$((attempt + 1))
  sleep 2
done

echo "Staging event did not become readable within 60 seconds." >&2
exit 1
