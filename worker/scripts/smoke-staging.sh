#!/bin/sh
set -eu

base_url="${1:-https://staging.snare.sh}"
worker_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
device_secret=$(openssl rand -hex 32)
token_id="snare-test-$(openssl rand -hex 12)"
proof_id=$(openssl rand -hex 16)
storage_backend=""
device_id=""

case "$base_url" in
  https://staging.snare.sh) ;;
  *) echo "managed smoke test only targets https://staging.snare.sh" >&2; exit 1 ;;
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

  if [ "$storage_backend" = "d1" ]; then
    # IDs were generated in this run and validated before SQL interpolation.
    # Delete only this disposable staging fixture, in foreign-key order.
    (
      cd "$worker_dir"
      npx wrangler d1 execute SNARE_DB --env staging --remote --command "
        DELETE FROM events WHERE token = '$token_id' AND device_id = '$device_id';
        DELETE FROM deliveries WHERE token = '$token_id' AND device_id = '$device_id';
        DELETE FROM delivery_attempts WHERE device_id = '$device_id';
        DELETE FROM tokens WHERE token = '$token_id' AND device_id = '$device_id';
        DELETE FROM devices WHERE device_id = '$device_id';
      " >/dev/null 2>&1
    ) || echo "Synthetic D1 cleanup needs operator attention." >&2
    return
  fi

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

  for synthetic_key in "owner:$token_id" "webhook:$token_id"; do
    (
      cd "$worker_dir"
      npx wrangler kv key delete "$synthetic_key" --binding SNARE_KV --env staging --remote >/dev/null 2>&1
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

health=$(curl -fsS "$base_url/health")
storage_backend=$(printf '%s' "$health" | jq -er 'select(.environment == "staging") | .storage | select(. == "kv" or . == "d1")')

device_payload=$(jq -nc --arg secret "$device_secret" '{device_secret: $secret}')
device_response=$(curl -fsS \
  -H "Authorization: Bearer ${SNARE_ENROLLMENT_TOKEN:-}" \
  -H "Content-Type: application/json" \
  --data "$device_payload" \
  "$base_url/api/devices")
device_id=$(printf '%s' "$device_response" | jq -er '.device_id | select(test("^dev-[0-9a-f]{32}$"))')

register_payload=$(jq -nc \
  --arg token_id "$token_id" \
  --arg device_id "$device_id" \
  '{
    token_id: $token_id,
    webhook_url: "https://hooks.slack.com/services/snare-staging-smoke/never-sent",
    device_id: $device_id,
    canary_type: "generic",
    label: "staging-e2e"
  }')
curl -fsS \
  -H "Authorization: Bearer $device_secret" \
  -H "Content-Type: application/json" \
  --data "$register_payload" \
  "$base_url/api/register" >/dev/null

# Preview classification records evidence while suppressing external notification.
# This placeholder destination must never receive a request.
curl -fsS \
  -A "Slackbot-Snare-Staging-Smoke/1.0" \
  "$base_url/c/$token_id/proof/$proof_id" >/dev/null

attempt=1
while [ "$attempt" -le 30 ]; do
  if events_response=$(curl -fsS \
    -H "Authorization: Bearer $device_secret" \
    -H "X-Snare-Device-ID: $device_id" \
    "$base_url/api/events/$token_id?proof_id=$proof_id" 2>/dev/null); then
    if printf '%s' "$events_response" | jq -e --arg token "$token_id" --arg proof "$proof_id" '
      .events | any(.token == $token and .is_test == true and .proof_id == $proof and
        (.id | type == "string" and length > 0) and .notification_suppressed == "preview")
    ' >/dev/null; then
      echo "Staging registration, correlated callback, suppression, storage, and authenticated event read passed."
      exit 0
    fi
  fi
  attempt=$((attempt + 1))
  sleep 2
done

echo "Staging event did not become readable within 60 seconds." >&2
exit 1
