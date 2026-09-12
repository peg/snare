# Durable webhook delivery

Snare is adopting Cloudflare Queues to separate callback ingestion from
outbound webhook availability. This document defines the resource topology,
message boundary, and rollout gates before queue delivery becomes active.

## Current rollout status

The managed Cloudflare account contains four isolated queues:

| Environment | Delivery queue | Dead-letter queue |
|---|---|---|
| Production | `snare-webhook-delivery` | `snare-webhook-delivery-dlq` |
| Staging | `snare-webhook-delivery-staging` | `snare-webhook-delivery-staging-dlq` |

The managed queues are not bound to the Worker yet: webhook delivery remains
direct and the queues remain empty. A follow-up behavioral change will add the
environment-specific `WEBHOOK_DELIVERY_QUEUE` producer and consumer paths
together with lifecycle tests. Keeping the inactive binding out of the default
configuration avoids imposing a new resource requirement on self-hosters.

## Delivery message v1

Queue delivery is at least once. Snare will generate one stable delivery ID for
each destination attempt chain and preserve it across retries. Receivers will
get the ID in `X-Snare-Delivery-ID` so they can deduplicate rare redeliveries.

The serialized message contract is:

```json
{
  "schema": "snare.webhook-delivery.v1",
  "delivery_id": "00000000-0000-4000-8000-000000000000",
  "queued_at": "2026-07-30T00:00:00.000Z",
  "destination_id": "sha256:<hex digest>",
  "event": {},
  "meta": {
    "canaryType": "awsproc",
    "label": "agent-prod-admin",
    "deviceId": "dev-..."
  }
}
```

`destination_id` is a one-way digest used to match the queued delivery to a
currently allowed destination. The message never contains the raw webhook URL.
The consumer must resolve the current registration again, apply the outbound
allowlist again, and cancel delivery if the destination was revoked or changed.

The message must never contain:

- the incoming callback request body;
- authorization or credential header values;
- a raw webhook URL;
- a device secret; or
- a webhook-signing secret.

The `event` object remains the metadata-only event already stored by Snare. The
consumer formats and signs the outbound payload only after dequeuing it.

## Consumer policy

The activation change must process each message independently:

- acknowledge a successful `2xx` delivery;
- retry network failures, timeouts, `408`, `425`, `429`, and `5xx` responses;
- bound any receiver-provided retry delay;
- avoid retrying permanent `4xx` responses indefinitely;
- continue rejecting redirects; and
- route exhausted failures to the environment-specific dead-letter queue.

Logs may include the delivery ID, attempt count, provider class, safe status or
error category, and latency. They must redact the token, IP, raw destination,
payload, and secrets.

## Activation gates

Queue-backed delivery must not reach production until staging proves:

1. successful delivery is acknowledged;
2. `429`, temporary `5xx`, and timeout failures recover through retry;
3. permanent failure reaches the dead-letter path;
4. a redelivery preserves its delivery ID;
5. redirects remain blocked;
6. callback bodies and destination secrets do not appear in logs or messages;
7. the existing registration, callback, storage, event-read, and cleanup smoke
   test still passes; and
8. the exact staging-qualified commit is promoted through the protected
   production workflow.

## Deployment prerequisites

Before queue-backed behavior is activated, both `snare-worker-staging` and
`snare-worker-production` GitHub environment tokens need account-scoped
`Queues Edit` in addition to their existing Worker, KV, and route permissions.
Keep the tokens restricted to the Snare account and retain their existing
expiration.

The dead-letter queues intentionally have no consumer during the first rollout.
That preserves failed messages for inspection instead of creating an untested
automatic replay loop.
