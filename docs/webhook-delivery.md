# Durable webhook delivery

The receiver supports a D1 event store with a durable outbox. Event admission
and all destination envelopes commit together before the callback returns 200.
That acknowledges stored evidence, not successful notification. Unknown or
revoked tokens return a harmless response without creating events or messages.
Admission exhaustion returns 429; storage failure returns 503.

The checked-in managed `worker/wrangler.jsonc` still uses KV. These guarantees
become active only after the separate D1 migration and binding change described
in [the activation guide](receiver-activation.md). KV mode is best effort and
cannot provide atomic first ownership claims or exact persistent quotas.

## Two delivery modes

D1 without a Queue binding sends from the outbox after ingestion and retries
through Cron. This is the smallest resource topology. D1 with
`WEBHOOK_DELIVERY_QUEUE` publishes notifications to Cloudflare Queues; consumers
load the authoritative envelope from D1. Keep Cron enabled in either mode:
it recovers abandoned work, expires delivery chains, and removes old evidence.

The earlier queue foundation recorded these resource names. Verify the current
account inventory and isolate production and staging before using them:

| Environment | Delivery queue | Optional infrastructure dead-letter queue |
|---|---|---|
| Production | `snare-webhook-delivery` | `snare-webhook-delivery-dlq` |
| Staging | `snare-webhook-delivery-staging` | `snare-webhook-delivery-staging-dlq` |

An optional Wrangler fragment, after creating the named resources:

```json
{
  "queues": {
    "producers": [{ "binding": "WEBHOOK_DELIVERY_QUEUE", "queue": "snare-webhook-delivery-staging" }],
    "consumers": [{
      "queue": "snare-webhook-delivery-staging",
      "max_batch_size": 5,
      "max_batch_timeout": 5,
      "max_retries": 5,
      "dead_letter_queue": "snare-webhook-delivery-staging-dlq"
    }]
  }
}
```

The consumer processes at most five notifications per invocation even if a
larger batch arrives. Direct outbox dispatch also handles five deliveries;
queue publication handles fifteen. These bounds leave room under the Workers
Free limit of 50 D1 queries per invocation, including ingestion and cleanup.
Direct outbound requests have five-second timeouts. Cron retries can be later
than the requested backoff because they follow its configured schedule.
[Cloudflare D1 limits](https://developers.cloudflare.com/d1/platform/limits/)

## Delivery and privacy contract

One stable delivery ID identifies a destination's attempt chain. A generic
receiver gets `X-Snare-Delivery-ID` and `X-Snare-Event-ID` on every send. Delivery
is at least once: if the receiver accepts a request and the Worker stops before
recording success, a later attempt can duplicate it. Downstream receivers should
deduplicate by delivery ID. Snare does not claim exactly-once notification.

The bounded `snare.webhook-delivery.v1` envelope contains a delivery ID, enqueue
time, token registration revision, destination URL digest, and allowlisted event
and display metadata. It excludes callback bodies, authorization values, raw
webhook URLs, device secrets, and signing secrets. Metadata such as IP, user
agent, path, or user labels can still contain sensitive information.

A Queue notification supplies a delivery ID; its event content is never the
authoritative send payload. The consumer reads D1, claims an expiring lease,
validates the stored envelope, rechecks the current owner, registration revision
and destination, and reserves an attempt atomically before sending. It applies
the HTTPS/domain allowlist again at the network boundary, rejects redirects,
and fails closed if configured webhook signing is unavailable.

Revocation or a material registration change cancels pending delivery chains.
An identical registration repair preserves their revision and pending work.
Cancellation cannot retract a request that was already authorized and sent.

## Retry and failure policy

Successful 2xx responses complete a delivery. Network errors, timeouts, 408,
425, 429, and 5xx responses retry with bounded backoff. Redirects and other
permanent responses fail. A chain has at most five reserved attempts and a
24-hour lifetime. Reserving before network I/O also counts an attempt when the
Worker stops before sending, favoring a firm abuse limit over guaranteed sends.
Global and device daily budgets are separate additional limits.

Application failures are persisted as `failed` or `cancelled` in D1, then the
Queue notification is acknowledged. They do **not** depend on a dead-letter
queue for visibility. Infrastructure retries exhausted by Cloudflare may reach
the optional DLQ; Cron still reconciles the D1 record. Do not automatically
replay dead letters without checking the authoritative state.

Authenticated event reads include `deliveries` with each ID, state, reserved
attempt count, and safe error code. Suppressed notifications have no delivery
rows and retain `notification_suppressed` on the event. Default evidence and
failure retention is seven days, removed in bounded cleanup batches.

## Activation checks

Before production activation, prove in staging: successful delivery; 429/5xx
and timeout recovery; permanent failure visibility; crash/duplicate handling;
revocation during pending work; attempt, event and storage caps; body/secret
exclusion; and the existing lifecycle smoke plus real-client proof contracts.
Exercise both direct and Queue modes if both are offered. Promote the exact
validated commit through the production workflow.

Use account-scoped D1 permissions for migrations and binding management, plus
Queues permissions only when enabling Queue delivery. Inspect the current
scoped deployment tokens and account plan before changing them. No credentials
or production bindings are supplied by this document.
