# Receiver activation and migration

This maintenance change adds an optional D1 receiver backend. It does not
provision Cloudflare resources, change a subscription, or migrate the managed
service automatically. `worker/wrangler.jsonc` remains the current KV deployment;
`worker/wrangler.d1.example.jsonc` is a separate closed-enrollment example.

## Default admission bounds

The D1 store uses these small-service defaults. They are application admission
limits, not a Cloudflare billing cap:

| Resource | Global bound | Per device |
|---|---:|---:|
| Enrolled devices | 200 | — |
| Active tokens | 500 | 100 |
| Token records including revoked ownership | 10,000 | 2,000 |
| Admitted events per UTC day | 200 | 50 |
| Suppressed events within that daily allowance | 50 | 10 |
| Retained events | 5,000 | 1,000 |
| Reserved outbound attempts per UTC day | 1,000 | 200 |
| Stored delivery records | 10,000 | — |

The HTTP receiver allows at most three destinations per event. Event and
attempt admission uses database transactions; it does not rely on KV counters.
Revoking or repairing tokens cannot reset event or delivery budgets. Retention
is seven days, with bounded scheduled cleanup; cleanup lag can cause admission
to stop earlier. Revoked ownership records are intentionally permanent so old
credentials cannot be claimed by another device. Their physical cap prevents
unbounded growth; reaching it requires operator review.

Preview, scanner, probe and coalesced observations share a smaller subset of the
daily allowance, preserving some capacity for activity. These classifications
are forgeable hints; they cannot reserve capacity against every attacker.

Unknown callbacks create no state. Denied requests still consume Worker
invocations and database reads. Native source limiters and edge rules can reduce
this load but do not guarantee availability under a distributed flood. A known
token flood can consume its owner's daily allowance. These limits accept that
availability tradeoff to keep stored evidence and outbound work bounded.

## Prepare staging

1. Inspect the current account's Workers subscription, D1/Queue allocations,
   usage, zone plan, existing WAF rules, and deployment-token scopes. Public
   product documentation does not establish which features this account has.
2. Copy the example to an environment-specific config; choose distinct staging
   D1, Queue (if used), rate-limit namespaces, domain, and secret values. Start
   enrollment closed or invite-only. Keep existing devices authorized.
3. Create the database and apply `worker/migrations/0001_state.sql` with Wrangler
   D1 migrations. Set `STORAGE_BACKEND=d1` and bind `SNARE_DB`. Missing required
   bindings must produce 503; never silently fall back to KV after cutover.
4. Use a dedicated test notification sink. Verify ownership, quotas, failure
   recovery, event history and correlated real-client proofs. Keep the Cron
   trigger enabled. See [delivery checks](webhook-delivery.md).
5. Measure actual Worker CPU, D1 rows read/written, queue operations, and storage.
   Include index writes and other applications sharing the account. Local tests
   cannot establish production CPU usage or account entitlements.

## Existing KV data

A fresh empty database must not replace existing device hashes or token owners.
A migration requires a consistent complete KV snapshot, not just active webhook
keys. Device secrets and webhook URLs are sensitive even though the repository
is public; save exports locally with owner-only permissions and never attach
them to issues, pull requests, or CI logs.

Use an explicit maintenance window: pause management writes and event ingestion
while taking and importing the final snapshot. Return temporary errors during
that window so clients do not mistake missing ingestion for success. A prior
staging rehearsal can use a suitably protected copy. Do not export live state
and then let KV continue changing before cutover without a reconciliation plan.

The [local migration helper and backup format](../worker/scripts/README.md) use a JSON array of `{ "name": "KV key",
"value": "JSON value" }` records (values may also be parsed objects). It requires
a complete set of referenced device records and rejects owner conflicts,
unknown key types, malformed state, or capacity violations. It reconstructs
revoked ownership from event history where the old registration was deleted.
It creates a new SQL file with mode 0600 and prints only counts and safe errors.
It does not contact Cloudflare or replay old notifications.

```sh
node worker/scripts/migrate-kv-to-d1.mjs /private/path/snare-kv.json /private/path/snare-import.sql
```

Apply generated SQL only to an initialized **empty** D1 schema. Rehearse the
exact export, conversion and import before production. Compare device/token and
event counts, verify original secrets still authenticate, and verify revoked
tokens cannot change owner. Review old events outside the new retention window;
do not silently drop ownership records or truncate a failed migration.

After validation, switch the Worker to the imported D1 binding and the desired
enrollment/rate policy in one controlled release. Retain the private KV snapshot
for recovery. A code rollback after D1 starts receiving writes must retain D1:
reverting to the old KV backend would abandon newer ownership and evidence.
Rollback across the storage boundary requires a reconciled backup, not only an
older Worker version.

## Hosted global webhook routing

New `use-global` registrations require the authenticated device ID in
`GLOBAL_WEBHOOK_DEVICE_IDS`. Existing global registrations can retain their
current route for compatibility. Audit those legacy registrations before
migration: their existing value does not by itself prove operator approval.
Do not import an unreviewed global route into an operator paging destination.

See [Cloudflare abuse controls](cloudflare-abuse-controls.md) for source limits,
invite enrollment, and disabled edge-rule examples that preserve SDK callbacks.
