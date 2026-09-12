# Offline KV-to-D1 migration

`migrate-kv-to-d1.mjs` reads a **local JSON backup** and creates a new SQL file. It has no Cloudflare authentication or network operations, creates no database, and sends no notifications.

From the repository root, using Node 22:

```sh
node worker/scripts/migrate-kv-to-d1.mjs /private/path/backup.json /private/path/import.sql
```

The output is created exclusively with mode `0600`. An existing output file or symlink is never overwritten. Standard output contains only numeric counts in JSON; failures print a fixed error code without record values, token IDs, hashes, or URLs. The SQL file itself necessarily contains credential hashes, webhook destinations, and event metadata, so keep it with the private backup.

## Backup format

The root must be an array of `{ "name": string, "value": object | string }` entries. A string value must contain the original JSON-encoded KV value. Include the complete values, not just the result of listing KV keys. No `base64`, `metadata`, or `expiration` fields are accepted in this normalized input format.

For example, the following shows the structure; replace placeholders with original stored values:

```json
[
  {
    "name": "device:dev-example",
    "value": {
      "secret_hash": "<original 64-character hexadecimal SHA-256 hash>",
      "created_at": "2026-09-01T00:00:00.000Z"
    }
  },
  {
    "name": "webhook:example_token_001",
    "value": {
      "device_id": "dev-example",
      "webhook_url": "use-global",
      "canary_type": "aws",
      "label": "build job",
      "registered_at": "2026-09-01T00:00:00.000Z"
    }
  }
]
```

Recognized persistent keys are `device:<id>`, `webhook:<token>`, `owner:<token>`, and `event:<token>:<epoch-milliseconds>:<unique-suffix>`. Known transient `rl:` and `dedup:` keys are counted and skipped. Unknown key types, duplicate identities, malformed values, or conflicting owners fail the entire conversion before output is created. A deleted registration with retained, consistently owned events becomes a revoked tombstone. Missing event ownership or a missing corresponding device hash requires private operator investigation; the converter never guesses ownership from a current registration.

Existing event IDs and valid proof IDs are preserved. Events without IDs receive `legacy_` plus the SHA-256 digest of their KV key, making repeated conversions stable. Event metadata is rebuilt from the bounded allowlist; arbitrary body/authorization fields are discarded. Historical events create no outbox entries and cannot replay notifications. Tokens deleted before backup with no remaining owner record or owned history cannot be reconstructed from absent data.

## Restore procedure and limits

Quiesce writes before taking a complete backup; an eventually consistent, partial export cannot be treated as a transactionally consistent snapshot. Check the count report and resolve every conflict before proceeding. The converter accepts at most 64 MiB, 30,000 entries, and 64 KiB per persistent KV value, and rejects imports exceeding the default D1 device/token/event capacity limits rather than silently truncating them.

Apply `worker/migrations/0001_state.sql` to a new, empty target first. Then import the generated SQL. Its first data statement rejects a populated target; it never replaces existing ownership or merges into a live database. The generated file omits explicit `BEGIN`/`COMMIT` because [D1 SQL imports manage transactions](https://developers.cloudflare.com/d1/best-practices/import-export-data/).

The converter preserves the admission timestamp encoded in each event's KV key, including its UTC quota day. Existing retention policy applies after activation. In particular, `eventsOutsideRetention` reports events older than the current seven-day window that scheduled cleanup will remove. A large same-day historical import can already consume that day's admission budget. Review this before cutover. Verify restored device ownership, tombstones, event counts, and a staging proof before binding the new database to a production receiver. The converter performs none of those remote steps.
