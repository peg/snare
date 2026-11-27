# Snare docs

These docs are written for security engineers evaluating, piloting, or operating Snare beyond a single local test.

- [Enterprise evaluation](enterprise-evaluation.md) — data flow, files touched, safe pilot checklist, proof artifact workflow, and limitations.
- [Self-hosting](self-hosting.md) — Docker Compose, `snare serve`, Cloudflare Worker deployment notes, reverse proxy guidance, backups, and upgrades.
- [Receiver activation](receiver-activation.md) — D1 quotas, staged activation, private KV migration, and rollback boundaries.
- [Cloudflare abuse controls](cloudflare-abuse-controls.md) — enrollment, native limits, and edge-rule candidates that preserve SDK callbacks.
- [Durable webhook delivery](webhook-delivery.md) — queue topology, privacy-preserving message contract, retry policy, and rollout gates.
- [Generic webhooks](integrations/generic-webhook.md) — event schema, signature verification, and relay guidance.
- [Splunk integration](integrations/splunk.md) — Splunk HEC relay pattern and field mapping.
- [Datadog integration](integrations/datadog.md) — direct Logs intake and monitor examples.
- [Microsoft Sentinel integration](integrations/sentinel.md) — Log Analytics relay pattern and KQL examples.
