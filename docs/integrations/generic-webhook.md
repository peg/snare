# Generic webhook integration

Snare sends alert payloads to Discord, Slack, Telegram, or generic JSON webhook endpoints. A generic webhook is any HTTPS endpoint that accepts a JSON `POST` without requiring custom request headers. If your destination requires custom headers, use a small relay.

## Generic payload schema

Generic endpoints receive a JSON object shaped like this:

```json
{
  "event": "canary.fired",
  "is_test": false,
  "token": "agent-prod-admin-2026-abc123...",
  "canary_type": "awsproc",
  "label": "agent-01",
  "device_id": "dev-...",
  "timestamp": "2026-03-14T04:07:33.000Z",
  "ip": "203.0.113.10",
  "location": {
    "city": "Council Bluffs",
    "country": "US"
  },
  "network": {
    "asn": 16509,
    "org": "Amazon Technologies Inc.",
    "is_cloud": true
  },
  "request": {
    "method": "GET",
    "user_agent": "Boto3/1.34.46 md/Botocore#1.34.46",
    "path": "/c/agent-prod-admin-2026-abc123",
    "sdk_hints": {
      "amzSdkRequest": null,
      "amzTarget": null,
      "contentType": null,
      "hasAwsSig": false,
      "isPost": false
    }
  },
  "bot_score": null,
  "privacy": "request_body_never_captured"
}
```

Callback request bodies are intentionally omitted. Do not build downstream detection logic that expects Snare to forward request bodies.

## Signature verification

Cloudflare Worker deployments can set `WEBHOOK_SIGNING_SECRET`. When configured, the Worker signs outbound webhook bodies with HMAC-SHA256 and sends:

```http
X-Snare-Signature: sha256=<hex-hmac>
```

Verify the signature over the exact raw request body before parsing JSON.

```python
import hmac
import hashlib
from flask import Flask, abort, request

app = Flask(__name__)
SNARE_WEBHOOK_SECRET = b"replace-with-secret"

@app.post("/snare")
def snare():
    raw = request.get_data()
    header = request.headers.get("X-Snare-Signature", "")
    expected = "sha256=" + hmac.new(SNARE_WEBHOOK_SECRET, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(header, expected):
        abort(401)

    event = request.get_json(force=True)
    # Forward to SIEM, alerting system, or queue here.
    return {"status": "ok"}
```

If the header is absent, the upstream deployment did not configure webhook signing. Do not silently treat unsigned webhooks as verified.

## Relay guidance

Use a relay when the destination requires any of the following:

- custom authorization headers;
- request signing;
- vendor-specific envelope format;
- private network access;
- filtering, enrichment, or redaction before ingestion.

A relay should:

1. accept only HTTPS;
2. verify `X-Snare-Signature` when available;
3. reject oversized bodies;
4. parse and validate JSON;
5. add destination-specific auth headers from server-side secrets;
6. forward only the fields required by the destination;
7. return a 2xx only after the downstream write succeeds or is durably queued.

## Testing

Use a live test before depending on an alert path:

```sh
snare doctor --test
snare prove --run --report --redact --format json --output proof.json
```

In the destination, distinguish test events with `is_test: true` from real canary callbacks.
