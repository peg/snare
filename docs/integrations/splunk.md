# Splunk integration

Splunk HTTP Event Collector (HEC) usually requires an `Authorization: Splunk <token>` header. Snare's generic webhook sender does not add custom destination headers, so the recommended pattern is:

```text
Snare -> HTTPS relay -> Splunk HEC
```

The relay keeps the Splunk token server-side, verifies Snare's webhook signature when configured, and wraps the event in a HEC envelope.

## HEC relay example

```python
import hmac
import hashlib
import os
import time
import requests
from flask import Flask, abort, request

app = Flask(__name__)
SNARE_WEBHOOK_SECRET = os.environ.get("SNARE_WEBHOOK_SECRET", "").encode()
SPLUNK_HEC_URL = os.environ["SPLUNK_HEC_URL"]  # e.g. https://splunk.example.com:8088/services/collector/event
SPLUNK_HEC_TOKEN = os.environ["SPLUNK_HEC_TOKEN"]
SPLUNK_INDEX = os.environ.get("SPLUNK_INDEX", "security")


def verify_signature(raw: bytes) -> None:
    if not SNARE_WEBHOOK_SECRET:
        return
    header = request.headers.get("X-Snare-Signature", "")
    expected = "sha256=" + hmac.new(SNARE_WEBHOOK_SECRET, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(header, expected):
        abort(401)


@app.post("/snare")
def snare_to_splunk():
    raw = request.get_data()
    verify_signature(raw)
    event = request.get_json(force=True)

    hec_event = {
        "time": time.time(),
        "host": event.get("device_id") or "snare",
        "source": "snare",
        "sourcetype": "snare:json",
        "index": SPLUNK_INDEX,
        "event": event,
    }

    resp = requests.post(
        SPLUNK_HEC_URL,
        headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"},
        json=hec_event,
        timeout=5,
    )
    if resp.status_code >= 300:
        return {"error": "splunk write failed", "status": resp.status_code}, 502
    return {"status": "ok"}
```

Run it behind TLS and point Snare at the relay URL:

```sh
snare config set webhook https://relay.example.com/snare
snare doctor --test
```

## Suggested field mapping

Keep the original Snare event under `event` so no context is lost. Common fields to extract in Splunk props/transforms or SPL are:

| Splunk field | Snare JSON path |
|---|---|
| `snare_event` | `event.event` |
| `snare_canary_type` | `event.canary_type` |
| `snare_label` | `event.label` |
| `snare_device_id` | `event.device_id` |
| `src_ip` | `event.ip` |
| `http_user_agent` | `event.request.user_agent` |
| `asn` | `event.network.asn` |
| `asn_org` | `event.network.org` |
| `is_cloud` | `event.network.is_cloud` |
| `is_test` | `event.is_test` |

## Example searches

Recent real canary fires:

```spl
index=security sourcetype=snare:json event.event="canary.fired" event.is_test=false
| table _time event.canary_type event.label event.ip event.network.org event.request.user_agent
```

Cloud-hosted sources:

```spl
index=security sourcetype=snare:json event.network.is_cloud=true event.is_test=false
| stats count by event.network.org event.canary_type event.label
```

Noisy tests by host/device:

```spl
index=security sourcetype=snare:json event.is_test=true
| stats count max(_time) as last_test by host event.device_id
```

## Validation

1. Run `snare doctor --test` and confirm a test event lands in Splunk with `event.is_test=true`.
2. Run `snare prove --run --report --redact --format json --output proof.json` and confirm real precision proof callbacks land with `event.is_test=false`.
3. Confirm the relay rejects a modified body when `SNARE_WEBHOOK_SECRET` is set.
