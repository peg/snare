# Microsoft Sentinel integration

Microsoft Sentinel commonly ingests custom application events through Azure Monitor Logs / Log Analytics endpoints that require signed authorization headers. Snare's generic webhook sender does not add custom destination headers, so the recommended pattern is:

```text
Snare -> HTTPS relay -> Azure Monitor Logs / Sentinel workspace
```

Use the relay to verify Snare's webhook signature, transform the payload, and sign the Azure request with workspace credentials or a Data Collection Rule endpoint.

## Relay responsibilities

- Terminate TLS.
- Verify `X-Snare-Signature` when your Snare deployment sets `WEBHOOK_SIGNING_SECRET`.
- Store Azure credentials in server-side secrets, not in Snare webhook URLs.
- Preserve the original Snare payload or a documented normalized subset.
- Return a non-2xx response if Azure ingestion fails.

## Legacy Log Analytics Data Collector relay shape

The older Log Analytics Data Collector API signs each request with the workspace shared key. Use the newer Azure Monitor Logs ingestion API and Data Collection Rules if that is your organization's standard; the same relay pattern applies.

```python
import base64
import datetime
import hashlib
import hmac
import json
import os
import requests
from flask import Flask, abort, request

app = Flask(__name__)
SNARE_WEBHOOK_SECRET = os.environ.get("SNARE_WEBHOOK_SECRET", "").encode()
WORKSPACE_ID = os.environ["LOG_ANALYTICS_WORKSPACE_ID"]
SHARED_KEY = os.environ["LOG_ANALYTICS_SHARED_KEY"]
LOG_TYPE = os.environ.get("LOG_ANALYTICS_LOG_TYPE", "Snare_CL")


def verify_snare(raw: bytes) -> None:
    if not SNARE_WEBHOOK_SECRET:
        return
    header = request.headers.get("X-Snare-Signature", "")
    expected = "sha256=" + hmac.new(SNARE_WEBHOOK_SECRET, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(header, expected):
        abort(401)


def build_signature(date: str, content_length: int, method: str, content_type: str, resource: str) -> str:
    x_headers = "x-ms-date:" + date
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    decoded_key = base64.b64decode(SHARED_KEY)
    digest = hmac.new(decoded_key, string_to_hash.encode("utf-8"), hashlib.sha256).digest()
    encoded_hash = base64.b64encode(digest).decode("utf-8")
    return f"SharedKey {WORKSPACE_ID}:{encoded_hash}"


@app.post("/snare")
def snare_to_sentinel():
    raw = request.get_data()
    verify_snare(raw)
    event = request.get_json(force=True)

    body = json.dumps([event])
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    signature = build_signature(date, len(body), method, content_type, resource)

    url = f"https://{WORKSPACE_ID}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
    headers = {
        "Content-Type": content_type,
        "Authorization": signature,
        "Log-Type": LOG_TYPE,
        "x-ms-date": date,
    }
    resp = requests.post(url, data=body, headers=headers, timeout=10)
    if resp.status_code >= 300:
        return {"error": "azure ingestion failed", "status": resp.status_code, "body": resp.text[:200]}, 502
    return {"status": "ok"}
```

Point Snare at the relay:

```sh
snare config set webhook https://relay.example.com/snare
snare doctor --test
```

## Suggested normalized columns

If you transform events before ingestion, preserve at least:

| Column | Snare JSON path |
|---|---|
| `Event` | `event` |
| `IsTest` | `is_test` |
| `CanaryType` | `canary_type` |
| `Label` | `label` |
| `DeviceId` | `device_id` |
| `SourceIp` | `ip` |
| `NetworkOrg` | `network.org` |
| `NetworkAsn` | `network.asn` |
| `IsCloud` | `network.is_cloud` |
| `UserAgent` | `request.user_agent` |
| `RequestMethod` | `request.method` |
| `RequestPath` | `request.path` |

## KQL examples

Recent real canary fires:

```kusto
Snare_CL
| where Event_s == "canary.fired" and IsTest_b == false
| project TimeGenerated, CanaryType_s, Label_s, SourceIp_s, NetworkOrg_s, UserAgent_s
```

Cloud-hosted sources:

```kusto
Snare_CL
| where Event_s == "canary.fired" and IsTest_b == false and IsCloud_b == true
| summarize Count=count() by NetworkOrg_s, CanaryType_s, Label_s
```

Test coverage by device:

```kusto
Snare_CL
| where IsTest_b == true
| summarize LastTest=max(TimeGenerated), Count=count() by DeviceId_s
```

## Validation

1. Run `snare doctor --test` and confirm an `IsTest=true` event in Sentinel.
2. Run `snare prove --run --report --redact --format json --output proof.json` and confirm precision proof callbacks with `IsTest=false`.
3. Tamper with a signed webhook body in a relay unit test and confirm the relay rejects it.
