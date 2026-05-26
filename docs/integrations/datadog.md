# Datadog integration

Datadog Logs intake can accept the API key in the URL path, so Snare can send generic JSON directly. Use a relay instead if your organization forbids secrets in webhook URLs or requires request signing before ingestion.

## Direct Logs intake

Use the Datadog site that matches your account.

US site example:

```sh
snare config set webhook 'https://http-intake.logs.datadoghq.com/v1/input/<DATADOG_API_KEY>?ddsource=snare&service=snare&ddtags=team:security,env:pilot'
snare doctor --test
```

EU site example:

```sh
snare config set webhook 'https://http-intake.logs.datadoghq.eu/v1/input/<DATADOG_API_KEY>?ddsource=snare&service=snare&ddtags=team:security,env:pilot'
snare doctor --test
```

Treat the configured webhook URL as a secret because it contains the Datadog API key.

## Recommended facets

Create facets or measures from these JSON fields:

| Datadog facet | Snare JSON path |
|---|---|
| `@event` | `event` |
| `@canary_type` | `canary_type` |
| `@label` | `label` |
| `@device_id` | `device_id` |
| `@ip` | `ip` |
| `@network.org` | `network.org` |
| `@network.asn` | `network.asn` |
| `@network.is_cloud` | `network.is_cloud` |
| `@request.user_agent` | `request.user_agent` |
| `@is_test` | `is_test` |

## Example log queries

Real canary fires:

```text
service:snare @event:canary.fired @is_test:false
```

Cloud-hosted source:

```text
service:snare @event:canary.fired @is_test:false @network.is_cloud:true
```

Specific canary type:

```text
service:snare @canary_type:awsproc @is_test:false
```

## Monitor example

Create a Logs monitor with query:

```text
logs("service:snare @event:canary.fired @is_test:false").index("*").rollup("count").last("5m") > 0
```

Notification text:

```text
Snare canary fired.

Type: {{log.attributes.canary_type}}
Label: {{log.attributes.label}}
IP: {{log.attributes.ip}}
Network: {{log.attributes.network.org}}
User-Agent: {{log.attributes.request.user_agent}}
```

## Validation

```sh
snare doctor --test
snare prove --run --report --redact --format json --output proof.json
```

Confirm `is_test:true` appears for the doctor test and `is_test:false` appears for proof callbacks.
