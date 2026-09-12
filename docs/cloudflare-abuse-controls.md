# Cloudflare abuse controls

Snare receives automated requests by design. Protecting the hosted service must
preserve callbacks from SDKs, command-line clients, and cloud infrastructure.
This document describes the receiver policy helpers and candidate deployment
settings. Examples do not configure an account or activate an edge rule.

## Input and enrollment policy

`worker/policy.js` exposes small helpers for the HTTP handler:

| Helper | Contract |
|---|---|
| `readManagementJSON(request)` | Reads at most 8,192 actual body bytes, including chunked requests. Requires uncompressed `application/json`. Rejects non-object JSON and refuses to access bodies outside `/api/*`. |
| `validateManagementBody(operation, body)` | Returns only validated fields for `devices`, `register`, `revoke`, or `rotate`. Unknown properties are discarded. |
| `authorizeEnrollment(request, env)` | Authorizes a **new device** under `ENROLLMENT_MODE`; call only on `POST /api/devices`, before creating state. |
| `authorizeGlobalWebhook(deviceId, env)` | Returns whether that exact device ID appears in `GLOBAL_WEBHOOK_DEVICE_IDS`. Caller must authenticate the device first. |
| `sanitizeCallbackMetadata(metadata)` | Copies only known metadata, caps string byte lengths, rejects nested values in scalar fields, and excludes bodies and credential fields. |
| `enforceSourceRateLimit(request, env, operation)` | Applies the binding for `enrollment`, `api`, or `callback` to a bounded source key. |
| `enforceDeviceRateLimit(env, verifiedDeviceId, operation)` | Applies a separate key for `register`, `revoke`, `rotate`, or `events`. Caller must authenticate before invoking it. |

Policy failures use `PolicyError` with `status`, `code`, and a safe `message`.
Rate failures include `retryAfter: 60`, a conservative delay covering both
supported binding periods. The handler should translate these to JSON errors
and the `Retry-After` header for management requests. An upstream failure must
not be represented as an empty successful event history.

Token IDs contain 8–80 ASCII letters, digits, hyphens or underscores. Device IDs
use the same alphabet with 1–80 characters to retain older enrolled IDs.
Device secrets and enrollment tokens contain 32–256 printable, non-whitespace
ASCII characters. Registration URLs are at most 2,048 UTF-8 bytes, HTTPS, and
contain no username/password; fragments are removed. Domain allowlisting is a
separate mandatory check at registration and every outbound send. Labels are
at most 128 UTF-8 bytes. Canary types use a bounded lowercase identifier so
future client types can remain compatible. Stored metadata has individual
byte limits, including 512 for user agents and 1,024 for paths.

`Content-Length` is an early rejection hint, not the enforcement mechanism.
The reader stops when actual stream bytes exceed the limit. The callback path
must never call a JSON/text/body reader. Sanitizing metadata does not make an
arbitrary user-supplied string non-sensitive; populate its source from the
existing explicit header-presence and connection-metadata extraction only.

Enrollment modes:

- `open`: new device enrollment is allowed by this helper, subject to rate
  limits and persistent admission quotas. This is the default when unset, for
  compatibility with self-hosting.
- `invite`: requires the separate Worker secret `SNARE_ENROLLMENT_TOKEN` in
  `Authorization: Bearer ...`. The CLI already sends this header when its
  `SNARE_ENROLLMENT_TOKEN` environment variable is set. Expected and presented
  tokens are hashed and compared with the Workers timing-safe API. Portable
  runtimes use native Web Crypto HMAC verification as the comparison fallback.
- `closed`: refuses new devices. Invalid modes, or invite mode without a valid
  configured secret, fail closed.

Changing enrollment mode does not revoke existing devices. Do not apply the
enrollment check to their registration, event-read, revocation, or rotation
requests. Keep invitation credentials separate from device management secrets.
Do not commit either secret to Wrangler configuration.

Global operator destinations need explicit approval. `GLOBAL_WEBHOOK_DEVICE_IDS`
is a comma-separated list of exact device IDs; no wildcard or prefix match is
accepted. An unset/empty list approves no new global routing. Existing global
registrations may only retain approval through a deliberate migration policy;
the helper does not infer trust from a public registration's `use-global` value.
Authentication alone does not grant permission to page the operator.

## Native burst limits

The helpers do not write KV counters and have no in-memory/KV counter fallback.
When a binding is configured, exceptions or malformed binding responses cause
503; a denied request causes 429. When bindings are absent, self-hosted use is
allowed and the helper returns `{ enforced: false }`. Set
`RATE_LIMITS_REQUIRED: "true"` for a managed deployment that must refuse requests
when its expected limiter is missing. An invalid required-mode value also
fails closed. Do not describe a deployment without bindings as rate limited.

This example uses hypotheses for a small deployment, not measured universal
defaults. Apply appropriate numeric namespace IDs unique within the account,
and choose different IDs for staging. This is a configuration fragment only:

```json
{
  "vars": {
    "ENROLLMENT_MODE": "invite",
    "RATE_LIMITS_REQUIRED": "true",
    "GLOBAL_WEBHOOK_DEVICE_IDS": ""
  },
  "ratelimits": [
    { "name": "ENROLLMENT_RATE_LIMITER", "namespace_id": "1101", "simple": { "limit": 3, "period": 60 } },
    { "name": "API_SOURCE_RATE_LIMITER", "namespace_id": "1102", "simple": { "limit": 120, "period": 60 } },
    { "name": "CALLBACK_SOURCE_RATE_LIMITER", "namespace_id": "1103", "simple": { "limit": 600, "period": 60 } },
    { "name": "API_DEVICE_RATE_LIMITER", "namespace_id": "1104", "simple": { "limit": 120, "period": 60 } }
  ]
}
```

Bindings are not inherited by named Wrangler environments. Include them
explicitly in staging configuration. The device helper separates operation
keys, so the last example gives each operation its own allowance; it does not
limit all operations together to 120. Use the database's token/admission quotas
for resource totals. Source IP is a coarse abuse control: many legitimate users
can share one IP. The Worker helper uses Cloudflare's `CF-Connecting-IP` and
does not accept an arbitrary `X-Forwarded-For` identity.

The binding is permissive, eventually consistent, and local to the Cloudflare
location serving the request. Neither these limits nor per-source limits are
an exact global quota or spending cap. Bound active devices/tokens, retained
events, and outbound attempts using atomic storage separately. Limiters execute
after the Worker starts, so rejected requests still consume an invocation.
[Rate Limiting binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)

Source rate limits should run before expensive lookups. Device limits must run
after authentication so a forged device ID cannot consume another owner's
allowance. Unknown tokens must create no stored events, persistent rate state,
or delivery messages. Under a known-token flood, preserve bounded first-event
evidence and a bounded indication of suppression. Writing a row or incrementing
a persistent counter for every rejected callback defeats the cost control.

## Candidate Free-zone rules

The website zone's plan and the Workers subscription are separate. A Free zone
includes five custom rules (no regex or Log action) and one rate-limiting rule.
Inspect the actual zone's existing rules before making changes. Free rate rules
support path/verified-bot expressions, IP counting, and 10-second counting and
mitigation periods. [Custom rule limits](https://developers.cloudflare.com/waf/custom-rules/),
[Rate-rule limits](https://developers.cloudflare.com/waf/rate-limiting-rules/)

This disabled candidate spends the single rate-rule slot on new enrollment:

```json
{
  "description": "Snare enrollment burst limit",
  "expression": "http.request.uri.path eq \"/api/devices\"",
  "action": "block",
  "ratelimit": {
    "characteristics": ["cf.colo.id", "ip.src"],
    "period": 10,
    "requests_per_period": 5,
    "mitigation_timeout": 10
  },
  "enabled": false
}
```

Do not add a hostname or method expression to this Free rate-rule example:
those fields require a higher plan. This path rule therefore also matches the
same path on other proxied hostnames in the zone, including staging if present.
Cloudflare's `cf.colo.id` counting characteristic is mandatory in the API and
means these counters are per data center.
[Counter scope](https://developers.cloudflare.com/waf/rate-limiting-rules/request-rate/)

A separate disabled **custom** rule can reject unsupported management methods:

```json
{
  "description": "Reject unsupported Snare management methods",
  "expression": "http.host eq \"snare.sh\" and ((http.request.uri.path in {\"/api/devices\" \"/api/register\" \"/api/revoke\" \"/api/rotate\"} and http.request.method ne \"POST\") or (starts_with(http.request.uri.path, \"/api/events/\") and http.request.method ne \"GET\"))",
  "action": "block",
  "enabled": false
}
```

These are individual rule candidates, not a replacement ruleset. Validate
matching paths, URL normalization, legitimate methods, staging, and CLI bursts
before enabling. Free custom rules cannot run in Log-only mode. An edge block
may return Cloudflare's own error response; the CLI must handle its status and
back off without assuming every edge response is Snare JSON.

Do not apply CAPTCHA, JavaScript challenges, browser cookie checks, blanket bot
blocking, or cloud-provider/geographic restrictions to `/c/*`. Free Bot Fight
Mode cannot be skipped with a WAF custom rule and can break the native clients
Snare is trying to observe. Keep automatic DDoS protection. If a managed WAF
signature blocks a real callback contract, investigate that specific rule and
use the narrowest justified exception rather than disabling all security.
[Bot Fight Mode limitations](https://developers.cloudflare.com/bots/get-started/bot-fight-mode/)

Do not use `http.request.body.size` in a Free custom rule; that field requires
Enterprise. Application management-body bounds remain necessary.
[Body-size field](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.size/)

## Verification and operating limits

Exercise real-client proofs through staging's edge rules, plus concurrent
enrollment, shared-NAT CLI bursts, oversized/chunked JSON, unknown tokens, known
token floods, backend failures, and multiple-location limit behavior. Protect
delivery retries with timeouts, capped attempts, destination revalidation, and
stable delivery IDs. Queue expiry and dead letters must leave owner-visible
failure status outside the queue.

Free resource exhaustion can cause unavailability. Workers Paid starts with a
monthly base subscription and includes usage; higher usage can be billed.
Budget alerts notify; they are not hard spending stops. Measure request, row,
queue, and retained-byte usage for the actual account and leave headroom for
other projects. Avoid per-request logging of unknown or suppressed callbacks.
[Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)

Policy implementation was checked against current Workers documentation,
`@cloudflare/workers-types` 5.20260911.1 and Wrangler 4.131.0's configuration
schema. References describe capability; they do not establish which features
are enabled in the deployed account.
