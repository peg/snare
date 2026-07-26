# Snare Architecture

## Overview

Snare is a compromise detection tool for AI agents. It plants fake credentials in standard locations, with callback URLs embedded as service endpoints. When a hijacked agent tries to use those credentials, the SDK redirects to snare.sh — and you get an instant alert.

**Key design choices:**

- **No daemon** — bait phones home directly via SDK redirect, no local process needed
- **Fires on USE, not READ** — inotify/audit-log approaches detect file reads; Snare detects active exploitation
- **Self-reporting credentials** — the callback URL is the service endpoint (`endpoint_url`, `token_uri`), not a comment. The SDK makes the call, not the attacker.
- **Content-matching teardown** — stores exact bytes written at plant time; finds and removes verbatim. No byte offsets (breaks when files change).

---

## Components

### CLI (`cmd/snare`, `internal/`)

A single static binary. No runtime dependencies.

```
cmd/snare/main.go          entrypoint, passes version string
internal/cli/cli.go        command routing, flag parsing, arm/disarm/rotate
internal/bait/bait.go      template rendering, file plant/remove
internal/manifest/         manifest.json CRUD, atomic writes
internal/config/           ~/.snare/config.json init/load/save, device registration
internal/token/            crypto/rand key generation per canary type
```

**Local state** (all under `~/.snare/`, mode 0700):
- `config.json` — device ID, device secret, callback base URL, optional webhook URL (0600)
- `manifest.json` — active canaries: path, mode, content hash, callback URL, timestamps (0600)

Nothing is stored server-side except event metadata and webhook registrations.

### Cloudflare Worker (`worker/`)

Deployed at `snare.sh`. Receives callbacks when bait is accessed.

**Routes:**

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET/POST` | `/c/{token}[/*]` | None | Canary callback — fires alert, returns 1×1 GIF |
| `POST` | `/api/devices` | None (first-time) | Create server-assigned device ID |
| `POST` | `/api/register` | Bearer device_secret | Register webhook + metadata for a token |
| `POST` | `/api/revoke` | Bearer device_secret | Remove a token registration |
| `GET` | `/api/events/{token}` | Bearer device_secret | Retrieve recent events for a token |
| `GET` | `/health` | None | Returns `{"status":"ok"}` |

**Auth model:**

Device secret is generated client-side (`crypto/rand`, 32 bytes) during `snare init`. SHA-256 hash stored in KV keyed by device ID on first use. Subsequent calls validate against the stored hash.

Device IDs are server-assigned via `POST /api/devices` — clients cannot choose or squat IDs. Falls back to local random ID if server is unreachable at init time.

`/c/{token}` has **no auth** by design — SDKs and tools must hit this URL without knowing it's a canary.

**KV namespace: `snare-events`**

| Key pattern | Value | TTL |
|---|---|---|
| `device:{device_id}` | `{secret_hash, created_at}` | No expiry |
| `webhook:{token_id}` | `{webhook_url, device_id, canary_type, label, registered_at}` | 365 days |
| `event:{token}:{timestamp}:{uuid}` | event JSON (see below) | 90 days |
| `dedup:{token}:{ip}:{minute}` | `1` | 120 seconds |
| `rl:{scope}:{window}` | request count | 2× window duration |

**Event JSON fields:** `token`, `is_test`, `timestamp`, `ip`, `userAgent`, `method`, `path`, `country`, `city`, `asn`, `asnOrg`, `botScore`, `sdkHints`

**No `body` field** — ever. Request bodies are never read, stored, or forwarded.

**Rate limiting:**
- `/api/*` — 30 requests/minute per IP
- `/c/{token}` — 10 alerts/minute per token (prevents alert flooding if token ID leaks)

**Webhook delivery:**

1. Load per-token webhook registration from KV (`webhook:{token_id}`)
2. Fall back to global `WEBHOOK_URLS` CF secret if no per-token registration
3. Fire all webhooks in parallel via `Promise.allSettled`
4. Failures logged to CF Workers Logs but don't affect the response

Outbound webhook requests include `X-Snare-Signature: sha256=<hmac>` when the Cloudflare Worker `WEBHOOK_SIGNING_SECRET` secret is configured. Receivers can verify alerts came from the configured Snare callback deployment.

**Supported webhook formats:** Discord (embed), Slack (attachment), Telegram (HTML), generic JSON (`event: "canary.fired"`).

---

## Canary Types

| Type | Location | Mechanism | Trigger | Reliability |
|------|----------|-----------|---------|-------------|
| `awsproc` | `~/.aws/config` | `credential_process` shell command | AWS SDK credential resolution | Precision |
| `ssh` | `~/.ssh/config` | `ProxyCommand curl` callback | SSH connection attempt | Precision |
| `k8s` | `~/.kube/<name>.yaml` | kubeconfig `server` URL | Any `kubectl` call | Precision |
| `git` | `~/.gitconfig` | scoped URL rewrite | Fake-host clone or remote lookup | Precision |
| `npm` | `~/.npmrc` | scoped registry URL | Fake-scope package lookup | Precision |
| `aws` | `~/.aws/config` | `endpoint_url` redirect | Named-profile AWS SDK/CLI call | High |
| `gcp` | `~/.config/gcloud/sa-*.json` | `token_uri` redirect | GCP OAuth token refresh | High |
| `pypi-upload` | `~/.pypirc` or inert backup | named upload repository | Explicit internal-repository upload | High |
| `pypi` | `~/.config/pip/pip.conf` | `extra-index-url` | `pip install` (queries all indexes) | High-noisy |
| `openai` | `~/.env` | `OPENAI_BASE_URL` redirect | Agent reads dotenv AND honors base URL | Medium |
| `anthropic` | `~/.env.local` | `ANTHROPIC_BASE_URL` redirect | Agent reads dotenv AND honors base URL | Medium |
| `mcp` | vendor-adjacent inert JSON backup | Streamable HTTP transport URL | Explicit MCP client `initialize` request | Medium |
| `huggingface` | `~/.env.hf` | `HF_INFERENCE_ENDPOINT` redirect | Agent loads dotenv and uses inference | Medium |
| `terraform` | `~/.terraformrc` | provider network mirror | `terraform init` for fake namespace | Medium |
| `generic` | `~/.env.production` | `API_BASE_URL` | Custom SDK clients | Medium |

**Precision reliability** = callback is wired into SDK/OS credential plumbing and requires active attempted use of the planted fake profile, host, or context.

**High reliability** = callback URL is on a credential-use path, but the agent must find and use the planted credential.

**Medium reliability** = callback URL is less standardized or requires specific agent behavior to trigger.

The `awsproc` canary uses a **two-profile pattern** for maximum realism:

```ini
# Visible assume-role profile (what attackers scan for)
[profile prod-admin]
role_arn = arn:aws:iam::982736450123:role/OrganizationAccountAccessRole
source_profile = prod-admin-source

# Hidden credential_process source (fires the callback)
[profile prod-admin-source]
credential_process = sh -c 'curl -sf https://snare.sh/c/{token} >/dev/null 2>&1; echo "{\"Version\":1,\"AccessKeyId\":\"AKIA...\",\"SecretAccessKey\":\"...\"}"'
```

**Firing timeline** for `aws s3 ls --profile prod-admin`:

```
T+0.00s  AWS SDK begins credential resolution for profile prod-admin
T+0.01s  Follows source_profile chain → prod-admin-source
T+0.01s  Executes credential_process shell command
T+0.01s  curl fires callback → alert delivered to webhook
T+0.02s  Shell command outputs fake JSON credentials
T+0.02s  SDK receives {"Version":1,"AccessKeyId":"AKIA...","SecretAccessKey":"..."}
T+0.03s  SDK attempts real AWS API call with fake creds → fails
```

The alert arrives **before the attacker's first API call lands on AWS**. CloudTrail-based detection would not see the credential resolution step at all.

**Network-restricted behavior:** If the callback URL is unreachable (firewall, airgap), curl fails silently and the shell command still outputs the fake credential JSON. The agent receives apparently-valid credentials and continues unaware. The canary remains deceptive on restricted networks.

**Precision mode** — `snare arm` defaults to five narrowly scoped, real-client-tested canaries:

| Type | Fires when | False positive risk |
|------|------------|---------------------|
| `awsproc` | AWS credential resolution | Essentially zero |
| `ssh` | SSH connection attempt via ProxyCommand | Near zero |
| `k8s` | kubectl/SDK call to fake cluster | Near zero |
| `git` | Git operation against the planted fake host | Near zero |
| `npm` | npm lookup under the planted fake scope | Near zero |

These five share a property: they require **active attempted use** of a planted fake target, not just file reads or environment scanning.

---

## Plant Flow (Transactional)

```
1. Render bait content (dry-run, no disk write)
2. Write manifest record with status="pending"
3. Write bait to disk:
   - New files: O_CREATE|O_EXCL|O_WRONLY — fails if file exists
   - Append: O_CREATE|O_APPEND|O_WRONLY — checks for duplicate token ID first
4. Register token with snare.sh (best-effort, non-blocking)
5. Activate manifest record
```

If step 3 fails, the manifest record stays in "pending" state — detectable and cleanable via `snare teardown --force`.

Registration (step 4) associates the token with the device secret so events can be queried via `snare status`. Uses `"use-global"` sentinel when no local webhook is configured, which binds ownership while routing delivery through the global CF fallback.

---

## Teardown Flow

```
1. Load manifest, find canary by ID (or all active)
2. Read current file from disk
3. Verify content hash matches planted content
   - Mismatch without --force: error (someone may have added real data)
   - Mismatch with --force: warn and proceed
4. For ModeNewFile: os.Remove()
5. For ModeAppend: find exact content block, write file without it
   - Preserve original file permissions
   - Atomic rename (write to .tmp, rename)
6. Revoke token registration from snare.sh (best-effort)
7. Mark canary inactive in manifest
```

Teardown only touches bytes that snare wrote. Real credentials in the same file are never modified.

---

## Device Secret Rotation

```sh
snare rotate
```

Generates a new 256-bit device secret, saves to `~/.snare/config.json`, and re-registers all active tokens with the new secret. If a local webhook is configured, tokens are re-registered immediately. If using the global CF fallback, re-registration is automatic on the next `snare arm` cycle.

If the device secret is compromised (e.g., `~/.snare/config.json` was read by an attacker), run `snare rotate` immediately. The old secret becomes invalid.

---

## Token Generation

All tokens use `crypto/rand`. Formats match real credentials exactly — no giveaway strings:

| Token | Format |
|---|---|
| AWS Key ID | `AKIA` + 16 uppercase alphanumeric |
| AWS Secret | 40 chars, base64 charset |
| GitHub PAT | `ghp_` + 36 alphanumeric |
| Stripe live key | `sk_live_` + 24 chars |
| OpenAI key | `sk-proj-` + 48 alphanumeric |
| Anthropic key | `sk-ant-api03-` + 48 chars |
| GCP client email | `{name}@{project}.iam.gserviceaccount.com` |
| Canary token ID | `{label}-` + 32 hex chars (128-bit random) |
| Device ID | `dev-` + 32 hex chars (128-bit random, server-assigned) |
| Device secret | 64 hex chars (256-bit random, client-generated) |

`SNARE`, `FAKE`, `TEST`, `canary` never appear in generated key material.

---

## Privacy Guarantees

**Callback traffic (`/c/{token}`):**
- Request body is **never read, stored, or forwarded** — worker returns the response before consuming the body
- Canary callbacks may carry real credentials or sensitive data in their body; the worker is deliberately body-blind
- Only header-derived metadata is stored: IP, user agent, method, path, country, ASN

**Management API (`/api/*`):**
- Request bodies are read (JSON payloads for registration/revocation)
- These contain only: token IDs, webhook URLs, device IDs — never credentials or user data

**Network layer:**
- Cloudflare terminates TLS and transports all requests
- The privacy guarantee applies to snare.sh application code, not the underlying network
- Self-hosting the worker provides full network-layer privacy

---

## Known Limitations

1. **Manifest is an attacker cheat sheet** — `~/.snare/manifest.json` (0600) lists every canary path and token ID. An attacker who reads this file knows which credentials are bait. Mitigation: protect `~/.snare/` with file integrity monitoring.

2. **KV eventual consistency** — Cloudflare KV is eventually consistent. Rate limiting and dedup counters can race under high concurrency. Strict atomicity requires Durable Objects (planned for v2).

3. **Domain fingerprinting** — `snare.sh` is a known domain once the project is public. Sophisticated attackers could avoid triggering canaries by detecting the domain. Mitigation: custom callback domains (enterprise feature, planned).

4. **GitHub/Stripe canaries are weaker** — these don't redirect SDK calls; they rely on agents following embedded URLs. A sophisticated attacker inspecting credentials before use may not trigger them.

---

## Self-Hosting

The worker source is in `worker/`. Deploy to your own Cloudflare account:

```sh
cd worker
npx wrangler deploy
```

Configure a custom callback base:

```sh
snare arm --webhook https://your-webhook.example.com
```

> **Note:** The `callback_base` in `~/.snare/config.json` defaults to `https://snare.sh/c`. To use a custom worker, edit `callback_base` directly after `snare init`. Custom callback domains void the managed privacy guarantee — your deployment controls what gets logged.

Set `WEBHOOK_URLS` as a Cloudflare Worker secret for alert delivery, and optionally `WEBHOOK_SIGNING_SECRET` for `X-Snare-Signature` verification.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE).
