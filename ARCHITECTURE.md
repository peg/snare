# Snare Architecture

## Overview

Snare is a compromise detection tool for AI agents. It plants fake credentials in standard locations, with callback URLs embedded as service endpoints. When a hijacked agent tries to use those credentials, the SDK redirects to snare.sh — and you get an instant alert.

**Key design choices:**

- **No daemon** — bait phones home directly via SDK redirect, no local process needed
- **Fires on USE, not READ** — inotify/audit-log approaches detect file reads; Snare detects actual API calls
- **Self-reporting credentials** — the callback URL is the service endpoint (`endpoint_url`, `token_uri`), not a comment. The SDK makes the call, not the attacker.
- **Content-matching teardown** — stores exact bytes written at plant time; finds and removes verbatim. No byte offsets (breaks when files change).

---

## Components

### CLI (`cmd/snare`, `internal/`)

A single static binary. No runtime dependencies.

```
cmd/snare/main.go          entrypoint, passes version string
internal/cli/cli.go        command routing, flag parsing
internal/bait/bait.go      template rendering, file plant/remove
internal/manifest/         manifest.json CRUD, atomic writes
internal/config/           ~/.snare/config.json init/load/save
internal/token/            crypto/rand key generation
```

**Local state** (all under `~/.snare/`, mode 0700):
- `config.json` — device ID, callback base URL, webhook URL (0600)
- `manifest.json` — active canaries: path, mode, content, hash, timestamps (0600)

Nothing is stored server-side except callback events.

### Cloudflare Worker (`worker/`)

Deployed at `snare.sh`. Receives callbacks when bait is accessed.

**Routes:**
- `GET/POST /c/{token}` — callback receiver; logs event to KV, fires webhooks, returns 1×1 GIF
- `GET /health` — returns `{"status":"ok"}`

**KV namespace: `snare-events`**

| Key pattern | Value | TTL |
|---|---|---|
| `event:{uuid}` | `{token, ip, ua, timestamp, method, body}` | 7 days |
| `dedup:{token}:{ip}` | `1` | 60 seconds |

Dedup key prevents alert floods: same token+IP within 60 seconds fires only once.

**Webhook delivery:** Worker reads `WEBHOOK_URLS` CF secret (comma-separated). Fires all webhooks in parallel via `Promise.allSettled`. Failures are logged but don't fail the request.

**Alert format:** Discord/Slack embed with token ID, timestamp, IP, city, ASN, user agent, and "Likely AI agent" indicator when request comes from known cloud ASNs (AWS, GCP, Azure, Cloudflare).

---

## Canary Types

| Type | Target File | SDK Redirect Field | Trigger | Reliability |
|------|-------------|-------------------|---------|-------------|
| `aws` | `~/.aws/credentials` | `endpoint_url` | Any boto3/AWS SDK call | High |
| `gcp` | `~/.config/gcloud/sa-*.json` | `token_uri` | GCP auth attempt | High |
| `github` | `~/.config/gh/hosts.yml` | `api_endpoint` | `gh` CLI call to fake host | Medium |
| `stripe` | `~/.config/stripe/config.toml` | comment URL | Agent following verify link | Medium |
| `openai` | `~/.env.local` | `OPENAI_BASE_URL` | Any OpenAI SDK call | High |
| `anthropic` | `~/.env.local` | `ANTHROPIC_BASE_URL` | Any Anthropic SDK call | High |
| `generic` | `~/.env.local` | `API_BASE_URL` | Custom SDK clients | Medium |

**High reliability** = callback URL is a real SDK config field; any API call using that credential hits snare.sh.

**Medium reliability** = callback URL is in a comment or less-standardized field; fires under specific conditions.

---

## Plant Flow (Transactional)

```
1. Render bait content (dry-run, no disk write)
2. Write manifest record with InactiveReason="pending"
3. Write bait to disk (O_EXCL for new files, O_APPEND for existing)
   - New file: full file is bait
   - Append: add block with sentinel markers, preserve existing content + permissions
4. Activate manifest record (remove InactiveReason)
```

If step 3 fails, the manifest record stays in "pending" state — detectable and cleanable via `snare teardown --force`.

---

## Teardown Flow

```
1. Load manifest, find canary by ID
2. Read current file from disk
3. Verify content hash matches (detect file modifications)
   - Mismatch: error unless --force
4. For ModeNewFile: os.Remove()
5. For ModeAppend: find exact content block, write file without it
   - Preserve original file permissions
   - Atomic rename (write to .tmp, rename)
6. Mark canary inactive in manifest
```

The teardown only touches bytes that snare wrote. Real credentials in the same file are never modified.

---

## Token Generation

All tokens use `crypto/rand`. Formats match real credentials exactly:

| Token | Format | Example |
|---|---|---|
| AWS Key ID | `AKIA` + 16 uppercase alphanumeric | `AKIAFLMSTWYSM6H9JE60` |
| AWS Secret | 40 chars, base64 charset | `CoXZ2UMcbR5LMG+wosok...` |
| GitHub PAT | `ghp_` + 36 alphanumeric | `ghp_tAPcckcEZMJnn...` |
| Stripe live key | `sk_live_` + 24 chars | `sk_live_xK9mPqRt...` |
| OpenAI key | `sk-proj-` + 48 alphanumeric | `sk-proj-FNPhMPM...` |
| Anthropic key | `sk-ant-api03-` + 48 chars | `sk-ant-api03-UPS...` |
| GCP key ID | 40 hex chars | `6e5b6a0e2c8d...` |
| GCP private key | Fake RSA PEM (1190 random bytes) | `-----BEGIN RSA...` |
| Canary ID | `{label}-` + 32 hex | `openclaw-fe7d31ff...` |

No giveaway strings. `SNARE`, `FAKE`, `TEST`, `canary` never appear in generated key material.

---

## Known Limitations

1. **Manifest is an attacker cheat sheet** — `~/.snare/manifest.json` (0600) contains the exact content of every canary. An attacker who exfiltrates the manifest knows which files are bait and can avoid them. This is inherent to the design. Mitigation: protect `~/.snare/` with file integrity monitoring (Rampart policy).

2. **No HMAC on callbacks** — anyone who knows a token ID can fire a false alert. Token IDs are 32 hex chars (128-bit entropy), so brute force isn't practical, but there's no cryptographic proof that a callback came from the actual credential being accessed.

3. **Stripe/GitHub canaries are weaker** — they don't redirect SDK calls; they rely on the agent following a URL embedded in config. A sophisticated attacker inspecting credentials before use would recognize the `snare.sh` domain.

4. **Content-hash teardown requires stable files** — if the credential file is modified between plant and teardown (e.g., by another tool), hash verification fails. Use `--force` to skip the check.

---

## Self-Hosting

The worker is MIT-licensed and fully deployable:

```sh
cd worker
wrangler deploy
```

Point the CLI at your own worker:

```sh
SNARE_CALLBACK_BASE=https://your-worker.workers.dev/c snare init
```

Set `WEBHOOK_URLS` as a Cloudflare Worker secret to receive alerts.
