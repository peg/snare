# snare

**Compromise detection for AI agents via deception.**

Snare plants fake credentials in your agent's environment. If the agent gets hijacked and goes hunting for credentials, it finds yours — and you get an instant alert.

No daemon. No proxy. No policy changes. The bait phones home.

---

## How it works

A hijacked AI agent — one that's been prompt-injected or otherwise compromised — does something a healthy agent doesn't: it looks for credentials it wasn't told about and tries to use them.

Snare exploits this. It plants convincing fake AWS keys, GCP service accounts, GitHub tokens, and more in the standard locations where real credentials live. Each fake credential has the callback URL embedded as the **service endpoint**, not a comment:

```ini
# ~/.aws/credentials
[prod-us-east-1-legacy-2024]
aws_access_key_id     = AKIAW2U59XALOTHPSSEI
aws_secret_access_key = tw7gxwYkonjmX8zDSge0vTKeXuEuG3Q...
region                = us-east-1
endpoint_url          = https://snare.sh/c/your-token-here
```

When a hijacked agent calls `boto3.client("s3").list_buckets()` with that profile, the AWS SDK sends the request to `snare.sh` instead of `amazonaws.com`. You get an alert within a second.

The agent sees a flaky AWS response. You see this:

```
🔑 AWS canary fired — agent-01
Token   agent-01-9193baef57a260b20858a45a7a14a74a
Time    2026-03-14 04:07:33 UTC
IP      34.121.8.92       Location  Council Bluffs, US
Network Amazon Technologies Inc (AS16509)
UA      Boto3/1.34.46 md/Botocore#1.34.46 ua/2.0 os/linux#6.8.0...
⚠️ Likely AI agent   Request originated from Amazon Technologies Inc
```

The Boto3 user agent tells you exactly which SDK fired it. The ASN tells you it came from a cloud-hosted agent. **The credential itself is the sensor.**

---

## Install

```sh
curl -fsSL https://snare.sh/install | sh
```

Or download a binary from [releases](https://github.com/peg/snare/releases).

**Requirements:** Linux or macOS, no other dependencies.

---

## Quick start

```sh
snare arm --webhook https://discord.com/api/webhooks/YOUR/WEBHOOK
```

That's it. Snare initializes itself, plants canaries across all your credential locations, fires a test alert to confirm your webhook works, and reports what's armed.

```
  ✓ initialized (device: dev-2146102a5849a7b3)

  Planting canaries...
    ✓ aws          ~/.aws/credentials
    ✓ awsproc      ~/.aws/config
    ✓ gcp          ~/.config/gcloud/sa-prod-backup.json
    ✓ openai       ~/.env
    ✓ anthropic    ~/.env.local
    ✓ ssh          ~/.ssh/config
    ✓ k8s          ~/.kube/staging-deploy.yaml
    ✓ npm          ~/.npmrc
    ✓ mcp          ~/.config/mcp-servers-backup.json
    ✓ pypi         ~/.config/pip/pip.conf

  ✓ webhook test fired

  🪤 10 canaries armed. This machine is protected.
```

**Supported webhook destinations:** Discord, Slack, Telegram, PagerDuty, MS Teams.

---

## Commands

```sh
snare arm [--webhook <url>]  # initialize + plant all canaries + test
snare disarm                 # remove all canaries (keep config)
snare disarm --purge         # remove canaries + ~/.snare/ config
snare status                 # show active canaries + last-seen timestamps
snare test                   # fire a test alert to verify your webhook
snare rotate                 # rotate device secret (if config.json was exposed)
snare uninstall              # remove everything including the binary
```

Re-arming is idempotent — running `snare arm` again skips already-planted canaries and plants any that are missing:

```sh
snare arm                    # plants missing canaries, skips existing ones
```

For granular control:

```sh
snare plant --type aws       # plant a single canary type
snare plant --type k8s --label prod-cluster
snare teardown --token <id>  # remove a specific canary
snare teardown --dry-run     # preview what would be removed
```

---

## Canary types

| Type | Location | Trigger | Reliability |
|------|----------|---------|-------------|
| `aws` | `~/.aws/credentials` | Any AWS SDK/CLI call via `endpoint_url` | High |
| `awsproc` | `~/.aws/config` | AWS SDK credential resolution via `credential_process` | High |
| `gcp` | `~/.config/gcloud/sa-*.json` | GCP auth attempt via `token_uri` redirect | High |
| `openai` | `~/.env` | Any OpenAI SDK call via `OPENAI_BASE_URL` | High |
| `anthropic` | `~/.env.local` | Any Anthropic SDK call via `ANTHROPIC_BASE_URL` | High |
| `ssh` | `~/.ssh/config` | SSH connection via `ProxyCommand` callback | High |
| `k8s` | `~/.kube/<name>.yaml` | Any `kubectl` call to fake cluster | High |
| `npm` | `~/.npmrc` | `npm install` of scoped package from fake registry | High |
| `pypi` | `~/.config/pip/pip.conf` | `pip install` queries fake extra index | High |
| `mcp` | `~/.config/mcp-servers*.json` | MCP client connects to fake HTTP server | High |
| `github` | `~/.config/gh/hosts.yml` | `gh` CLI targeting fake Enterprise host | Medium |
| `stripe` | `~/.config/stripe/config.toml` | Stripe CLI or agent following verify URL | Medium |
| `generic` | `~/.env.production` | Any SDK reading `API_BASE_URL` | Medium |

**High reliability** canaries detect active exploitation — the callback URL is the service endpoint, so any API call using that credential hits snare.sh before the attacker can do anything else.

**Medium reliability** canaries fire under more specific conditions but still provide valuable coverage.

### awsproc: fires before any API call

The `awsproc` canary uses AWS `credential_process` — a shell command that runs when the SDK needs to fetch credentials. The callback fires at **credential resolution time**, before any AWS API call happens. Even cleaner than `endpoint_url`.

### mcp: first MCP config canary

The `mcp` canary plants a fake MCP server config in a discoverable but non-auto-loaded location. A compromised agent scanning the filesystem for MCP servers will find it and attempt to connect — the HTTP transport URL points to snare.sh. This is standalone from your active Claude/Cursor/VS Code configs and won't interfere with running tools.

---

## Alerts

Each alert includes:
- **Type + label** — which canary fired, what machine it was on
- **Timestamp** — exact UTC time
- **IP + location** — city, country
- **ASN** — hosting org (`Amazon Technologies Inc` = cloud agent, `Hetzner` = VPS, etc.)
- **User agent** — identifies exactly which SDK fired (`Boto3/1.34.46`, `kubectl/v1.35.1`, etc.)
- **"Likely AI agent"** — flagged when request originates from cloud infrastructure

Alerts are signed with `X-Snare-Signature` (HMAC-SHA256) so you can verify they came from snare.sh.

---

## Privacy

**Snare never reads request bodies.** When a canary fires, the worker returns a response before consuming the request body. Canary callbacks may carry real credentials or prompts in their body — we never see them.

Each fired alert stores only:
- Token ID, timestamp, IP, user agent, method, path, country, ASN

Your fake credential content is stored locally in `~/.snare/manifest.json` (0600) and never sent to snare.sh. Token IDs are 128-bit random hex — they can't be reversed to identify you or your configuration.

API access to your events requires authentication. Each machine gets a unique device secret (`~/.snare/config.json`, 0600). Other users of snare.sh cannot query your events.

---

## Side effects

> **PyPI:** `snare plant --type pypi` adds an `extra-index-url` to your pip config. Every `pip install` will also query snare.sh as an additional index. This means package names are visible in snare.sh request metadata when the canary fires. Use `snare teardown --type pypi` to revert.

> **npm:** `snare plant --type npm` adds a scoped registry entry. Only packages under the fake scope are affected — not all npm packages. Use `snare teardown --type npm` to revert.

---

## How it differs from canarytokens.org

[Canarytokens](https://canarytokens.org) is great. Snare is built for AI agents specifically:

| | Canarytokens | Snare |
|---|---|---|
| Setup | Manual, one token at a time | `snare arm` covers 10+ credential types at once |
| AWS detection | CloudTrail (minutes lag) | Direct SDK callback (sub-second) |
| Credential types | AWS + a few others | 13 types: AWS, GCP, GitHub, Stripe, OpenAI, Anthropic, SSH, k8s, npm, PyPI, MCP, and more |
| AI agent context | None | Cloud ASN detection, SDK user-agent parsing, `credential_process` timing |
| Fires on | Read or use (varies) | Use only — active exploitation, not passive scanning |

---

## Relationship to Rampart

Snare and [Rampart](https://rampart.sh) are complementary:

- **Rampart** enforces policy — it blocks agents from making calls they shouldn't
- **Snare** detects compromise — it catches agents that have been hijacked

Rampart blocks. Snare catches what gets through.

Neither requires the other. Both are stronger together.

---

## Self-hosting

The Cloudflare Worker is open source in this repo (`worker/`). Deploy to your own account:

```sh
cd worker
npx wrangler deploy
```

Set `WEBHOOK_URLS` as a Cloudflare Worker secret for alert delivery. Optionally set `WEBHOOK_SIGNING_SECRET` to sign outbound webhook requests.

To use a custom callback server, edit `callback_base` in `~/.snare/config.json` after `snare init`.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE).
