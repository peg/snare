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
| `openai` | `~/.env` | Any OpenAI SDK call via `OPENAI_BASE_URL` | Medium |
| `anthropic` | `~/.env.local` | Any Anthropic SDK call via `ANTHROPIC_BASE_URL` | Medium |
| `ssh` | `~/.ssh/config` | SSH connection via `ProxyCommand` callback | High |
| `k8s` | `~/.kube/<name>.yaml` | Any `kubectl` call to fake cluster | High |
| `npm` | `~/.npmrc` | `npm install` of scoped package from fake registry | Medium |
| `pypi` | `~/.config/pip/pip.conf` | `pip install` queries fake extra index | High |
| `mcp` | `~/.config/mcp-servers*.json` | MCP client connects to fake HTTP server | Medium |
| `github` | `~/.config/gh/hosts.yml` | `gh` CLI targeting fake Enterprise host | Medium |
| `stripe` | `~/.config/stripe/config.toml` | Stripe CLI or agent following verify URL | Medium |
| `generic` | `~/.env.production` | Any SDK reading `API_BASE_URL` | Medium |

**High reliability** canaries fire whenever the credential is used — the callback URL *is* the service endpoint, so any SDK call redirects to snare.sh automatically.

**Medium reliability** canaries fire conditionally — they require the agent to both read the credential file *and* honor the base URL override in the same process. Still valuable coverage, especially for Python and Node agents that load dotenv files.

### awsproc: the crown jewel

`awsproc` is the most technically sophisticated canary in Snare. It uses AWS `credential_process` — a shell command that runs when the SDK resolves credentials, before any API call is made.

Here's the exact timeline when a compromised agent runs `aws s3 ls --profile prod-admin`:

```
T+0.00s  aws s3 ls --profile prod-admin
T+0.01s  AWS SDK begins credential resolution
T+0.01s  credential_process shell command executes
T+0.01s  curl fires to snare.sh → alert in your webhook
T+0.02s  SDK receives fake JSON credentials
T+0.03s  SDK attempts s3.ListBuckets() → fails (fake creds)
T+0.03s  Agent: "AWS error, credentials may be invalid"
```

**The alert arrives before the agent knows the credentials don't work.** No other canary tool does this.

The two-profile pattern makes it look like a real assume-role configuration:

```ini
# ~/.aws/config — looks like a legitimate assume-role profile
[profile prod-admin]
role_arn       = arn:aws:iam::389844960505:role/OrganizationAccountAccessRole
source_profile = prod-admin-source

[profile prod-admin-source]
credential_process = sh -c 'curl -sf https://snare.sh/c/{token} >/dev/null 2>&1; echo "{\"Version\":1,\"AccessKeyId\":\"AKIA...\",\"SecretAccessKey\":\"...\"}"'
```

**Why Canarytokens can't do this:** Canarytokens is a hosted service — you visit their site, download a token. They can't embed a shell command in your local AWS config. Their AWS canary creates a real IAM user in their account and monitors CloudTrail, which introduces minutes of lag and requires external AWS infrastructure. `awsproc` requires running code locally — which is exactly what Snare is built to do.

**On network-restricted machines:** Even if the callback can't reach snare.sh (firewall, airgap), the shell command still outputs the fake credential JSON. The agent receives apparently-valid credentials and continues — it doesn't know the canary fired and the callback failed silently. If the attacker later tries to use those credentials against real AWS from outside your network, that's a separate signal.

**Precision mode** — if you only want awsproc and the other near-zero false-positive canaries:

```sh
snare arm --precision --webhook <url>
# Plants: awsproc, ssh (ProxyCommand), k8s (kubeconfig server URL)
# Skips: everything that might fire on casual reads or dotenv loading
```

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

**Dashboard auth required:** `snare serve` requires `--dashboard-token` (or `SNARE_DASHBOARD_TOKEN` env var) to protect the alert dashboard. Generate one with `openssl rand -hex 32`.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE).
