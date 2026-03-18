# snare

**Compromise detection for AI agents via deception.**

Snare plants fake credentials in your agent's environment. When a hijacked agent goes hunting for credentials, it finds yours and phones home.

No daemon. No proxy. No policy changes.

---

## How it works

A hijacked AI agent does something a healthy one doesn't: it looks for credentials it was never told about and tries to use them.

Snare exploits this. It plants convincing fake AWS keys, GCP service accounts, GitHub tokens, and more in the standard locations where real credentials live. Each fake credential has the callback URL baked in as the **service endpoint**, not a comment:

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

The Boto3 user agent tells you which SDK fired it. The ASN tells you it came from a cloud-hosted agent. **The credential itself is the sensor.**

---

## Install

```sh
curl -fsSL https://snare.sh/install | sh
```

Or with Homebrew:

```sh
brew install peg/tap/snare
```

Or download a binary from [releases](https://github.com/peg/snare/releases).

Requires Linux or macOS. No other dependencies.

---

## Quick start

```sh
snare arm --webhook https://discord.com/api/webhooks/YOUR/WEBHOOK
```

That's it. Snare initializes, plants the highest-signal canaries, fires a test alert to confirm the webhook works, and tells you what's armed.

By default, `snare arm` uses **precision mode**: only `awsproc`, `ssh`, and `k8s` canaries are planted. These fire via existing SDK and OS plumbing with near-zero false positive risk.

**Running AI agents on this machine?** The default precision mode won't fire on your own tooling. Use `--select` for an interactive picker, or `--all` to arm every canary type.

```
  ✓ initialized (device: dev-2146102a5849a7b3)

  Planting canaries...
  Precision mode: planting highest-signal canaries only (awsproc, ssh, k8s)
    ✓ awsproc      ~/.aws/config
    ✓ ssh          ~/.ssh/config
    ✓ k8s          ~/.kube/staging-deploy.yaml

  ✓ webhook test fired

  🪤 3 canaries armed. This machine is protected.
```

To arm all canary types (including dotenv-based ones like OpenAI, Anthropic, etc.):

```sh
snare arm --all --webhook https://discord.com/api/webhooks/YOUR/WEBHOOK
```

Supported webhook destinations: Discord, Slack, Telegram, PagerDuty, MS Teams.

---

## Commands

```sh
snare arm [--webhook <url>]  # precision mode: plant awsproc, ssh, k8s + test
snare arm --select           # interactive picker: choose which canaries to arm
snare arm --all              # plant all 18 canary types
snare disarm                 # remove all canaries (keep config)
snare disarm --purge         # remove canaries + ~/.snare/ config
snare status                 # show active canaries + last-seen timestamps
snare events                 # fetch recent alert history from snare.sh
snare events --summary       # ASN/UA distribution across all canaries
snare scan                   # check canary integrity on disk
snare test                   # fire a test alert to verify your webhook
snare doctor                 # validate configuration and canary health
snare config                 # show current config
snare config set webhook <url>  # update webhook URL
snare rotate                 # rotate device secret (if config.json was exposed)
snare serve [--dashboard-token <token>]  # run self-hosted callback server
snare uninstall              # remove everything including the binary
```

`snare arm` is idempotent. Running it again skips canaries that are already planted and adds any that are missing.

For more control:

```sh
snare plant --type aws       # plant a single canary type
snare plant --type k8s --label prod-cluster
snare teardown --token <id>  # remove a specific canary
snare teardown --dry-run     # preview what would be removed
```

---

## Canary types

| Type | Location | Trigger | Tier |
|------|----------|---------|------|
| `awsproc` | `~/.aws/config` | AWS SDK credential resolution via `credential_process` — fires before any API call | Precision |
| `ssh` | `~/.ssh/config` | SSH connection via `ProxyCommand` callback | Precision |
| `k8s` | `~/.kube/<name>.yaml` | Any `kubectl` call to fake cluster | Precision |
| `aws` | `~/.aws/credentials` | Any AWS SDK/CLI call via `endpoint_url` | High |
| `gcp` | `~/.config/gcloud/sa-*.json` | GCP auth attempt via `token_uri` redirect | High |
| `npm` | `~/.npmrc` | `npm install` of scoped package from fake registry | High |
| `git` | `~/.gitconfig` | `git credential fill` against fake host via `credential.helper` | High |
| `pypi` | `~/.config/pip/pip.conf` | `pip install` queries fake extra index — **fires on your own installs too** | High |
| `openai` | `~/.env` | Any OpenAI SDK call via `OPENAI_BASE_URL` | Medium |
| `anthropic` | `~/.env.local` | Any Anthropic SDK call via `ANTHROPIC_BASE_URL` | Medium |
| `azure` | `~/.azure/service-principal-credentials.json` | Azure SDK token fetch via `tokenEndpoint` | Medium |
| `mcp` | `~/.config/mcp-servers*.json` | MCP client connects to fake HTTP server | Medium |
| `github` | `~/.config/gh/hosts.yml` | `gh` CLI targeting fake Enterprise host | Medium |
| `stripe` | `~/.config/stripe/config.toml` | Stripe CLI or agent following verify URL | Medium |
| `huggingface` | `~/.env.hf` | Any HF Hub SDK call via `HF_ENDPOINT` | Medium |
| `docker` | `~/.docker/config.json` | `docker pull`/`login` to fake registry | Medium |
| `terraform` | `~/.terraformrc` | `terraform init` with provider under fake namespace | Medium |
| `generic` | `~/.env.production` | Any SDK reading `API_BASE_URL` | Medium |

**Precision** canaries fire via existing SDK and OS plumbing — near-zero false positives, no side effects on your own tooling. Default with `snare arm`.

**High** canaries fire when the credential is actively used by anyone — human attacker, compromised agent, scanner. Some (pypi) have side effects on your own installs.

**Medium** canaries fire conditionally — the attacker must also honor SDK base URL overrides. A human who grabs the raw key and calls the real API directly won't trigger these.

### awsproc

`awsproc` uses AWS `credential_process` — a shell command that runs when the SDK resolves credentials, before any API call is made.

Timeline when a compromised agent runs `aws s3 ls --profile prod-admin`:

```
T+0.00s  aws s3 ls --profile prod-admin
T+0.01s  AWS SDK begins credential resolution
T+0.01s  credential_process shell command executes
T+0.01s  curl fires to snare.sh -> alert in your webhook
T+0.02s  SDK receives fake JSON credentials
T+0.03s  SDK attempts s3.ListBuckets() -> fails (fake creds)
T+0.03s  Agent: "AWS error, credentials may be invalid"
```

**The alert arrives before the agent knows the credentials don't work.** CloudTrail-based tools like Canarytokens see the API call; awsproc fires before it exists.

The two-profile pattern looks like a real assume-role setup:

```ini
# ~/.aws/config
[profile prod-admin]
role_arn       = arn:aws:iam::389844960505:role/OrganizationAccountAccessRole
source_profile = prod-admin-source

[profile prod-admin-source]
credential_process = sh -c 'curl -sf https://snare.sh/c/{token} >/dev/null 2>&1; echo "{\"Version\":1,\"AccessKeyId\":\"AKIA...\",\"SecretAccessKey\":\"...\"}"'
```

Canarytokens can't do this. Their AWS canary creates a real IAM user and monitors CloudTrail, which adds minutes of lag and requires external AWS infrastructure. `awsproc` runs locally, which is the whole point.

On airgapped or firewalled machines: even if the callback can't reach snare.sh, the shell command still returns fake credential JSON. The agent gets apparently-valid creds and keeps going. If it later tries to use them from outside your network, that fires separately.

This is why `awsproc`, `ssh`, and `k8s` are planted by default — they fire only on active credential use, making them the best choice for machines running AI agents.

### mcp

Plants a fake MCP server config in a discoverable but non-auto-loaded location. A compromised agent scanning for MCP servers will find it and attempt to connect. The HTTP transport URL points to snare.sh. It won't interfere with your active Claude/Cursor/VS Code configs.

---

## Alerts

Each alert includes:

- Which canary fired and what machine it was on
- Timestamp (UTC)
- IP, city, country
- ASN (hosting org — `Amazon Technologies Inc` = cloud agent, `Hetzner` = VPS, etc.)
- User agent (identifies the exact SDK: `Boto3/1.34.46`, `kubectl/v1.35.1`, etc.)
- "Likely AI agent" flag when the request comes from cloud infrastructure

Alerts are signed with `X-Snare-Signature` (HMAC-SHA256) so you can verify they came from snare.sh.

---

## Privacy

Snare never reads request bodies. When a canary fires, the worker returns a response before the body is consumed. Canary callbacks can carry real credentials or prompts in their body — we never see them.

Each alert stores only: token ID, timestamp, IP, user agent, method, path, country, ASN.

Fake credential content lives locally in `~/.snare/manifest.json` (0600) and is never sent to snare.sh. Token IDs are 128-bit random hex. Other snare.sh users can't query your events.

---

## Side effects

> **PyPI:** `snare plant --type pypi` adds an `extra-index-url` to your pip config. Every `pip install` will query snare.sh as an additional index, which means package names show up in request metadata when the canary fires. Run `snare teardown --type pypi` to remove it.

> **npm:** `snare plant --type npm` adds a scoped registry entry. Only packages under the fake scope are affected. Run `snare teardown --type npm` to remove it.

---

## vs. canarytokens.org

[Canarytokens](https://canarytokens.org) is good. Snare is built specifically for AI agents:

| | Canarytokens | Snare |
|---|---|---|
| Setup | Manual, one token at a time | `snare arm` covers 18 credential types |
| AWS detection | CloudTrail (minutes lag) | Direct SDK callback (sub-second) |
| Credential types | AWS + a few others | 18 types: AWS, GCP, SSH, k8s, git, terraform, OpenAI, Anthropic, npm, PyPI, MCP, and more |
| AI agent context | None | Cloud ASN detection, SDK user-agent parsing, `credential_process` timing |
| Fires on | Read or use (varies) | Use only |

---

## Relationship to Rampart

[Rampart](https://rampart.sh) enforces policy and blocks agents from making calls they shouldn't. Snare detects when an agent has already been compromised. They solve different parts of the problem and work fine independently.

---

## Self-hosting

The Cloudflare Worker is open source in this repo (`worker/`). Deploy it to your own account:

```sh
cd worker
npx wrangler deploy
```

Set `WEBHOOK_URLS` as a Cloudflare Worker secret for alert delivery. Set `WEBHOOK_SIGNING_SECRET` to sign outbound requests.

To point canaries at your own server instead of snare.sh, edit `callback_base` in `~/.snare/config.json` after `snare init`.

`snare serve` requires `--dashboard-token` (or `SNARE_DASHBOARD_TOKEN`) to protect the dashboard. Generate one with `openssl rand -hex 32`.

---

## Verifying releases

Release checksums are signed with [Sigstore/cosign](https://docs.sigstore.dev/) using keyless OIDC signing via GitHub Actions. To verify a downloaded release:

```sh
cosign verify-blob --bundle checksums.txt.bundle checksums.txt
```

This confirms the checksums file was produced by the official GitHub Actions release workflow and has not been tampered with.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE).
