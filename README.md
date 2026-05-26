# snare

**Compromise detection for AI agents via deception.**

Snare plants fake credentials in your agent's environment. When a hijacked agent goes hunting for credentials, it finds yours and phones home.

No daemon. No proxy. No policy changes.

---

## How it works

A hijacked AI agent does something a healthy one doesn't: it looks for credentials it was never told about and tries to use them.

Snare exploits this. It plants convincing fake credentials in the standard locations where real ones live. The precision canaries fire via SDK and OS plumbing — before any API call leaves the machine.

The `awsproc` canary uses AWS `credential_process` — a shell command that runs when the SDK resolves credentials. When a compromised agent runs `aws s3 ls --profile prod-admin`, the alert lands at T+0.01s. CloudTrail never sees it.

```ini
# ~/.aws/config
[profile prod-admin]
role_arn       = arn:aws:iam::123456789012:role/OrganizationAccountAccessRole
source_profile = prod-admin-source

[profile prod-admin-source]
credential_process = sh -c 'curl -sf https://snare.sh/c/{token} >/dev/null 2>&1; echo "{\"Version\":1,\"AccessKeyId\":\"AKIA...\",\"SecretAccessKey\":\"...\"}"'
```

The two-profile pattern matches how real AWS environments set up assume-role chains. A compromised agent sees a dormant-looking credential and tries to use it.

The agent sees a flaky AWS response. You see this:

```
🔑 AWS canary fired — agent-01
Token   agent-prod-admin-2026-••••••••
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

**Running AI agents on this machine?** Precision mode stays quiet during normal work unless the planted fake AWS profile, SSH host, or kube context is actively used. Use `--select` for an interactive picker, or `--all` to arm every canary type.

```
  ✓ initialized (device: dev-2146102a5849a7b3)

  Planting canaries...
  Precision mode: planting active-use canaries only (awsproc, ssh, k8s)
    ✓ awsproc      ~/.aws/config
    ✓ ssh          ~/.ssh/config
    ✓ k8s          ~/.kube/staging-deploy.yaml

  ✓ webhook test fired

  🪤 3 canaries armed. This machine is protected.

  Precision mode is safe for first run: alerts require active use of the fake
  AWS profile, SSH host, or kube context. Passive file reads do not fire them.

  Next checks:
    snare status   show event state; `never fired` is normal at first
    snare scan     verify planted files are present and unchanged
    snare doctor   confidence screen: config, API, ownership, and test health
    snare repair   re-sync registrations safely if doctor finds drift
    snare prove --run --report   safely trigger precision canaries and print a proof report
    snare prove --format json --redact --output proof.json   write a share-safe proof artifact
    snare events   view real hits when one arrives
```

Immediately after arming, `snare status` will usually show `never fired`. That is expected: it means Snare has not recorded a real callback for that canary yet. Use `snare scan` for local file integrity, `snare doctor` for setup health, and `snare prove --run --report` when you want to safely trigger the precision canaries and produce a first-success report. Add `--redact --output proof.json --format json` when you need a share-safe artifact for a teammate or issue.

To arm all canary types (including dotenv-based ones like OpenAI, Anthropic, etc.):

```sh
snare arm --all --webhook https://discord.com/api/webhooks/YOUR/WEBHOOK
```

Supported webhook destinations: Discord, Slack, Telegram, or any endpoint that accepts JSON. Treat webhook URLs as secrets — don't commit, screenshot, or share them.

Evaluating Snare for a team or lab? Start with the [enterprise evaluation guide](docs/enterprise-evaluation.md), then wire alerts to your SIEM with the [webhook integration docs](docs/integrations/generic-webhook.md).

---

## Commands

```sh
snare arm [--webhook <url>]  # precision mode: plant awsproc, ssh, k8s + test
snare arm --select           # interactive picker: choose which canaries to arm
snare arm --all              # plant all 18 canary types
snare disarm                 # remove all canaries (keep config)
snare disarm --purge         # remove canaries + ~/.snare/ config
snare status                 # show active canaries + event state
snare repair                 # re-register active tokens + run a live test check
snare sync                   # alias for snare repair
snare prove [--type <t>]     # guided precision trigger commands (awsproc/ssh/k8s)
snare prove --run --report   # execute safe triggers and print a proof report
snare prove --format json    # machine-readable proof report output
snare prove --redact --output proof.json --format json  # share-safe proof artifact
snare events                 # fetch recent alert history from snare.sh
snare events --summary       # ASN/UA distribution across all canaries
snare scan                   # check canary integrity on disk
snare test                   # fire a test alert to verify your webhook
snare doctor [--test]        # confidence screen; add --test for live callback proof
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

## Confidence loop (first 10 minutes)

After `snare arm`, the expected healthy loop is:

- `snare status` shows active canaries and event state. `never fired` is normal until someone actively uses a planted fake credential.
- `snare scan` is local-only integrity: present/modified/missing/orphaned files. It does not fire alerts.
- `snare doctor` is the confidence screen: config, callback health, local canary files, token ownership, events API readability, and webhook test history.
- `snare doctor --test` runs a live callback test and verifies it is readable in the events API.
- `snare test` sends a synthetic callback test only; check your webhook destination for the routed alert.
- `snare events` shows real hit history; empty output on fresh installs is expected.
- `snare repair` (or `snare sync`) safely re-registers active tokens and re-tests callback/event readability when drift is detected.
- `snare prove` prints safe precision trigger commands so you can intentionally prove alerts fire for `awsproc`, `ssh`, and `k8s`.
- `snare prove --run --report` executes those triggers, confirms callbacks through the events API, and prints a compact proof report with cleanup commands, event visibility, observed latency, and explicit proof/limitation notes.
- `snare prove --format json --redact --output proof.json` writes a machine-readable artifact with device IDs, token IDs, labels, cleanup tokens, and absolute local paths redacted.

Important state distinction:

- `never fired` means token is registered/readable and no real callback has happened yet.
- `events unavailable` means API/auth/readability failed for that token; run `snare doctor`, then `snare repair` if needed.

---

## Canary types

| Type | Location | Trigger | Tier |
|------|----------|---------|------|
| `awsproc` | `~/.aws/config` | AWS SDK credential resolution via `credential_process` — fires before any API call | Precision |
| `ssh` | `~/.ssh/config` | SSH connection via `ProxyCommand` curl/wget callback | Precision |
| `k8s` | `~/.kube/<name>.yaml` | `kubectl` exec credential callback, plus fake API server URL | Precision |
| `aws` | `~/.aws/credentials` | Any AWS SDK/CLI call via `endpoint_url` | High |
| `gcp` | `~/.config/gcloud/sa-*.json` | GCP auth attempt via `token_uri` redirect | High |
| `npm` | `~/.npmrc` | `npm install` of scoped package from fake registry | High |
| `git` | `~/.gitconfig` | Fake Git host URL rewrite plus credential-helper fallback | High |
| `pypi` | `~/.config/pip/pip.conf` | `pip install` queries fake extra index — **fires on your own installs too** | High-noisy |
| `openai` | `~/.env` | Any OpenAI SDK call via `OPENAI_BASE_URL` | Medium |
| `anthropic` | `~/.env.local` | Any Anthropic SDK call via `ANTHROPIC_BASE_URL` | Medium |
| `azure` | `~/.azure/service-principal-credentials.json` | Azure SDK token fetch via `tokenEndpoint` | Medium |
| `mcp` | `~/.config/mcp-servers*.json` | MCP client connects to fake HTTP server | Medium |
| `github` | `~/.config/gh/hosts.yml` | `gh` CLI targeting fake Enterprise host | Medium |
| `stripe` | `~/.config/stripe/config.toml` | Stripe CLI or agent following verify URL | Medium |
| `huggingface` | `~/.env.hf` | Any HF Hub SDK call via `HF_ENDPOINT` | Medium |
| `docker` | `~/.docker/config.json` (new file only) | `docker pull`/`login` to fake registry | Medium |
| `terraform` | `~/.terraformrc` | `terraform init` with provider under fake namespace | Medium |
| `generic` | `~/.env.production` | Any SDK reading `API_BASE_URL` | Medium |

**Precision** canaries fire via existing SDK and OS plumbing — near-zero false positives during normal work because they require active use of the planted fake profile, host, or context. Default with `snare arm`.

**High** canaries fire when the credential is actively used by anyone — human attacker, compromised agent, scanner.

**High-noisy** canaries fire readily, but may also trigger during normal developer workflows. `pypi` is useful for aggressive monitoring, not the quiet default.

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
role_arn       = arn:aws:iam::123456789012:role/OrganizationAccountAccessRole
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

Alerts are signed with `X-Snare-Signature` (HMAC-SHA256) when webhook signing is configured, so receivers can verify the sender.

See [generic webhooks](docs/integrations/generic-webhook.md), [Splunk](docs/integrations/splunk.md), [Datadog](docs/integrations/datadog.md), and [Microsoft Sentinel](docs/integrations/sentinel.md) for SIEM integration patterns.

---

## Privacy

Snare's callback handlers never read request bodies. When a canary fires, the worker returns a response before the body is consumed. Canary callbacks can carry real credentials or prompts in their body — the application code does not inspect them. In managed mode, Cloudflare still terminates the network request; self-host if you need full network-layer control.

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

Use self-hosting when you need a custom callback domain, full network-layer control, private retention, or SIEM relay behavior. The repo includes both the Cloudflare Worker source (`worker/`) and a standalone `snare serve` path with Docker Compose.

Quick standalone server:

```sh
SNARE_DASHBOARD_TOKEN="$(openssl rand -hex 32)" \
  snare serve --port 8080 --db /var/lib/snare/snare.db
```

Quick Docker Compose path:

```sh
{
  echo "SNARE_DASHBOARD_TOKEN=$(openssl rand -hex 32)"
  echo "SNARE_PORT=8080"
} > .env
docker compose up -d
curl -fsS http://localhost:8080/health
```

Only expose `snare serve` behind a reverse proxy you control. By default the server ignores `X-Forwarded-For` and `X-Real-IP`; set `--trusted-proxy <cidr,...>` only for proxy networks that are allowed to supply those headers.

See the [self-hosting guide](docs/self-hosting.md) for reverse proxy, backup, upgrade, Cloudflare Worker, and client `callback_base` steps.

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
