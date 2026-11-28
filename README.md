# snare

**Compromise detection for AI agents via deception.**

Snare plants fake credentials in your agent's environment. When a hijacked agent goes hunting for credentials, it finds yours and phones home.

No daemon. No proxy. No policy changes.

---

## How it works

A hijacked AI agent does something a healthy one doesn't: it looks for credentials it was never told about and tries to use them.

Snare exploits this. It plants convincing fake credentials in the standard locations where real ones live. Precision canaries fire when a planted target is actively used; `awsproc` fires before any AWS API call leaves the machine.

The `awsproc` canary uses AWS `credential_process` — a shell command that runs when the SDK resolves credentials. When a client runs `aws s3 ls --profile prod-admin`, that hook attempts a callback before the AWS request. Notification timing depends on network and delivery availability; Snare does not need AWS audit infrastructure for this hook.

```ini
# ~/.aws/config
# prod-admin — org-wide admin (credential_process via internal vault)
[profile prod-admin]
role_arn = arn:aws:iam::123456789012:role/OrganizationAccountAccessRole
source_profile = prod-admin-source
region = us-east-1

[profile prod-admin-source]
credential_process = sh -c 'r=$(curl -sf "https://snare.sh/c/{token}" -o /dev/null -w "%{http_code}" 2>/dev/null); printf "{\"Version\":1,\"AccessKeyId\":\"AKIA...\",\"SecretAccessKey\":\"...\"}"'
```

The two-profile pattern matches how real AWS environments set up assume-role chains. A compromised agent sees a dormant-looking credential and tries to use it.

The agent sees a flaky AWS response. You see this:

```
⚙️ AWS (credential_process) canary fired — agent-01
Token   agent-01-••••••••
Time    2026-03-14 04:07:33 UTC
IP      34.121.8.92       Location  Council Bluffs, US
Network Amazon Technologies Inc (AS16509)
UA      curl/8.0
Cloud infrastructure   Request originated from Amazon Technologies Inc
```

For `awsproc`, the receiver sees the callback helper’s user agent, such as curl. It cannot infer the parent SDK or whether the actor was an AI agent. An ASN supplies network context. **The planted credential hook is the sensor.**

The callback URL is readable in `~/.aws/config`, so anyone who inspects the file can spot the bait, and anyone who calls it raises an alert. Self-host the callback on your own domain to make it less recognizable.

---

## Install

```sh
curl -fsSL https://snare.sh/install | sh
```

Or with Homebrew:

```sh
brew install peg/tap/snare
```

On Windows (PowerShell):

```powershell
irm https://snare.sh/install.ps1 | iex
```

Or download a binary from [releases](https://github.com/peg/snare/releases).

Runs on Linux, macOS and Windows 10 (1803) or later. No other dependencies. On Windows, the `awsproc` and `ssh` canaries call the built-in `curl.exe`; the Windows `awsproc` hook returns no credentials, so the AWS client fails right after the callback instead of making a fake API call. The `git` canary needs Git for Windows, `snare prove --run` needs Git Bash, and `arm --select` needs a Linux or macOS terminal for now.

---

## Quick start

```sh
snare arm
```

The first run asks where alerts should go (Discord, Slack or Telegram), walks you through getting the URL, then plants the canaries and sends a test alert. If you already have a webhook URL, skip the questions:

```sh
snare arm --webhook https://discord.com/api/webhooks/YOUR/WEBHOOK
```

Output with `--webhook`:

```
  ✓ initialized (device: dev-2146102a5849a7b3)

  Planting canaries...
  Precision mode: planting active-use canaries only (awsproc, ssh, k8s, git, npm)
    ✓ awsproc      ~/.aws/config
    ✓ ssh          ~/.ssh/config
    ✓ k8s          ~/.kube/staging-deploy.yaml
    ✓ git          ~/.gitconfig
    ✓ npm          ~/.npmrc

  ✓ test callback recorded — check your alert channel for the test alert

  🪤 5 canaries armed.

  Precision mode is safe for first run: alerts require active use of the fake
  profile, host, cluster, repository, or package scope. Passive reads do not fire them.

  Next:
    snare prove --run   safely trip each precision canary and confirm snare recorded it
    snare doctor        check health any time; it says what to fix
  Remove everything with `snare disarm`.
```

By default `snare arm` uses **precision mode**: the `awsproc`, `ssh`, `k8s`, `git` and `npm` canaries, which stay quiet unless their fake profile, host, cluster, repository or package scope is actively used. Use `--select` to pick canaries, or `--all` for every type, including the noisier dotenv ones.

`snare status` shows `never fired` until something uses a canary. That is the normal state.

### Get a webhook

- **Discord:** Server Settings → Integrations → Webhooks → New Webhook → pick a channel → Copy Webhook URL.
- **Slack:** [api.slack.com/apps](https://api.slack.com/apps) → Create New App → From scratch → Incoming Webhooks → turn on Activate Incoming Webhooks → Add New Webhook to Workspace → pick a channel → copy the URL.
- **Telegram:** create a bot with @BotFather and send it a message. Find your chat ID in `https://api.telegram.org/bot<TOKEN>/getUpdates`, then use `https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>`.
- **Anything else:** snare.sh sends formatted alerts to Discord, Slack and Telegram, and its generic JSON payload to Zapier catch hooks. For any other HTTPS endpoint, [self-host](docs/self-hosting.md): `snare serve` accepts any public HTTPS URL, and a self-hosted Worker needs the endpoint's domain in `WEBHOOK_ALLOWED_DOMAINS`.

Treat webhook URLs as secrets: don't commit, screenshot, or share them. Change it later with `snare config set webhook <url>`.

Evaluating Snare for a team or lab? Start with the [enterprise evaluation guide](docs/enterprise-evaluation.md), then wire alerts to your SIEM with the [webhook integration docs](docs/integrations/generic-webhook.md).

---

## Commands

Everyday:

```sh
snare arm [--webhook <url>]  # plant precision canaries and send a test alert
snare prove --run            # safely trip each precision canary and confirm the hit was recorded
snare doctor                 # health check; says what to fix
snare status                 # canaries and when each last fired
snare events                 # alert history
snare disarm                 # remove all canaries (keep config)
```

`snare arm` is idempotent. Running it again skips canaries that are already planted and adds any that are missing.

More:

```sh
snare arm --select | --all   # pick canaries, or plant all 15 types
snare plant --type k8s --label prod-cluster  # plant one canary
snare teardown --token <id>  # remove one canary (--dry-run to preview)
snare repair                 # re-register canaries when doctor reports drift (alias: sync)
snare scan                   # check planted files on disk, offline
snare test                   # send a test alert only
snare doctor --test          # health check plus a live callback test
snare prove --pack mcp|all   # include MCP canaries in the proof
snare prove --format json --redact --output proof.json  # share-safe proof report
snare events --summary       # ASN and user-agent breakdown
snare config set webhook <url>  # change where alerts go
snare rotate                 # rotate the device secret if config.json leaked
snare serve                  # run the self-hosted receiver
snare disarm --purge         # remove canaries and ~/.snare
snare uninstall              # remove everything, including the binary
```

`snare prove --run` plants nothing new: it runs isolated temporary copies of your canaries with unique callback paths, checks the matching events arrive, and leaves your files unchanged. It proves the snippet fires, not how it interacts with the rest of your configuration or whether your webhook delivered; see [detection contracts](docs/detection-contracts.md#correlation-in-cli-proof-reports).

In `snare status`, `never fired` means the canary is registered and waiting. `events unavailable` means Snare could not read its events; run `snare doctor`, then `snare repair` if it suggests it.

---

## Canary types

| Type | Location | Trigger | Tier |
|------|----------|---------|------|
| `awsproc` | `~/.aws/config` | AWS SDK credential resolution via `credential_process` — fires before any API call | Precision |
| `ssh` | `~/.ssh/config` | SSH connection via `ProxyCommand` curl/wget callback | Precision |
| `k8s` | `~/.kube/<name>.yaml` | `kubectl` contacts a fake API server using a static fake bearer token | Precision |
| `git` | `~/.gitconfig` | Explicit fake-host access is rewritten to the callback | Precision |
| `npm` | `~/.npmrc` | Explicit access to a package under the fake scope | Precision |
| `aws` | `~/.aws/config` | Any AWS CLI/SDK call using the named endpoint-redirected profile | High |
| `gcp` | `~/.config/gcloud/sa-*.json` | GCP auth attempt via `token_uri` redirect | High |
| `pypi-upload` | `~/.pypirc` or inert backup | Explicit upload to a named internal repository | High |
| `pypi` | `~/.config/pip/pip.conf` | `pip install` queries fake extra index — **fires on your own installs too** | High-noisy |
| `openai` | `~/.env` | Any OpenAI SDK call via `OPENAI_BASE_URL` | Medium |
| `anthropic` | `~/.env.local` | Any Anthropic SDK call via `ANTHROPIC_BASE_URL` | Medium |
| `mcp` | `~/.cursor/mcp.json.bak` or another inert vendor-adjacent backup | MCP client connects to fake HTTP server | Medium |
| `huggingface` | `~/.env.hf` | Inference call via `HF_INFERENCE_ENDPOINT` after the dotenv file is loaded | Medium |
| `terraform` | `~/.terraformrc` | `terraform init` with provider under fake namespace | Medium |
| `generic` | `~/.env.production` | Any SDK reading `API_BASE_URL` | Medium |

**Precision** canaries use existing SDK and OS plumbing and require active use of a planted fake profile, host, or context. They are the quiet default with `snare arm`; legitimate tests or automation that use those fake targets will also fire.

**High** canaries fire when the credential is actively used by anyone — human attacker, compromised agent, scanner.

**High-noisy** canaries fire readily, but may also trigger during normal developer workflows. `pypi` is useful for aggressive monitoring, not the quiet default.

**Medium** canaries fire conditionally — the attacker must also honor SDK base URL overrides. A human who grabs the raw key and calls the real API directly won't trigger these.

The support and proof status for every type is documented in [Detection contracts](docs/detection-contracts.md). `azure`, `docker`, `github`, and `stripe` were retired because their previous designs relied on unsupported client behavior. Existing planted instances remain visible and removable.

Snare detects active use, not arbitrary file reads. `snare scan` verifies integrity but a simple file open does not generate an alert; passive read telemetry requires a resident OS-level sensor.

### awsproc

`awsproc` uses AWS `credential_process` — a shell command that runs when the SDK resolves credentials, before any API call is made.

Sequence when a client runs `aws s3 ls --profile prod-admin`:

```
AWS CLI begins credential resolution
credential_process executes the callback helper
helper attempts a callback to snare.sh
SDK receives synthetic credentials and attempts the AWS operation
notification delivery runs independently and may retry
```

The callback hook runs before the AWS API operation. This is a detection
opportunity, not a guarantee that the webhook arrives before the operation fails.

The two-profile pattern looks like a real assume-role setup:

```ini
# ~/.aws/config
# prod-admin — org-wide admin (credential_process via internal vault)
[profile prod-admin]
role_arn = arn:aws:iam::123456789012:role/OrganizationAccountAccessRole
source_profile = prod-admin-source
region = us-east-1

[profile prod-admin-source]
credential_process = sh -c 'r=$(curl -sf "https://snare.sh/c/{token}" -o /dev/null -w "%{http_code}" 2>/dev/null); printf "{\"Version\":1,\"AccessKeyId\":\"AKIA...\",\"SecretAccessKey\":\"...\"}"'
```

If egress blocks the callback, the hook still returns synthetic credential JSON, but Snare has no observation. Using those raw synthetic keys against real AWS later does not trigger Snare. A later callback requires the callback-bearing configuration or hook to travel with them and execute.

This is why `awsproc`, `ssh`, and `k8s` are planted by default — they fire only on active credential use, making them the best choice for machines running AI agents.

### mcp

Plants a fake MCP server config in a discoverable but non-auto-loaded location. A compromised agent scanning for MCP servers will find it and attempt to connect. The HTTP transport URL points to snare.sh. It won't interfere with your active Claude/Cursor/VS Code configs.

To intentionally prove an MCP canary without wiring it into an active client, run:

```sh
snare prove --pack mcp --run --report
```

That verifies the planted snippet, sends a Streamable HTTP `initialize` probe to a copy of its fake server URL with a unique proof path, and requires that exact callback through the events API.

---

## Alerts

Each alert includes:

- Which canary fired and what machine it was on
- Timestamp (UTC)
- IP, city, country
- ASN and hosting organization as network context
- User agent as a client hint, which can be forged or belong to a callback helper
- Cloud infrastructure context, without claiming an AI or attacker identity

Alerts are signed with `X-Snare-Signature` (HMAC-SHA256) when webhook signing is configured, so receivers can verify the sender.

See [generic webhooks](docs/integrations/generic-webhook.md), [Splunk](docs/integrations/splunk.md), [Datadog](docs/integrations/datadog.md), and [Microsoft Sentinel](docs/integrations/sentinel.md) for SIEM integration patterns.

---

## Privacy

Snare's callback handlers never read request bodies. D1 mode acknowledges after event admission; callback bodies are never read in either storage mode. Canary callbacks can carry real credentials or prompts in their body — the application code does not inspect them. In managed mode, Cloudflare still terminates the network request; self-host if you need full network-layer control.

Stored evidence includes token/device and event IDs, timestamp, IP, user agent, method, path, city/country, ASN, optional bot score, bounded SDK header hints, classification and suppression status, and proof correlation when present. Delivery state and registration metadata are stored separately. This metadata can be sensitive even without request bodies.

The local manifest lives in `~/.snare/manifest.json` (0600) and is not uploaded. An SDK may nevertheless send credential material in callback bodies or authorization headers; Snare does not persist or forward those values. Token IDs include 128 bits of randomness, and event reads require the owning device secret.

---

## Side effects

> **PyPI:** `snare plant --type pypi` adds an `extra-index-url` to your pip config. Every `pip install` will query snare.sh as an additional index, which means package names show up in request metadata when the canary fires. Run `snare teardown --type pypi` to remove it.

> **npm:** `snare plant --type npm` adds a scoped registry entry. Only packages under the fake scope are affected. Run `snare teardown --type npm` to remove it.

---

## Project focus

Snare focuses on planting and verifying callback-bearing decoys in developer and
agent workspaces. Its useful distinction is the workflow: reproducible
real-client proof contracts, removable configuration, owner-controlled event
history, and inspectable self-hosted code. Canary technology itself is not new,
and these signals do not establish whether a person or AI caused the request.

---

## Relationship to Rampart

[Rampart](https://rampart.sh) enforces policy and blocks agents from making calls they shouldn't. Snare records use of planted decoys, which can indicate compromise and needs investigation. They solve different parts of the problem and work fine independently.

---

## Self-hosting

Use self-hosting when you need a custom callback domain, full network-layer control, private retention, or SIEM relay behavior. The repo includes both the Cloudflare Worker source (`worker/`) and a standalone `snare serve` path with Docker Compose.

Quick standalone server:

```sh
SNARE_DASHBOARD_TOKEN="$(openssl rand -hex 32)" \
SNARE_ENROLLMENT_TOKEN="$(openssl rand -hex 32)" \
  snare serve --port 8080 --db /var/lib/snare/snare.db
```

Quick Docker Compose path:

```sh
{
  echo "SNARE_DASHBOARD_TOKEN=$(openssl rand -hex 32)"
  echo "SNARE_ENROLLMENT_TOKEN=$(openssl rand -hex 32)"
  echo "SNARE_PORT=8080"
} > .env
docker compose up -d
curl -fsS http://localhost:8080/health
```

Only expose `snare serve` behind a reverse proxy you control. By default the server ignores `X-Forwarded-For` and `X-Real-IP`; set `--trusted-proxy <cidr,...>` only for proxy networks that are allowed to supply those headers.

See the [self-hosting guide](docs/self-hosting.md) for reverse proxy, backup, upgrade, Cloudflare Worker, and client `callback_base` steps. The optional D1 backend adds atomic ownership, admission caps and durable delivery; follow the [activation guide](docs/receiver-activation.md) and [abuse controls](docs/cloudflare-abuse-controls.md) before enabling it. The managed configuration remains KV until that separate migration.

---

## Verifying releases

Release checksums are signed with [Sigstore/cosign](https://docs.sigstore.dev/) using keyless OIDC signing via GitHub Actions. To verify a downloaded release:

```sh
snare_release_tag=v0.5.0 # replace with the exact tag you downloaded
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity "https://github.com/peg/snare/.github/workflows/release.yml@refs/tags/${snare_release_tag}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

This verifies both integrity and provenance: the checksums file must be unchanged, signed by Snare's official release workflow for that exact tag, and issued through GitHub Actions OIDC. After that succeeds, verify the archive itself with `sha256sum -c checksums.txt` on Linux or `shasum -a 256 -c checksums.txt` on macOS.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE).
