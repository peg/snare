# snare

**Compromise detection for AI agents via deception.**

Snare plants fake credentials in your agent's environment. If the agent gets hijacked and goes hunting for credentials, it finds yours — and you get an instant alert.

No daemon. No proxy. No policy changes. The bait phones home.

---

## How it works

A hijacked AI agent — one that's been prompt-injected — does something a healthy agent doesn't: it looks for credentials it wasn't told about and tries to use them.

Snare exploits this. It plants convincing fake AWS keys, GCP service accounts, GitHub tokens, and Stripe keys in the standard locations where real credentials live. Each fake credential has the callback URL embedded as the **service endpoint**, not a comment:

```ini
# ~/.aws/credentials
[prod-us-east-1-legacy-2024]
aws_access_key_id     = AKIAW2U59XALOTHPSSEI
aws_secret_access_key = tw7gxwYkonjmX8zDSge0vTKeXuEuG3Q...
region                = us-east-1
endpoint_url          = https://snare.sh/c/your-token-here
```

When a hijacked agent calls `boto3.client("s3").list_buckets()` with that profile, the AWS SDK sends the request to `snare.sh` instead of `amazonaws.com`. You get an alert within a second — before the agent has done anything else.

The agent sees a flaky AWS response. You see this:

```
🪤 Snare fired
Token   openclaw-9193baef57a260b20858a45a7a14a74a
Time    2026-03-11 06:07:33 UTC
IP      34.121.8.92       Location  Council Bluffs, US
Network Amazon Technologies Inc (AS16509)
UA      Boto3/1.34.46 md/Botocore#1.34.46 ua/2.0 os/linux#6.8.0...
⚠️ Likely AI agent   Request originated from Amazon Technologies Inc
```

The Boto3 user agent tells you exactly which SDK fired it. The ASN tells you it came from a cloud-hosted agent. No daemon needed — the credential itself is the sensor.

---

## Install

```sh
curl -fsSL https://snare.sh/install | sh
```

Or download a binary from [releases](https://github.com/peg/snare/releases).

**Requirements:** Linux or macOS, curl

---

## Quick start

```sh
# 1. Initialize snare (generates a device ID)
snare init

# 2. Plant canaries in real credential locations
snare plant              # AWS credentials (~/.aws/credentials)
snare plant --type gcp   # GCP service account (~/.config/gcloud/)
snare plant --type github # GitHub token (~/.config/gh/hosts.yml)
snare plant --type stripe # Stripe key (~/.config/stripe/config.toml)

# 3. Verify your alert pipeline
snare test

# 4. Check what's active
snare status
```

Done. If anything touches those credentials and tries to use them, you'll know.

---

## Canary types

| Type | Location | Trigger | Reliability |
|------|----------|---------|-------------|
| `aws` | `~/.aws/credentials` | Any AWS SDK/CLI call | High |
| `gcp` | `~/.config/gcloud/sa-prod-backup.json` | Auth attempt with service account | High |
| `github` | `~/.config/gh/hosts.yml` | `gh` CLI targeting fake Enterprise host | Medium |
| `stripe` | `~/.config/stripe/config.toml` | `stripe` CLI or agent following verify URL | Medium |
| `generic` | `~/.env.local` | Any SDK reading `API_BASE_URL` | Medium |

**High reliability** canaries fire when the credential is **used** — the callback URL is the service endpoint, so any SDK call redirects to snare.sh. **Medium reliability** canaries fire under more specific conditions but are still valuable coverage.

Use `--label` to prefix your canary names for easy identification in alerts:

```sh
snare plant --label claude-code
snare plant --label codex --type gcp
```

---

## Teardown

```sh
# Remove all canaries (surgical — only removes snare-planted blocks)
snare teardown

# Remove a single canary
snare teardown --token <id>

# Preview what would be removed
snare teardown --dry-run

# Remove everything including ~/.snare config
snare uninstall
```

Teardown is content-matched, not pattern-matched. Snare finds the exact bytes it wrote and removes only those — your real credentials are never touched.

---

## Alerts

Snare sends alerts via webhook when a canary fires. Set your destination during `snare init` or configure directly on snare.sh.

Supported: **Slack**, **Discord**, **any webhook**.

Each alert includes:
- Token ID (which canary, which agent environment)
- Exact timestamp
- IP + location (city, country)
- ASN + hosting org (Amazon = cloud agent, etc.)
- User agent (identifies SDK: `Boto3/1.34.46`, `node-fetch/2.6.1`, etc.)
- "Likely AI agent" indicator when request comes from cloud infrastructure

---

## How it differs from canarytokens.org

[Canarytokens](https://canarytokens.org) is a great tool. Snare is different:

| | Canarytokens | Snare |
|---|---|---|
| Setup | Manual, one token at a time | `snare plant` covers all credential types |
| AWS detection | CloudTrail (minutes lag) | Direct callback (sub-second) |
| Other providers | AWS only | AWS, GCP, GitHub, Stripe |
| Mechanism | Thinkst monitors AWS CloudTrail | Credential self-reports via SDK redirect |
| AI agent context | None | Built for it — ASN detection, SDK UA parsing |
| Infrastructure | Thinkst's | Cloudflare edge |

---

## Privacy

Snare.sh receives callback requests when a canary fires. Each request logs:
- Token ID, timestamp, IP, user agent, ASN

Canary content (fake credentials) is stored locally in `~/.snare/manifest.json` and never sent to snare.sh. Token IDs are random hex — they can't be reversed to identify you.

---

## Self-hosting

The Cloudflare Worker is open source in this repo (`worker/`). You can deploy your own callback server:

```sh
cd worker
wrangler deploy
```

Set your own callback base in `snare init`:

```sh
SNARE_CALLBACK_BASE=https://your-worker.workers.dev/c snare init
```

---

## Relationship to Rampart

Snare and [Rampart](https://rampart.sh) are complementary:

- **Rampart** enforces policy — it blocks agents from making calls they shouldn't
- **Snare** detects compromise — it catches agents that have been hijacked

Rampart blocks. Snare catches what slips through.

Neither requires the other. Both are stronger together.

---

## Status

Snare is early-stage. The core detection mechanism works and is tested. What's coming:

- [ ] Dashboard at snare.sh
- [ ] `snare scan` — find orphaned canaries when manifest is lost
- [ ] `snare rotate` — teardown + replant atomically
- [ ] Kubernetes secret canaries
- [ ] OpenAI/Anthropic API key canaries
- [ ] Database connection string canaries

---

## License

MIT
