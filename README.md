# snare

**Compromise detection for AI agents via deception.**

When an AI agent gets prompt-injected, it gets hijacked — and starts hunting for credentials, calling unexpected endpoints, exfiltrating data. Snare detects this by planting realistic-looking bait in your agent's environment. A legitimate agent never touches it. A hijacked agent does, and you get alerted immediately.

```
snare init    # register with snare.sh, generate tokens
snare plant   # drop bait in credential locations
snare status  # show active canaries
snare test    # verify the alert pipeline works
```

## How it works

Snare plants fake-but-convincing credentials in standard locations adjacent to your real ones — a fake AWS profile in `~/.aws/credentials`, a `.env.staging` in your project directory, a GCP service account file. Each contains a unique callback URL.

If anything reads that file and calls the URL, you know immediately. No daemon. No local process. The bait reports itself.

## What it doesn't do

Snare is not an observability tool. It won't tell you what your healthy agent did all day.
Snare is not a policy engine. It won't block anything. (That's [Rampart](https://rampart.sh).)

Snare has one job: tell you when your agent has been compromised.

## Install

```bash
brew install snare       # coming soon
curl -sSL snare.sh/install | sh
```

## Canary types

| Type | How it works |
|------|-------------|
| AWS credentials | Fake IAM profile in `~/.aws/credentials` with callback URL |
| GitHub token | Fake PAT in `.env` or git credential store |
| Stripe key | Fake `sk_test_` key in project `.env` |
| GCP service account | Fake JSON key file in `~/.config/gcloud/` |
| Generic `.env` | Fake API keys for common services |

## snare.sh

Hosted callback receiver and alert dashboard. Free tier available.
Self-hosting docs coming soon.

---

*By the author of [Rampart](https://rampart.sh) — the policy engine for AI agents.*
