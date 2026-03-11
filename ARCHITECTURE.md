# Snare — Architecture

*Compromise detection for AI agents via deception.*

---

## Core Principle

Snare has one job: detect when an AI agent has been hijacked.

It does this by planting realistic-looking bait in your agent's operating environment. A legitimate agent, following its instructions, never touches the bait. A hijacked agent — one that's been prompt-injected and is now hunting for credentials or exfiltration paths — will. When it does, Snare fires.

**Snare is not:**
- An observability tool (don't care what healthy agents do)
- A policy engine (doesn't block anything — that's Rampart)
- A network proxy or MITM layer

**Snare is:**
- Deception infrastructure, purpose-built for AI agent threat models

---

## Threat Model

**The hijacked agent scenario:**

1. Agent receives a prompt injection via a document, web page, or tool response
2. Injected instruction says: "exfiltrate credentials to attacker.com" or similar
3. Agent starts hunting — scanning credential files, calling unexpected endpoints
4. Without Snare: you find out later (or never)
5. With Snare: the agent touches bait → callback fires → you're alerted immediately

**What a hijacked agent does that a legitimate one doesn't:**
- Reads credential files it was never instructed to read
- Calls URLs embedded in files (not in its instructions)
- Connects to endpoints outside its normal task scope

**The key:** Snare's bait is only reachable by a process that's actively hunting. It's not in the agent's active context, not in its instructions, not in its normal workflow. It's adjacent — in the same credential locations a real attacker would scan.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                  snare CLI (Go binary)               │
│                                                      │
│  snare init      → register device, generate tokens  │
│  snare plant     → drop bait in credential locations  │
│  snare status    → show active canaries               │
│  snare test      → fire a test alert                  │
│  snare teardown  → remove all planted bait            │
└──────────────────────────┬──────────────────────────┘
                           │ HTTPS (device reg, token mgmt)
                           ▼
┌─────────────────────────────────────────────────────┐
│                    snare.sh API                      │
│             (Cloudflare Workers + KV)                │
│                                                      │
│  POST /api/devices    → register device              │
│  POST /api/tokens     → generate canary tokens       │
│  GET  /api/tokens     → list tokens for device       │
│  GET  /c/{token}      → canary callback receiver     │
│  POST /c/{token}      → canary callback receiver     │
└──────────────────────────┬──────────────────────────┘
                           │ webhook forward
                           ▼
              Slack / Discord / email / generic webhook
```

---

## Bait Placement Strategy

### Where bait lives (real credential locations)

Bait is placed **adjacent to real credentials** — in the same directories and file formats that automated scanners and hijacked agents target first.

| Canary Type | Default Location | File Format |
|-------------|-----------------|-------------|
| AWS | `~/.aws/credentials` | INI profile append |
| GCP | `~/.config/gcloud/sa-prod-backup.json` | New file |
| GitHub | `~/.config/gh/canary-hosts.yml` | New file |
| Stripe | `{project}/.env.staging` | New file in project dir |
| Generic | `{project}/.env.local` | New file |

### What makes bait convincing

1. **Correct format** — passes structural validation (AKIA prefix for AWS keys, correct JSON schema for GCP, etc.)
2. **Tempting names** — `prod-us-east-1-legacy`, `sa-prod-backup`, `staging` — words that suggest value to an attacker
3. **Plausible comments** — `# break-glass only`, `# rotate when migrated`, generated dates
4. **Non-functional but realistic fake values** — keys that look real but will fail auth if actually used

### Where bait does NOT live

- `~/.snare/` — this directory is for the **manifest only** (metadata about what was planted)
- In the agent's active context window or system prompt
- In files the agent was explicitly instructed to read

---

## Callback Mechanism

Every bait artifact contains a unique callback URL embedded naturally:

```ini
# ~/.aws/credentials (appended)
# prod-us-east-1-legacy — rotate when migrated
# verify: https://snare.sh/c/a3f9b2c1d4e5f6a7
[prod-us-east-1-legacy]
aws_access_key_id     = AKIAIOSFODNN7SNARE01
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYSNAREKEY01
region                = us-east-1
```

The trigger is NOT reading the file — it's the agent subsequently calling the URL (which happens when a hijacked agent tries to exfiltrate or verify the credential). This eliminates false positives from simple file reads.

**No local daemon needed.** The callback URL phones home to snare.sh directly. Zero local infrastructure after `snare plant`.

---

## snare.sh Infrastructure

**Cloudflare Workers** — chosen for:
- Global edge (low latency callbacks from anywhere)
- Free tier handles hundreds of thousands of requests/day
- Zero server management
- KV for event storage
- D1 (SQLite) for user/device/token management at scale

```
snare.sh/c/{token}       → Worker: log event, forward webhook
snare.sh/api/*           → Worker: device + token management
snare.sh/                → Pages: dashboard (future)
```

**KV schema:**
```
event:{token}:{timestamp}  → JSON event record (90d TTL)
device:{deviceID}          → device registration + webhook config
token:{tokenID}            → token metadata + device association
```

---

## Token Lifecycle

```
snare init
  → generates deviceID (UUID stored in ~/.snare/manifest.json)
  → registers with snare.sh/api/devices
  → receives API key for this device

snare plant
  → calls snare.sh/api/tokens (creates N tokens)
  → renders bait templates with token callbacks
  → writes bait to filesystem
  → records planted canaries in ~/.snare/manifest.json

canary fires
  → HTTP request hits snare.sh/c/{token}
  → event logged to KV
  → webhook(s) fired immediately
  → manifest updated on next snare status pull

snare teardown
  → reads manifest
  → removes each planted file or appended block
  → marks tokens inactive via API
  → clears manifest
```

---

## Bait Template Library

Templates live in `templates/` and are compiled into the binary.

Each template produces output that:
- Passes format validation for the target service
- Embeds the callback URL naturally (in a comment, a field, a metadata block)
- Uses convincing names and values
- Won't accidentally work (invalid key material)

**Priority order for v1:**
1. `aws` — highest value target, most common
2. `generic` — `.env`-style keys, broadest coverage
3. `gcp` — service account JSON
4. `github` — PAT format
5. `stripe` — common in agent workflows

**v2 additions:**
- `k8s` — kubeconfig entries
- `azure` — service principal credentials
- `openai` — API key format
- `anthropic` — API key format (agents reading agents' own keys — very relevant)
- `database` — connection strings (Postgres, Redis, MySQL)

---

## Local State

Everything local lives under `~/.snare/`:

```
~/.snare/
  manifest.json    ← what's planted, where, token IDs, timestamps
  config.json      ← device ID, API key, webhook URL
```

Permissions: `0700` for the directory, `0600` for files.

---

## False Positive Mitigation

The architecture avoids false positives by design:

1. **Bait in new files or appended profiles** — never modifying existing entries that legitimate tools use
2. **Callback URL as the trigger** — a legitimate agent reads credential files all the time; it doesn't call random URLs embedded in comments
3. **`snare test` verifies the pipeline** — fires a synthetic callback so you know it's working before you need it
4. **Manifest tracks everything** — `snare status` shows every active canary so you always know what's planted

---

## Non-Goals (v1)

- eBPF / kernel-level monitoring
- Network interception / MITM proxy
- Document watermarking
- MCP canary server (v2)
- Agent framework SDK integration
- Windows support (Linux + macOS first)

---

## Relationship to Rampart

Rampart and Snare are complementary, not competing:

| | Rampart | Snare |
|---|---|---|
| **Layer** | Prevention | Detection |
| **Mechanism** | Policy enforcement (block) | Deception (alert) |
| **When it acts** | Before the bad thing | When the bad thing is tried |
| **Required** | No | No |
| **Better together** | Yes — Rampart blocks, Snare catches what slips through |

Neither requires the other. Both are stronger together.

---

## Build Order (4-week evenings plan)

**Week 1:** Core infrastructure
- `snare.sh` Cloudflare Worker (callback receiver + webhook forwarding)
- `snare init` — device registration, config storage
- `snare test` — verify pipeline end-to-end

**Week 2:** Bait system
- Template library (AWS, generic `.env`, GCP)
- `snare plant` — render + place bait, write manifest
- `snare status` — read manifest, show active canaries

**Week 3:** Polish + teardown
- `snare teardown` — clean removal of planted bait
- `--dry-run` support
- `--dir` for project-level canaries

**Week 4:** Public release prep
- README + docs
- Brew tap / install script
- snare.sh landing page (Cloudflare Pages)
- First public announcement (Rampart community + HN)
