# Changelog

All notable changes to Snare are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/)

---

## [Unreleased]

## [0.4.0] - 2026-05-27

### Added
- `snare prove --output <path>` for writing proof reports as shareable artifacts.
- `snare prove --redact` for share-safe proof reports that remove device IDs, token IDs, labels, cleanup tokens, and absolute local paths.
- Enterprise evaluation, self-hosting, and SIEM integration guides for security-review-friendly pilots.
- `snare serve --help` for self-hosted callback server flag discovery.
- `snare prove --pack mcp` to safely trigger planted MCP canaries with a Streamable HTTP `initialize` probe and verify callbacks through the events API.
- `snare prove --pack all` to run precision and MCP proof recipes in one report.

### Changed
- Proof reports now include event visibility, observed callback latency, and explicit “what this proves” / “what this does not prove” sections.

## [0.3.0] - 2026-05-26

### Added
- `snare prove` for guided precision canary proof commands covering `awsproc`, `ssh`, and `k8s` canaries.
- `snare prove --run` to execute safe precision triggers and confirm callback visibility through the events API.
- `snare prove --report` and `snare prove --format json` for first-success proof reports that capture precision trigger commands, observed callbacks, status, and cleanup commands.

## [0.2.1] - 2026-05-23

### Fixed
- Hardened release archives and self-hosted deployment packaging.

## [0.2.0] - 2026-05-01

### Added
- `snare serve --trusted-proxy <cidr,...>` so self-hosted deployments only trust `X-Forwarded-For` / `X-Real-IP` from explicitly configured reverse proxies
- Server-side `/api/rotate` endpoint and safer `snare rotate` flow that updates the hosted secret before replacing the local secret
- Device ownership on stored events, preserving event access for revoked tokens without opening reads to unrelated devices
- CI coverage for worker tests, plus additional canary inventory, rotation, and serve/event tests

### Changed
- `snare arm --all` and `snare plant --all` now use one canonical list of all 18 implemented canary types, including `git`, `terraform`, and `generic`
- Alert copy and privacy docs now say the precise guarantee: IP, user agent, timestamp, method/path, and coarse network metadata only — no request body inspection
- Webhook guidance now treats webhook URLs as secrets and documents custom JSON endpoints

### Fixed
- Worker and self-hosted webhook logs no longer print raw canary token IDs or webhook URLs on common failure paths
- Worker authentication no longer silently auto-registers unknown devices during authenticated API requests
- Docker registry generation returns errors instead of panicking on `crypto/rand` failure
- Self-hosted callback IP attribution no longer trusts spoofable proxy headers by default
- Discord/Slack alert metadata includes the full canary inventory labels for newer canary types

## [0.1.4] - 2026-03-24

### Fixed
- Worker: unregistered tokens no longer fire the global fallback webhook — probe traffic hitting partial/random token URLs (e.g. `/c/agent-01-`) is silently dropped
- Worker: alert footer text updated to "IP, UA, timestamp only — no request body" (matches website copy)
- Worker: test token callbacks now logged as `CANARY_TEST` instead of `CANARY_FIRED` for cleaner production logs
- Worker: added missing canary types to `CANARY_TYPES` map (huggingface, azure, git, terraform)
- README: replaced example AWS account ID `389844960505` with canonical `123456789012`


## [0.1.3] - 2026-03-18

### Fixed
- Unregistered tokens no longer fire the global fallback webhook — probe traffic hitting random/partial token URLs is silently dropped (#23)
- Added 15s timeout to all outbound HTTP clients — CLI no longer hangs forever if snare.sh is unreachable (#19)
- Write `.snare.bak` backup before appending canary content to existing config files; backup cleaned up on successful disarm (#18)
- Dashboard authentication replaced ?token= query param with HttpOnly session cookie — prevents token leakage to browser history and server logs (#22)
- Session cookie Secure flag is conditional on TLSDomain — plain HTTP self-hosted deployments now work correctly
- Release checksums signed with Sigstore/cosign for tamper verification (#21)

## [0.1.2] - 2026-03-18

### Added
- **`snare arm --select`** — interactive TUI checklist for picking canaries. Arrow keys/j/k, Space to toggle, Enter to confirm. Precision canaries pre-checked. No new dependencies (raw terminal via syscall).
- **`snare events --summary`** — ASN distribution, SDK/user-agent breakdown, likely-AI-agent count, and per-canary hit counts. Covers 12 cloud provider ASNs.
- **`git` canary** (high reliability) — `credential.helper` entry in `~/.gitconfig`, scoped to a fake internal git hostname. Fires on `git credential fill`.
- **`terraform` canary** (medium reliability) — `network_mirror` in `~/.terraformrc` with fake provider namespace. Fires on `terraform init`. New-file-only to avoid HCL conflicts.
- Three-tier reliability system: **precision** (awsproc, ssh, k8s), **high**, **medium**.
- `snare scan` — check canary integrity on disk; detects OK, MODIFIED, MISSING, and ORPHANED canaries.
- Hugging Face canary (`huggingface`) — `~/.env.hf` with `HF_TOKEN` + `HF_ENDPOINT` redirect.
- Docker canary (`docker`) — fake registry entry in `~/.docker/config.json`.
- Azure canary (`azure`) — fake service principal credentials with `tokenEndpoint` redirect (medium reliability).
- Homebrew tap: `brew install peg/tap/snare`.

### Changed
- `snare arm` defaults to precision mode (awsproc, ssh, k8s). Use `--select` for interactive picker or `--all` for all 18 types.
- `--precision` flag removed — precision is now the default.
- Azure moved from precision to medium — not in standard Azure SDK credential chain.
- `npm` promoted from medium to high — scoped registry fires reliably on `npm install`.
- Token generation: `randString()` centralizes giveaway-free generation. Generated credentials no longer contain SNARE, FAKE, TEST, CANARY, HONEY, DECOY, DUMMY, or EXAMPLE.

### Fixed
- Worker: false-positive filtering — AWS canaries require AWS4-HMAC-SHA256 signature, GCP require POST, known scanner orgs (Shodan, Censys, Rapid7) silently dropped.
- `install.sh`: checksum verification fails closed.
- `snare disarm`: revokes token registrations even when no local webhook configured.
- `awsproc`: removed `SessionToken: null` from credential JSON (broke strict SDK parsers).

## [0.1.1] - 2026-03-16

### Fixed
- Worker: false-positive filtering — AWS canaries require AWS4-HMAC-SHA256 signature, GCP canaries require POST, known scanner orgs (Shodan, Censys, Rapid7, etc.) silently dropped
- `install.sh`: checksum verification now fails closed — previously skipped silently if checksum lookup returned empty
- README: added missing commands (`snare doctor`, `snare events`, `snare config`, `snare serve`)
- CHANGELOG: correctly marked v0.1.0 release date

## [0.1.0] - 2026-03-15

### Added
- `snare arm --precision` — plants only the 3 highest-signal canaries (awsproc, ssh, k8s) with near-zero false positive risk
- `snare config` / `snare config set webhook <url>` — post-init webhook management
- `snare doctor [--test]` — validates configuration, canary health, and optionally fires a live test alert
- `snare rotate` — rotates device secret if `~/.snare/config.json` is compromised
- `snare serve --dashboard-token` — required token for self-hosted dashboard auth (was unauthenticated)
- Worker: `X-Snare-Signature` HMAC-SHA256 on outbound webhook requests
- Worker: server-assigned device IDs via `POST /api/devices`
- Worker: token hijack prevention — cross-device re-registration rejected
- Worker: webhook domain allowlist (Discord, Slack, Telegram, PagerDuty, Teams, `use-global`)
- Worker: rate limiting (30 req/min per IP on `/api/*`, 10 alerts/min per token)
- `awsproc` canary — two-profile `credential_process` pattern, fires at credential resolution
- `pypi` canary — `extra-index-url` in `~/.config/pip/pip.conf`
- `mcp` canary — first public MCP security canary
- `ssh` canary — `ProxyCommand` callback in `~/.ssh/config`
- `k8s` canary — kubeconfig with fake cluster server URL
- `npm` canary — scoped registry URL in `~/.npmrc`
- GCP canary: now uses real RSA-2048 key — confirmed fires `token_uri` OAuth redirect
- `install.sh` with SHA-256 checksum verification
- `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`

### Fixed
- `snare events` was sending unauthenticated requests (missing Bearer + Device-Id headers)
- `snare test` was firing an unregistered token — now registers first so worker routes to webhook
- `snare arm` was silently swallowing registration failures
- `snare uninstall` was force-deleting files that changed since planting (footgun)
- Worker `use-global` sentinel was rejected by HTTPS check before sentinel exception
- Worker `forwardAlert` wasn't receiving `env` — webhook signing silently failed
- PyPI template had `trusted-host = snare.sh` — dead giveaway removed
- GCP fake RSA key failed ASN.1 parse in google-auth library before `token_uri` call
- `.env` collision: OpenAI→`~/.env`, Anthropic→`~/.env.local`, Generic→`~/.env.production`
- `arm --dry-run` was mutating config

### Changed
- Canary reliability reclassification: `openai`, `anthropic`, `npm`, `mcp` → medium (were high)
  - These fire conditionally on dotenv loading + base URL override; honest labeling
- `snare serve` now requires `--dashboard-token` (was unauthenticated)
- Worker TTL: 90 days → 365 days for webhook registrations
- Device secret: 128-bit → 256-bit entropy

### Security
- All `/api/*` endpoints require device secret authentication
- Dashboard and dashboard API endpoints gated by `DashboardToken`
- Token hijack prevention: cross-device registration rejected
- Rate limiting on both API and callback endpoints
- Request body never read on `/c/{token}` callbacks (privacy guarantee)

---

## [0.1.0] — TBD

Initial public release.

### Added
- 13 canary types: `aws`, `awsproc`, `gcp`, `github`, `stripe`, `openai`, `anthropic`, `ssh`, `k8s`, `npm`, `mcp`, `pypi`, `generic`
- `snare arm` — one-command setup: init + plant all + test
- `snare disarm` — remove all canaries
- `snare status` — show active canaries with last-seen timestamps
- `snare events` — fetch recent alert events from snare.sh
- `snare test` — fire test alert to verify webhook
- `snare plant / teardown` — granular canary management
- `snare init` — initialize device config
- `snare uninstall` — complete removal
- Cloudflare Worker backend with KV event storage
- Webhook delivery: Discord, Slack, Telegram, PagerDuty, MS Teams
- Content-matching teardown (never touches real credentials)
- Transactional plant flow with manifest activation
- Apache 2.0 license
