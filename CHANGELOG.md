# Changelog

All notable changes to Snare are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/)

---

## [Unreleased]

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
