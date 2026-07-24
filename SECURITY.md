# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in Snare, please **do not open a public GitHub issue**.

Report it privately by emailing: **security@snare.sh**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Any suggested fixes

We aim to acknowledge reports within 48 hours and provide a fix or mitigation within 14 days for critical issues.

## Scope

In scope:
- Snare CLI (`internal/`, `cmd/`)
- Cloudflare Worker (`worker/`)
- Install script (`install.sh`)
- Snare.sh API endpoints

Out of scope:
- Theoretical attacks that require physical access to `~/.snare/`
- The fact that `~/.snare/manifest.json` reveals canary locations to local users (by design — see Known Limitations in ARCHITECTURE.md)
- Social engineering attacks against users

## Security Model

**What Snare protects against:** Detection of compromised AI agents attempting credential use.

**What Snare does not protect against:** An attacker with local filesystem access who can read `~/.snare/manifest.json`. The manifest intentionally stores canary locations and content for teardown purposes. Protect the manifest with file integrity monitoring if this is a concern.

**Privacy guarantee:** The `/c/{token}` callback endpoint never reads, stores, or forwards request bodies. Only header-derived metadata is stored (IP, user agent, timestamp, ASN). This applies to the managed snare.sh worker. Self-hosted deployments are controlled by the operator.

For a team/security review checklist covering data flow, files touched, proof artifacts, SIEM routing, and cleanup, see [docs/enterprise-evaluation.md](docs/enterprise-evaluation.md).

**Device secret:** The CLI generates a 256-bit device secret at `~/.snare/config.json` (0600 permissions). This secret authenticates API calls to snare.sh. If compromised, run `snare rotate` immediately.

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest release | ✅ |
| older releases | ❌ |

We maintain only the latest release. Please update before reporting issues.
