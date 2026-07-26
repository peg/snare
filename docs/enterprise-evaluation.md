# Enterprise evaluation guide

Snare is intentionally small: a CLI plants credential and tool-use tripwires, callbacks produce alert metadata, and the operator can prove and remove the tripwires. This guide is for security engineers who need to evaluate Snare safely before using it in a lab, developer fleet, CI environment, or AI-agent pilot.

## What Snare does and does not do

Snare detects active use of planted fake credentials and tool configurations. It is not a prompt-injection firewall, EDR, DLP tool, or policy enforcement engine.

Snare is useful when you want to know whether an agent, scanner, script, or human attacker tried to use a sensitive-looking local capability such as an AWS profile, SSH host, kube context, package registry, or SDK endpoint override.

## Recommended safe pilot

Start with the default precision canaries (`awsproc`, `ssh`, `k8s`, `git`, `npm`). They are designed to stay quiet during normal work and fire only when a planted fake target is actively used.

```sh
# 1. Preview local file changes without writing canaries.
snare arm --dry-run

# 2. Arm precision-mode canaries and send alerts to an existing destination.
snare arm --webhook https://example.com/snare-webhook

# 3. Confirm local state and expected quiet state.
snare status
snare scan
snare doctor

# 4. Run an end-to-end test callback and verify event readability.
snare doctor --test

# 5. Safely trigger precision canaries and write a redacted proof artifact.
snare prove --run --report --redact --format json --output proof.json

# 6. Review recent callback evidence.
snare events

# 7. Remove canaries and local Snare config when the pilot is done.
snare disarm --purge
```

A fresh canary showing `never fired` can be healthy. Use `snare scan`, `snare doctor`, and `snare prove` to distinguish a healthy quiet canary from a registration or readability problem.

## What files Snare touches

`snare arm` defaults to precision mode and plants `awsproc`, `ssh`, `k8s`, `git`, and `npm`. `snare arm --all` expands to every supported canary type.

| Scope | Examples | Notes |
|---|---|---|
| Local Snare state | `~/.snare/config.json`, `~/.snare/manifest.json` | Created with restrictive permissions. Manifest records exact bytes written for safe teardown. |
| Precision canaries | `~/.aws/config`, `~/.ssh/config`, `~/.kube/<name>.yaml`, `~/.gitconfig`, `~/.npmrc` | Default mode. Designed to fire on active use, not passive reads. |
| Package/tool canaries | `~/.config/pip/pip.conf`, `~/.pypirc`, `~/.terraformrc` | Use selectively. The pip extra-index canary may fire during normal developer workflows. |
| SDK/app canaries | dotenv files and vendor-adjacent configs for OpenAI, Anthropic, GCP, Hugging Face, MCP, and generic endpoints | These depend on how the target agent or tool consumes local config. |

Teardown is content-matched: Snare removes the exact bytes it wrote and does not rewrite unrelated credentials in the same file. Use `snare teardown --dry-run`, `snare disarm`, or `snare disarm --purge` during evaluation cleanup.

## Data flow

### Managed `snare.sh`

1. The CLI creates a local device secret and registers token metadata with `snare.sh`.
2. A planted canary contains a callback URL such as `https://snare.sh/c/<token>`.
3. If the fake credential/tool path is used, the SDK or tool requests the callback URL.
4. The callback service stores metadata and optionally forwards an alert to your webhook destination.
5. The CLI reads recent events with the local device secret.

### What leaves the machine

| Flow | Data |
|---|---|
| Registration API | Token ID, device ID, canary type, label, webhook routing metadata. |
| Events API | Token ID in the URL and bearer device secret for authenticated reads. |
| Canary callback | Token ID, request path, method, IP, user agent, Cloudflare-derived geography/ASN/bot metadata when using the managed worker. |
| Webhook delivery | Alert payload containing event metadata. No request body is included. |

Callback handlers intentionally do not read, store, or forward request bodies. This matters because some SDK callbacks can include credential material in HTTP bodies. The application-level privacy guarantee does not mean Cloudflare or other network infrastructure never handles the encrypted network request; self-host if you need full network-layer control.

## Proof artifact workflow

Use proof reports as the shareable evaluation artifact:

```sh
snare prove --run --report --redact --format json --output proof.json
```

A useful proof artifact should show:

- which precision canaries were armed;
- which trigger commands were executed;
- whether callbacks were visible through the events API;
- observed callback timestamps and latency where available;
- cleanup commands;
- what the proof demonstrates;
- what the proof does not demonstrate.

Use `--redact` before sharing outside the evaluating machine. Redaction removes raw device IDs, token IDs, labels, cleanup-token values, and local absolute paths.

## Webhooks and SIEMs

Snare can post alerts to Discord, Slack, Telegram, or generic JSON webhook endpoints. For SIEMs that require custom headers, signed requests, or vendor-specific envelope formats, put a small relay in front of the SIEM and have Snare post to the relay.

See:

- [Generic webhooks](integrations/generic-webhook.md)
- [Splunk](integrations/splunk.md)
- [Datadog](integrations/datadog.md)
- [Microsoft Sentinel](integrations/sentinel.md)

## Self-hosting decision

Use managed `snare.sh` for a quick lab. Self-host when you need one or more of the following:

- all callback traffic to stay inside your network or cloud account;
- a custom callback domain;
- control over log retention, backup, and alert routing;
- custom webhook signing or relay behavior;
- evaluation in a restricted enterprise lab.

See [Self-hosting](self-hosting.md).

## Release and install verification

For production-like pilots, verify the release before installing broadly:

```sh
cosign verify-blob --bundle checksums.txt.bundle checksums.txt
sha256sum -c checksums.txt
```

Then smoke-test the binary in a temporary install directory before deploying to endpoints:

```sh
snare --version
snare arm --help
snare doctor --help
snare prove --help
```

## Known limitations to include in review

- Snare detects use of planted tripwires; it does not prevent compromise.
- `~/.snare/manifest.json` records canary locations so Snare can safely remove them. A local attacker who reads it can identify bait.
- Public callback domains can be fingerprinted. Use self-hosting or a custom callback domain when that matters.
- Some canary types are intentionally noisier than the precision defaults and should be selected deliberately.
- Managed mode depends on the availability and policy of the hosted callback service and its network provider.
- Webhook URLs are secrets and should be handled like credentials.

## Evaluation checklist

- [ ] `snare arm --dry-run` output reviewed by a security engineer.
- [ ] Default precision-mode canaries tested before `--all`.
- [ ] `snare doctor --test` passes in the target network.
- [ ] `snare prove --run --report --redact --format json --output proof.json` produces a share-safe artifact.
- [ ] Alert destination tested and owned by the evaluating team.
- [ ] Cleanup command verified with `snare disarm --purge` on a pilot host.
- [ ] SIEM relay or direct integration documented, including secret handling.
- [ ] Self-hosting decision recorded for callback privacy and custom domain requirements.
