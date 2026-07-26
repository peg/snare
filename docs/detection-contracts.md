# Detection contracts

Snare distinguishes signal quality from proof quality. A rendered template is
not evidence that the named client honors it.

Proof levels:

- **Real client:** an automated test plants the canary, invokes the actual
  client, and requires the callback to arrive.
- **Manual probe:** Snare can validate the callback protocol, but CI does not
  yet invoke a representative production client.
- **Template only:** structure and teardown are tested, but client behavior is
  conditional or has not yet earned a real-client claim.

| Type | Default | Proof | Trigger contract |
|---|---:|---|---|
| `awsproc` | Yes | Real client | AWS CLI resolves a named `credential_process` profile. |
| `ssh` | Yes | Real client | OpenSSH targets the planted fake host and runs its scoped `ProxyCommand`. |
| `k8s` | Yes | Real client | kubectl contacts the kubeconfig's callback API server using a static fake token. |
| `git` | Yes | Real client | Git targets the planted fake host and applies the scoped URL rewrite. |
| `npm` | Yes | Real client | npm looks up a package under the planted fake scope. |
| `aws` | No | Real client | AWS CLI uses a named profile whose supported shared-config `endpoint_url` is the callback. |
| `gcp` | No | Real client | google-auth explicitly loads the planted service-account JSON and refreshes through `token_uri`. |
| `pypi-upload` | No | Template only | A publisher explicitly selects the named internal repository from the planted `.pypirc`. |
| `pypi` | No | Template only | pip queries the configured extra index during normal dependency resolution; intentionally noisy. |
| `mcp` | No | Manual probe | An MCP client explicitly loads the inert vendor-adjacent backup and initializes a fake HTTP server. |
| `openai` | No | Template only | A process loads the planted dotenv file and honors `OPENAI_BASE_URL`. |
| `anthropic` | No | Template only | A process loads the planted dotenv file and honors `ANTHROPIC_BASE_URL`. |
| `huggingface` | No | Template only | A process loads the planted dotenv file and honors `HF_INFERENCE_ENDPOINT`. |
| `terraform` | No | Template only | Terraform resolves a provider under the planted fake namespace. |
| `generic` | No | Template only | A custom client loads the planted `API_BASE_URL`. |

The CI canary lab runs in strict mode: missing AWS CLI, OpenSSH, kubectl, Git,
npm, or google-auth dependencies fail the job instead of silently skipping the
corresponding real-client proof.

## Retired types

`azure`, `docker`, `github`, and `stripe` are no longer plantable:

- The former Azure JSON file is not part of the Azure CLI or default SDK
  credential chain.
- Docker registry configuration cannot retain a token-specific callback path
  without a token-specific hostname and DNS design.
- GitHub CLI does not support the former `api_endpoint` field in `hosts.yml`.
- Stripe CLI has no supported per-profile API endpoint redirect for this use.

Existing manifest entries remain known to `status`, `scan`, and teardown, so
upgrades do not strand already planted files.

## Detection boundary

These are active-use tripwires. Reading, copying, or exfiltrating a planted file
without invoking its configured tool path does not produce a callback. `snare
scan` detects missing or modified bait, but passive file-open telemetry would
require a separate resident OS sensor.
