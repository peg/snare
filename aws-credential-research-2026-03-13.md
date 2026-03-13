**Recommendation**

Use `credential_process` in a dedicated decoy profile. It is the best canary mechanism by a wide margin.

Why:
- It fires during credential resolution, not merely when `~/.aws/config` is parsed.
- The callback payload is fully under your control; the AWS SDK does not send anything to your server directly.
- It does not require abusing AWS metadata or SSO flows.
- It has the broadest documented SDK/tool support across current AWS SDK families.
- It can coexist cleanly with real profiles if you keep it in a named decoy profile and do not set it as `default`.

I would not use `credential_source`, SSO, or `web_identity_token_file` as the primary tripwire. They are either not actually configurable the way you want, too interactive, or they carry materially higher risk of leaking real tokens or role credentials.

**Definitive call**

Best design for Snare:
- Primary: `credential_process` on a realistic named profile in `~/.aws/config`
- Optional camouflage: make the visible profile an assume-role profile that `source_profile`s into another decoy profile containing `credential_process`
- Do not use endpoint redirection for STS or metadata in the general case
- Do not use SSO as a canary
- Do not use `web_identity_token_file` unless you explicitly want a higher-risk token-exfil trap

**Mechanism-by-mechanism**

`credential_process`
- Fires on use: Yes, on credential resolution at runtime. Docs say the SDK/tool runs the configured command and reads JSON from `stdout`; it is part of the credential provider chain, not a passive config read. In practice, some SDKs resolve credentials on client creation, not only on first API call, so this is “on active use of the profile/client”, not strictly “on first network API call”. ([process provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html), [CLI v2 external process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html))
- What gets sent: Whatever your command sends. The SDK itself only executes the command and expects JSON on `stdout` with `Version`, `AccessKeyId`, `SecretAccessKey`, optional `SessionToken`, optional `Expiration`. ([CLI v2 external process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html))
- Real credential leak risk: Low, if your helper is self-contained and does not inspect other profiles or env vars. Much lower than endpoint redirection.
- Coexistence: Good. Keep it in a named decoy profile; do not make it `default`.
- False positives: Moderate. It can trigger when a tool constructs a client or validates credentials, even before an API call. For a canary, that is usually a feature.
- SDK support: Very broad. AWS CLI v2, Go v1/v2, JS v2/v3, Java 1.x/2.x, Kotlin, .NET 3.x/4.x, PHP, Boto3, Ruby, Rust, Swift, PowerShell all show support. Go v1 requires shared config loading enabled. ([support matrix](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html))
- Security warnings: AWS explicitly warns it can be dangerous, says to lock down the config file and ensure the helper does not write secrets to `stderr`, because SDKs/CLI may log it. AWS also notes external-process creds are not cached like assume-role creds; caching is your problem if you want it. ([CLI v2 warning](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html), [SDK ref warning](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html))
- Version caveat: Current support is broad. AWS CLI v1 also documents `credential_process`, but CLI v1 is old and AWS says migrate to v2. ([CLI v1 doc](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-sourcing-external.html))

`credential_source`
- Fires on use: Yes, but only as part of assume-role resolution, and only for the three fixed sources: `Environment`, `Ec2InstanceMetadata`, `EcsContainer`. ([assume-role provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-assume-role-credentials.html), [CLI config](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html))
- Can you point `EcsContainer` at your callback URL from config: No. `credential_source = EcsContainer` just selects the container provider. The URL is controlled by env vars like `AWS_CONTAINER_CREDENTIALS_FULL_URI`, not by `credential_source` itself. ([container provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html))
- What gets sent:
  - ECS/EKS container provider: HTTP GET to the configured endpoint; optional `Authorization` header if `AWS_CONTAINER_AUTHORIZATION_TOKEN` or token file is set. ([container provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html))
  - EC2 IMDS: by default IMDSv2, which does a `PUT` to `/latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`, then `GET`s with `X-aws-ec2-metadata-token`. ([IMDS provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-imds-credentials.html), [IMDSv2 flow](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html))
- Real credential leak risk: High if you mess with IMDS/container endpoints on real EC2/ECS/EKS systems. You can exfiltrate real role creds or auth tokens. AWS explicitly warns IMDS use on untrusted networks can be impersonated and recommends disabling it when not needed. ([IMDS security](https://docs.aws.amazon.com/sdkref/latest/guide/feature-imds-credentials.html))
- Coexistence: Poor for a canary unless isolated carefully. It depends on env or host metadata, so it is easy to interfere with real workloads.
- False positives: High in cloud environments, because legitimate SDK usage already hits metadata providers.
- SDK support: Broad for assume-role and container/IMDS, but not universal in older SDKs; e.g. `credential_source` is partial/not supported in some older Java/C++/JS entries. ([assume-role support](https://docs.aws.amazon.com/sdkref/latest/guide/feature-assume-role-credentials.html), [container support](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html), [IMDS support](https://docs.aws.amazon.com/sdkref/latest/guide/feature-imds-credentials.html))
- Verdict: Not a clean canary mechanism.

`sso_start_url` + `sso_registration_scopes`
- Fires on use: Not cleanly. SSO requires an IAM Identity Center session. AWS CLI explicitly requires `aws sso login`; SDKs typically consume cached SSO tokens and then call `getRoleCredentials` at runtime. ([SSO provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-sso-credentials.html), [how SSO resolves](https://docs.aws.amazon.com/sdkref/latest/guide/understanding-sso.html), [CLI SSO login](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html))
- What gets sent: During login, the CLI uses PKCE by default starting in AWS CLI `2.22.0`, opening browser flows against AWS OIDC endpoints; older/device-code flows use AWS device endpoints. At runtime, SDKs use the cached access token to call IAM Identity Center `getRoleCredentials`. ([CLI SSO flow](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html), [SSO resolution](https://docs.aws.amazon.com/sdkref/latest/guide/understanding-sso.html))
- Can a fake `sso_start_url` be a good callback: No. It is a bad canary. The flow is interactive, version-sensitive, and often requires prior login or cached tokens. Many SDKs will just fail without a valid cached session.
- Real credential leak risk: Medium to high if you ever involve real SSO cache or bearer tokens. Those tokens are cached under `~/.aws/sso/cache`. ([SSO provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-sso-credentials.html))
- Coexistence: Awkward; likely to annoy real users with browser/device-code prompts.
- False positives: High if humans use AWS SSO normally.
- SDK support: Broad on current SDKs, but not universal; Java 1.x is `No`, Rust is only partial for legacy non-refreshable config. ([support matrix](https://docs.aws.amazon.com/sdkref/latest/guide/feature-sso-credentials.html))
- Verdict: Bad canary.

`source_profile` chaining
- Fires on use: Only as part of assume-role resolution. `source_profile` by itself does not generate a callback. It just tells the SDK which other profile to use to obtain credentials, and role chaining proceeds until a profile with credentials is found. ([assume-role provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-assume-role-credentials.html))
- What gets sent: Nothing to your callback unless the upstream source profile itself uses something callback-capable, like `credential_process`.
- Real credential leak risk: High if the chain terminates in a real credential source and you also redirect STS endpoints.
- Coexistence: Good as camouflage, not as a standalone canary.
- False positives: Same as the underlying provider.
- SDK support: Broad where assume-role is supported. ([support matrix](https://docs.aws.amazon.com/sdkref/latest/guide/feature-assume-role-credentials.html))
- Verdict: Useful only as an indirection layer. Good pattern: visible decoy profile `source_profile = internal-helper`, and `internal-helper` contains `credential_process`.

`web_identity_token_file`
- Fires on use: Yes, during assume-role-with-web-identity resolution. The SDK loads the file contents and passes them as `WebIdentityToken` to STS `AssumeRoleWithWebIdentity`. ([assume-role provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-assume-role-credentials.html), [CLI config](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html))
- What gets sent: The contents of the token file are sent to STS as `WebIdentityToken`. If you redirect STS, your callback can receive the token.
- Real credential leak risk: High. This is the main reason not to use it for a generic canary. If the token file is real, you are exfiltrating a real OIDC/OAuth token.
- Coexistence: Poor unless you are absolutely certain the token file is fake and isolated.
- False positives: Moderate; many modern workloads legitimately use IRSA/OIDC.
- SDK support: Broad. ([support matrix](https://docs.aws.amazon.com/sdkref/latest/guide/feature-assume-role-credentials.html))
- Verdict: Technically works, operationally too risky.

**Other providers worth mentioning**

`Container provider` and `IMDS provider`
- These are real callback-capable HTTP providers, but they are env/host driven, not good shared-config tripwires. They are also exactly where real cloud credentials live, which is the opposite of “safe canary.” ([container provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html), [IMDS provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-imds-credentials.html))

`IAM Identity Center provider`
- Not suitable. Too interactive, cache-dependent, and noisy. ([SSO provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-sso-credentials.html))

`Login provider`
- Also not suitable for a passive tripwire. It is an auth mechanism, not a clean callback surface. ([standardized providers overview](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html))

**What I’d ship**

A realistic named profile in `~/.aws/config`:

- Public-facing decoy:
  - `[profile prod-admin]`
  - `role_arn = arn:aws:iam::123456789012:role/OrganizationAccountAccessRole`
  - `source_profile = prod-admin-source`

- Hidden source:
  - `[profile prod-admin-source]`
  - `credential_process = /absolute/path/to/snare-aws-helper`

Why this pattern:
- Agents and humans see something normal-looking.
- The first callback is still your controlled `credential_process`.
- `source_profile` adds realism without requiring STS endpoint abuse.
- No real AWS creds need to be present anywhere.

**Bottom line**

`credential_process` is the best AWS SDK canary tripwire for Snare.

It is the cleanest, broadest, and safest option:
- cleaner than endpoint redirection
- broader than SSO
- safer than metadata or web-identity tricks
- realistic enough to bait agents
- low risk of leaking real credentials if you keep it profile-local and self-contained

The only real downside is that it can fire on credential resolution before an actual API request. For a deception tool, that is not a downside. It is exactly the tripwire you want.