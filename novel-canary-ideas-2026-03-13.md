The best next moves are the ones that exploit what attackers and agents actually *do* on a dev box: `install`, `build`, `init`, `connect`, `enumerate tools`, `pull`, `fetch`. The holy-shit category is where one fake config entry fans out across multiple ecosystems and only trips when somebody operationalizes it.

1. `MCP server canary`
Mechanism: Plant a fake remote MCP server entry with a juicy name like `prod-k8s-admin` or `github-enterprise-root` in agent config. Point its transport URL at Snare’s MCP shim, not the real service.
Why it’s high-reliability: this catches AI-specific behavior, not generic credential theft. Agents often enumerate configured tools/servers, probe capabilities, or opportunistically connect before using them. A human attacker almost never does that by accident.
Callback path: `/.well-known/oauth-authorization-server`, `/mcp`, `/sse`, or `/rpc/initialize`.
Who’s doing it: I did not find a public MCP canary product. I found MCP security/auth discussion, but not deception tokens built around tool discovery. This looks genuinely novel.

2. `OCI registry canary`
Mechanism: Plant fake high-value registry auth/config in `~/.docker/config.json` or `~/.config/containers/auth.json`, plus references to a decoy private registry such as `registry.prod-infra.example.com`. Any `docker pull`, `oras pull`, `helm pull oci://...`, `syft`, `grype`, or OpenTofu OCI fetch hits Snare.
Why it’s high-reliability: one canary covers Docker, ORAS, Helm OCI, container scanners, and OpenTofu because they reuse Docker-style registry auth/config. Fires on actual pull/login/use, not on file reads.
Callback path: `/v2/`, `/token?scope=repository:...`, `/v2/<repo>/manifests/<tag>`.
Who’s doing it: I found official docs showing the shared config path, but I did not find a public honeytoken product turning OCI client config into a workstation canary. This is strong.

3. `Terraform/OpenTofu provider-mirror canary`
Mechanism: Put a fake `provider_installation { network_mirror { url = "https://snare..." } }` in `~/.terraformrc` or `~/.tofurc`, or ship a decoy repo whose providers/modules resolve through Snare.
Why it’s high-reliability: `terraform init` and `tofu init` are exactly what agents run when “understanding infra.” It’s use-only. If you isolate it to a decoy repo or fake mirror stanza never used in normal work, false positives are effectively zero.
Callback path: `/providers/<namespace>/<type>/index.json`, `/v1/providers/.../versions`, module source fetch endpoints.
Who’s doing it: official mirror support exists; I didn’t find public canary tooling using it.

4. `Git submodule canary`
Mechanism: Put a plausible but dormant `.gitmodules` entry or decoy repo remote pointing to Snare. If an attacker runs `git submodule update --init --recursive`, `git fetch --all`, or an agent tries to “make the repo work,” it phones home.
Why it’s high-reliability: this is a classic agent move. Humans also do it during hands-on-keyboard post-compromise. Reading `.gitmodules` alone does nothing.
Callback path: `/<org>/<repo>.git/info/refs?service=git-upload-pack` and later `/git-upload-pack`.
Who’s doing it: Thinkst has an SVN token, but I didn’t find public Git-submodule deception aimed at dev workstations.

5. `Python package index canary`
Mechanism: Plant a fake internal package source in `pip.conf`, `uv` config, or `pyproject.toml` such as `https://snare/simple`, with bait names like `company-internal-sdk` or `prod-secrets-client`.
Why it’s high-reliability: AI coding agents love `pip install`, `uv sync`, `uv pip install`, and dependency repair. If the package name only appears in a decoy project, any hit is signal.
Callback path: `/simple/company-internal-sdk/`, `/packages/...whl`, auth challenge endpoints.
Who’s doing it: package-index support is standard in pip/uv; I didn’t find public deception products built around dev-box Python index canaries.

6. `Cargo alternate-registry canary`
Mechanism: Add an alternate registry in `.cargo/config.toml` with an index URL at Snare, then reference a tempting private crate in a decoy Rust workspace.
Why it’s high-reliability: `cargo check` or `cargo build` will consult the registry/index only on real use. Rust agents often run build/test immediately.
Callback path: `/git/index`, `/config.json`, crate download URLs like `/api/v1/crates/<crate>/<ver>/download`.
Who’s doing it: Cargo alternate registries are official. I didn’t find public canary tooling using them.

7. `Devcontainer canary`
Mechanism: In a decoy repo, set `.devcontainer/devcontainer.json` to use a fake private image or fake Feature source hosted on Snare.
Why it’s high-reliability: modern AI IDEs and humans both spin up devcontainers to explore unfamiliar repos. No alert unless someone actually tries to open/build the environment.
Callback path: `/v2/devcontainers/<image>/manifests/latest`, Feature tarball endpoints, registry auth flow.
Who’s doing it: I didn’t find anyone publicly productizing this. It’s very good because it catches “I want to execute this code safely” behavior.

8. `Docker context lateral-movement canary`
Mechanism: Plant a fake remote Docker context named something irresistible like `prod-root` or `payments-builders`. Set the daemon endpoint to Snare’s Docker API impersonator.
Why it’s high-reliability: this catches lateral movement and capability probing. AI agents and attackers frequently try `docker context ls`, then `docker --context prod ps` or `images`.
Callback path: `/_ping`, `/v1.41/containers/json`, `/v1.41/images/json`.
Who’s doing it: I didn’t find a public canary product for Docker contexts. It’s a beautiful lateral-movement tripwire.

9. `CI bootstrap canary`
Mechanism: In a decoy repo, define a fake but plausible bootstrap source that only CI-like behavior touches: a composite GitHub Action repo, a reusable workflow URL, or a build bootstrap script that fetches from Snare.
Why it’s high-reliability: catches attackers or agents trying to replay CI locally or inspect release paths by actually running them.
Callback path: `/<owner>/<action>/info/refs?service=git-upload-pack`, release asset URLs, bootstrap script URLs.
Who’s doing it: I didn’t find public deception tooling focused on CI-local replay canaries.

10. `Adjacent non-endpoint tripwire: credential helpers / credential_process`
Mechanism: For ecosystems that support on-demand helpers, point the helper to a Snare client or tiny wrapper. Examples: Docker `credHelpers`, AWS `credential_process`, Git `credential.helper`.
Why it’s high-reliability: this is even cleaner than endpoint redirection. The helper only runs when the credential is actually requested. Reading config doesn’t trip it.
Callback path: usually a direct HTTPS callback like `/helper/docker/<host>`, `/helper/aws/<profile>`, `/helper/git/<host>`.
Who’s doing it: pieces exist as helper ecosystems, but I haven’t seen a unified deception product leaning into this. It’s nasty in a good way.

My strongest picks for Snare are: `MCP`, `OCI`, `Terraform/OpenTofu mirror`, `Git submodule`, and `Devcontainer`. That set nails AI-agent behavior, dev workflow reality, and “fires on use, never on read.”

The most clever single idea is probably `OCI registry canaries`, because one fake registry host in the right config fans out across Docker, Helm OCI, ORAS, scanners, and OpenTofu. Security engineers will absolutely mutter “holy shit” when they realize one canary covers half the cloud-native toolchain.

Sources I used for the landscape check:
- Canarytokens docs: https://docs.canarytokens.org/
- Kubeconfig token: https://docs.canarytokens.org/guide/kubeconfig-token.html
- AWS keys token: https://docs.canarytokens.org/guide/aws-keys-token
- WireGuard token: https://docs.canarytokens.org/guide/wireguard-token.html
- SVN token: https://docs.canarytokens.org/guide/svn-token.html
- Fake IdP app token: https://docs.canarytokens.org/guide/idp-app-token.html
- Docker auth/config: https://docs.docker.com/reference/cli/docker/login/
- OpenTofu OCI credential reuse: https://opentofu.org/docs/cli/oci_registries/credentials/
- Terraform provider network mirror: https://developer.hashicorp.com/terraform/internals/provider-network-mirror-protocol
- Cargo alternate registries: https://books.irust.net/read/cargo-book/en-us/reference/registries.html
- pip index URLs: https://pip.pypa.io/en/stable/cli/pip_install/
- uv indexes/auth: https://docs.astral.sh/uv/concepts/indexes/ and https://docs.astral.sh/uv/concepts/authentication/http/
- MCP auth/background: https://stackoverflow.blog/2026/01/21/is-that-allowed-authentication-and-authorization-in-model-context-protocol/ and https://www.mend.io/blog/model-context-protocol-security-explained/

If you want, I can turn this into a ranked Snare roadmap with `implementation difficulty`, `blast radius`, and `expected catch rate against real coding agents`.