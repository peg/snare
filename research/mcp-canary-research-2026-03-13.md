As of **March 13, 2026**, I found **very little public evidence of fake MCP client configs being planted as canaries**, but I did find **real MCP-specific honeypot/deception work**.

**1. Fake MCP configs as tripwires/canaries**
I did **not** find credible public writeups, tools, or repos showing people planting fake `mcp.json` / `.mcp.json` / `config.toml` entries specifically to detect compromised agents.

Closest things I found:

- **HoneyMCP**: a real MCP deception tool released on PyPI in **January 2026**. It adds fake “ghost tools” to an MCP server to catch exfiltration and indirect prompt injection. That is **server-side deception**, not fake client config files.  
  Source: https://pypi.org/project/honeymcp/
- **GitGuardian MCP** supports creating **honeytokens** and even suggests hiding them in config files, but again that is generic secret-canary usage, not fake MCP config tripwires.  
  Source: https://github.com/GitGuardian/gg-mcp

My assessment: **publicly, config-file canaries seem mostly unexplored**. MCP deception has started, but it is happening at the **server/tool layer**, not the **client config layer**.

**2. MCP-specific deception / honeypotting tools, blogs, papers**
What does exist:

- **HoneyMCP**: explicit MCP honeypot middleware with fake tools and telemetry. This is the strongest direct hit.  
  https://pypi.org/project/honeymcp/
- **Trail of Bits blog** on “line jumping” / tool poisoning: explains why merely listing tools can poison the model before a tool is used. Not a honeypot, but directly relevant to deception attacks.  
  https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/
- **MCPTox** (2025): benchmark for tool poisoning on real MCP servers.  
  https://www.sciencestack.ai/paper/2508.14925
- **AutoMalTool** (2025): automated red-teaming by generating malicious MCP tools.  
  https://api-inference.hf-mirror.com/papers/2509.21011
- **MCP-ITP** (2026): automated implicit tool poisoning.  
  https://www.catalyzex.com/paper/mcp-itp-an-automated-framework-for-implicit
- **Securing the Model Context Protocol** (2025): frames poisoning, shadowing, rug pulls, and defenses.  
  https://www.sciencestack.ai/paper/2512.06556
- **Koi Security** documented real malicious MCP servers in the wild in late 2025. That is supply-chain abuse, not honeypotting, but it shows the threat is real.  
  https://www.koi.security/blog/postmark-mcp-npm-malicious-backdoor-email-theft  
  https://www.koi.ai/blog/mcp-malware-wave-continues-a-remote-shell-in-backdoor

I also searched X/Reddit. I found lots of discussion about **tool poisoning, shadowing, supply-chain risk, and config sprawl**, but **not much about fake MCP configs as canaries**.

**3. MCP config locations across major tools**
Verified locations I found:

- **Claude Code**
  - `~/.claude.json` for user and local scopes
  - `.mcp.json` in project root for project scope
  - Managed configs:
    - macOS: `/Library/Application Support/ClaudeCode/managed-mcp.json`
    - Linux/WSL: `/etc/claude-code/managed-mcp.json`
    - Windows: `C:\Program Files\ClaudeCode\managed-mcp.json`
  Source: https://docs.anthropic.com/en/docs/claude-code/mcp

- **Claude Desktop**
  - Config file name: `claude_desktop_config.json`
  - Exact paths are widely documented by community repos as:
    - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
    - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
  Anthropic’s docs reference the filename, but I did not find a clean official Anthropic page in search results giving both OS paths.  
  Community examples:  
  https://github.com/letsbonk-ai/bonk-mcp  
  https://github.com/Flux159/mcp-chat

- **Cursor**
  - Project: `.cursor/mcp.json`
  - Global: `~/.cursor/mcp.json`
  Source: Cursor docs snippet  
  https://docs.cursor.com/advanced/model-context-protocol

- **VS Code / GitHub Copilot (Agent mode)**
  - Workspace: `.vscode/mcp.json`
  - User profile: user-profile `mcp.json`
  - Remote user config also supported
  - Dev Containers: `devcontainer.json` under `customizations.vscode.mcp`
  Source:  
  https://code.visualstudio.com/docs/copilot/customization/mcp-servers  
  https://code.visualstudio.com/docs/copilot/reference/mcp-configuration

- **Windsurf**
  - `~/.codeium/windsurf/mcp_config.json`
  Source: https://docs.windsurf.com/windsurf/cascade/mcp

- **Codex**
  - `~/.codex/config.toml`
  - OpenAI says CLI and IDE extension share this config
  Source:  
  https://developers.openai.com/resources/docs-mcp  
  https://developers.openai.com/api/docs/mcp  
  https://raw.githubusercontent.com/openai/codex/main/docs/config.md

**4. What an MCP initial connection sends**
At the protocol level, the first real message is an **`initialize` JSON-RPC request**. It includes:

- `protocolVersion`
- client `capabilities`
- `clientInfo` (`name`, `version`)

Then the server replies with:

- negotiated `protocolVersion`
- server `capabilities`
- `serverInfo`
- optionally `instructions`

After that, the client sends `notifications/initialized`.

Sources:  
https://modelcontextprotocol.io/specification/2025-03-26/basic/lifecycle  
https://modelcontextprotocol.io/specification/latest/basic/lifecycle

Typical wire pattern:

- **stdio**
  - client spawns process
  - writes newline-delimited JSON-RPC to stdin
  - server replies on stdout
- **Streamable HTTP**
  - client POSTs JSON-RPC to the MCP endpoint
  - server may return `MCP-Session-Id`
  - client must include `MCP-Session-Id` and `MCP-Protocol-Version` on later requests
- **legacy SSE**
  - older compatibility mode; newer spec prefers Streamable HTTP

Transport refs:  
https://modelcontextprotocol.io/specification/2025-03-26/basic/transports  
https://modelcontextprotocol.io/specification/2025-11-25/basic/transports

What usually happens immediately after init, in practice:
- clients often call `tools/list`
- sometimes also `resources/list` and `prompts/list`

That behavior is described in the official TypeScript client guide; it’s not mandated as the very first post-init call, but it is common.  
Source: https://raw.githubusercontent.com/modelcontextprotocol/typescript-sdk/main/docs/client.md

**Operational implication:** if you point a compromised agent or client at a fake MCP server, the server can usually learn at least:
- client name/version
- protocol version
- client capabilities
- possibly session identifiers and auth context for HTTP transports
- that the client is alive and attempting discovery

**5. Risks of planting fake MCP configs**
Yes, there are real risks.

Potential breakage:
- **Tool conflicts / ambiguity**: duplicate names or overlapping tools can confuse model selection.
- **Startup failures / noisy UX**: broken entries can make clients show red/yellow server status or repeated errors.
- **Trust prompts / approval churn**: some clients prompt on project-scoped or newly discovered servers.
- **Tool budget pressure**: Windsurf explicitly caps available tools at **100**.
- **Auto-discovery side effects**: VS Code can discover MCP configs from other apps like Claude Desktop, so a fake config might get imported where you did not intend.
- **Silent execution risk**: VS Code warns that if a server is started directly from `mcp.json`, you may not get a trust prompt.
- **Outbound leakage**: a fake remote MCP endpoint will still receive the initial handshake and follow-up discovery calls.

Relevant docs:
- VS Code trust/discovery warnings: https://code.visualstudio.com/docs/copilot/customization/mcp-servers
- Windsurf tool limit: https://docs.windsurf.com/windsurf/cascade/mcp
- Claude Code precedence/storage: https://docs.anthropic.com/en/docs/claude-code/mcp

My take:
- **Fake MCP configs are viable as a detection idea**, but they are not zero-risk.
- The safer version is usually **server-side deception**:
  - add fake tools to a controlled MCP server
  - or expose synthetic secrets/resources through a monitored server
- Planting bogus client configs is more brittle because it can degrade the user’s tool environment before it catches anything.

**Bottom line**
- **Publicly documented fake MCP config canaries:** I found **none**.
- **Publicly documented MCP honeypots/deception:** **yes**, mainly **HoneyMCP** as of Jan-Feb 2026.
- **Research ecosystem:** strong and growing around **tool poisoning, shadowing, rug pulls, and malicious MCP servers**.
- **Best current pattern:** deception at the **MCP server/tool layer**, not the **client config file layer**.

If you want, I can turn this into a **design for an MCP config canary system**: where to plant it, what signal to watch for, and how to avoid breaking Claude/Cursor/Codex/VS Code.