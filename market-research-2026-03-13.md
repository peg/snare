**Bottom line**

As of **March 13, 2026**, the AI agent security market is real but uneven:

- The **money is going into identity/NHI controls**, not agent-specific deception.
- The **deception / canary / honeypot** side is still thin for agents specifically; most activity is extensions of older honeytoken ideas into MCP/devtool/agent environments.
- The **incident curve is no longer hypothetical**. By late 2025 and early 2026, there were confirmed cases of agents or agent-connected systems being hijacked, leaking private data, or using stolen credentials/tokens.
- **Developer sentiment is cautious-to-negative on autonomy without guardrails**. Productivity is acknowledged; trust is not.

**1. New entrants in canary / honeypot / deception for AI agents**

The honest read: I did **not** find a big wave of venture-backed pure-play “Canarytokens-for-agents” startups. The space is emerging, but it is mostly being covered by adjacent vendors and OSS tooling.

Relevant entrants / moves:

- **GreyNoise** used **Ollama honeypot infrastructure** and reported **91,403 attack sessions** against AI/LLM infrastructure between **October 2025 and January 2026**. That is not a commercial agent-deception product, but it is one of the clearest proof points that AI-specific honeypots are now operationally useful. Source: https://www.greynoise.io/blog/threat-actors-actively-targeting-llms
- **GitGuardian** continued pushing honeytokens into developer workflows, including GitHub leak detection and local planting workflows. This is not “AI-agent-only,” but it maps directly to coding agents and agentic CI/CD. Sources: https://docs.gitguardian.com/honeytoken/code-leakage , https://github.com/GitGuardian/ggcanary , https://github.com/GitGuardian/ggshield
- **Thinkst** remains the canonical deception vendor with OSS primitives that are still relevant in agent environments: **Canarytokens** and **OpenCanary**. Not new, but still the baseline. Sources: https://github.com/thinkst/canarytokens , https://github.com/thinkst/opencanary
- **Invariant Labs / Snyk** are not deception vendors, but they are among the most important new **agent-runtime security** entrants. Their **MCP-scan** and **Guardrails** products detect toxic flows, prompt injection, and MCP abuse, which is the nearest fast-growing alternative to deception in agent security. Sources: https://github.com/invariantlabs-ai/mcp-scan , https://github.com/invariantlabs-ai/invariant , https://invariantlabs.ai/blog/toxic-flow-analysis
- **Delinea** released an open-source **MCP server** in September 2025 to keep credentials out of prompts and give agents controlled secret access. Again, not deception, but part of the same “don’t let the agent hold real credentials at rest” trend. Sources: https://delinea.com/news/delinea-mcp-server-to-provide-secure-credential-access-for-ai-agents , https://github.com/DelineaXPM/delinea-mcp

My inference from the market: **agent-specific deception is still underbuilt**. Identity brokers, runtime guardrails, and monitoring are winning budget first.

**2. Recent incidents where AI agents were compromised and used stolen credentials**

Confirmed / high-confidence cases:

- **Anthropic disclosed the first reported AI-orchestrated cyber espionage campaign** on **November 13, 2025**. Anthropic says a Chinese state-sponsored actor manipulated **Claude Code** into infiltrating about **30 targets**, harvesting **usernames and passwords**, identifying high-privilege accounts, creating backdoors, and exfiltrating data. Anthropic said the AI performed **80-90%** of the campaign with minimal human supervision. Source: https://www.anthropic.com/news/disrupting-AI-espionage
- **Salesloft / Drift OAuth token theft** in **August 2025**. Attackers stole **OAuth and refresh tokens** tied to the **Drift AI chat agent** Salesforce integration and used them to pivot into customer Salesforce environments. Salesloft said the attackers’ objective included stealing **AWS keys, passwords, and Snowflake-related tokens**. Source: https://www.bleepingcomputer.com/news/security/salesloft-breached-to-steal-oauth-tokens-for-salesforce-data-theft-attacks/
- **Moltbook database breach** on **January 31, 2026** exposed agent control data at scale. Reporting says anyone could commandeer agents because Supabase row-level security was not enabled; exposed data included **secret API keys, claim tokens, verification codes, and owner relationships**. Source: https://www.axios.com/2026/02/03/moltbook-openclaw-security-threats and related reporting summarized here: https://en.wikipedia.org/wiki/Moltbook
- **OpenClaw website-to-local takeover (“ClawJacked”)** was disclosed by **Oasis Security** on **February 26, 2026**. Oasis said any website could silently take full control of a developer’s local OpenClaw agent. Oasis also noted earlier marketplace abuse, including **malicious skills** deploying info-stealers and backdoors. Source: https://www.oasis.security/blog/openclaw-vulnerability
- **GitHub MCP exploit** disclosed by **Invariant Labs** on **May 26, 2025** showed that a malicious GitHub issue could hijack an MCP-connected agent and coerce it into leaking data from **private repositories** into a public PR. This was a research disclosure, not a public breach report, but it is one of the most important real exploit chains in the space. Source: https://invariantlabs.ai/blog/mcp-github-vulnerability
- **GitLab Duo prompt-injection issue** disclosed in **May 2025** let attackers manipulate Duo into leaking private source code and steering users toward malicious content. Again, this was responsibly disclosed research, but it demonstrates the exact agent failure mode defenders now worry about. Sources: https://arstechnica.com/security/2025/05/researchers-cause-gitlab-ai-developer-assistant-to-turn-safe-code-malicious/ , https://docs.gitlab.com/ja-jp/user/duo_agent_platform/security_threats/

High-signal pattern across these incidents:

- The most common kill chain is **untrusted content -> agent context -> privileged tool access -> credential/token theft or data exfiltration**.
- Stolen material is usually **OAuth tokens, API keys, refresh tokens, source code, private repo contents, or browser/session secrets**, not just passwords.

**3. Current NHI security funding and products**

This is where the market is hottest.

- **Token Security**: raised **$20M Series A** on **January 28, 2025**, **$27M total funding**. Product focus: discover/manage/govern **non-human identities and AI agents**, least privilege, lifecycle governance, AI agent identity security. Sources: https://www.token.security/news/token-security-raises-20m-to-secure-enterprises-machine-identities----from-legacy-applications-to-ai-agents , https://www.token.security/news/token-security-achieves-rapid-growth-in-2025 , https://www.token.security/news/token-security-top-10-finalist-for-rsac-2026-innovation-sandbox-contest
- **Astrix Security**: raised **$45M Series B** on **December 10, 2024**, **$85M total**. Product focus: NHI discovery, posture, remediation, visibility into **AI agents** and service identities. Sources: https://astrix.security/learn/news/astrix-raises-45m-series-b-to-redefine-identity-security-for-the-ai-era/ , https://astrix.security/product/discover-non-human-identities/
- **Oasis Security**: emerged with **$40M** in January 2024, then added a **$35M Series A extension** on **May 1, 2024**, **$75M total**. Product focus evolved into **Agentic Access Management (AAM)**, intent-aware, time-bound least-privilege sessions for agents. Sources: https://www.newswire.com/view/content/oasis-security-raises-40m-to-solve-the-non-human-identity-security-gap-22222284 , https://www.accessnewswire.com/newsroom/en/computers-technology-and-internet/oasis-secures-35m-series-a-extension-to-automate-non-human-identit-858061 , https://www.oasis.security/blog/introducing-oasis-agentic-access-management
- **Entro Security**: raised **$18M Series A** on **June 18, 2024**, **$24M total**. Product now explicitly pitches unified security for **AI agents, NHIs, and secrets**, with **NHIDR**, posture, ownership attribution, and intent monitoring for Claude Code. Sources: https://www.businesswire.com/news/home/20240618621007/en/Entro-Security-Announces-18M-Series-A-Round-to-Enhance-Non-Human-Identity-Lifecycle-Management/ , https://entro.security/ , https://pr.comtex.com/2026/02/25/474205776/
- **Aembit**: raised **$25M Series A** on **September 12, 2024**, **nearly $45M total**. Product focus: workload IAM, now expanded into **IAM for Agentic AI**, with **Blended Identity** and **MCP Identity Gateway**. Sources: https://aembit.io/press-release/aembit-raises-25-million-in-series-a-funding-for-non-human-identity-and-access-management/ , https://aembit.io/press-release/aembit-introduces-identity-and-access-management-for-agentic-ai/
- **Veza**: launched **AI Agent Security** on **December 8, 2025**; then **ServiceNow announced intent to acquire Veza** on **December 2, 2025**. Product focus: AI-SPM / identity governance for agents, third-party AI agents, LLM apps, MCP. Sources: https://veza.com/company/press-room/veza-introduces-ai-agent-security-to-protect-and-govern-ai-agents-at-enterprise-scale/ , https://veza.com/company/press-room/servicenow-to-expand-security-portfolio-with-acquisition-of-vezas-leading-ai-native-identity-security-platform/
- **Delinea**: not a startup funding story here, but strategically important. Released open-source MCP server in **September 2025** and completed **StrongDM acquisition** on **March 5, 2026** to push JIT authorization / zero standing privilege for AI agents. Sources: https://delinea.com/news/delinea-mcp-server-to-provide-secure-credential-access-for-ai-agents , https://delinea.com/news/delinea-acquires-strongdm-to-secure-ai-with-continuous-authorization

Market read:

- The category is converging on **identity-first AI agent security**.
- Core product patterns are: **discovery**, **ownership attribution**, **least privilege**, **JIT/ephemeral credentials**, **runtime intent monitoring**, **MCP governance**, and **agent audit trails**.

**4. Open-source tools that plant fake credentials as tripwires**

The strongest OSS options I found:

- **GitGuardian `ggcanary`**: Terraform-based deployment of AWS credential honeytokens with alerting. Best fit for developer/CI/CD/cloud tripwires. Repo: https://github.com/GitGuardian/ggcanary
- **Thinkst `canarytokens`**: self-hosted canary token server supporting multiple token types. Repo: https://github.com/thinkst/canarytokens
- **Thinkst `opencanary`**: full honeypot rather than fake credentials specifically, but still relevant when agents can scan internal networks. Repo: https://github.com/thinkst/opencanary
- **Secureworks `dcept`**: Active Directory honeytoken deployment; plants fake credentials in memory to catch credential theft and lateral movement. Repo: https://github.com/secureworks/dcept

Useful adjacent OSS for agent security, even though they do **not** plant fake creds:

- **Invariant `mcp-scan`**: scans MCP connections for prompt injection, tool poisoning, toxic flows. Repo: https://github.com/invariantlabs-ai/mcp-scan
- **Invariant Guardrails**: runtime guardrails for agent systems. Repo: https://github.com/invariantlabs-ai/invariant
- **Delinea MCP server**: open-source brokered secret access for agents. Repo: https://github.com/DelineaXPM/delinea-mcp

If your requirement is specifically “plant bogus secrets so an agent trips them,” the best open-source shortlist is still **`ggcanary` + `canarytokens` + `dcept`**.

**5. Developer sentiment on AI agent security**

The sentiment is pretty clear: developers like the productivity, but they **do not trust the security model**.

- **Stack Overflow 2025 Developer Survey**: **75.3%** said they don’t trust AI answers; **61.7%** reported ethical or security concerns about AI-generated code; only **31%** currently use AI agents; **38%** have no plans to use them. Source: https://stackoverflow.co/company/press/archive/stack-overflow-2025-developer-survey/ and survey detail: https://survey.stackoverflow.co/2025/ai/
- Stack Overflow also shows that among agent developers, observability/security is mostly being done with **existing tools** like **Grafana/Prometheus (43%)** and **Sentry (32%)**, which says a lot: dedicated agent-security tooling is still early. Source: https://survey.stackoverflow.co/2025/ai/
- **Axios (March 10, 2026)** reported OSS maintainers being flooded by low-quality AI-generated security reports; some bug bounty programs are being shut down or constrained. That is a negative sentiment signal from the exact people who have to absorb agentic security externalities. Source: https://www.axios.com/2026/03/10/ai-agents-spam-the-volunteers-securing-open-source-software
- **Darktrace survey (February 3, 2026)**: **76%** of security professionals are concerned about AI-agent risk; top concerns were data exposure, privacy/regulatory issues, and misuse. Source: https://www.globenewswire.com/news-release/2026/02/03/3231035/0/en/Over-Three-Quarters-of-Security-Professionals-Concerned-About-AI-Agent-Risk-New-Darktrace-Report-Finds.html
- Simon Willison’s framing, echoed by Invariant and GitLab docs, has become the shorthand: the “**lethal trifecta**” is access to sensitive data, exposure to untrusted instructions, and a channel for exfiltration. That idea is basically the current developer mental model for why agent security feels brittle. Sources: https://invariantlabs.ai/blog/mcp-github-vulnerability , https://docs.gitlab.com/ja-jp/user/duo_agent_platform/security_threats/

**What matters most right now**

- The market is treating **AI agents as privileged non-human identities**, not as a separate security universe.
- The biggest practical controls today are:
  - **ephemeral/JIT credentials**
  - **least-privilege identity scoping**
  - **MCP/runtime guardrails**
  - **audit/intent monitoring**
  - **tripwire secrets / honeytokens in dev and CI paths**
- The gap is in **purpose-built deception for agents**. That category is still mostly open terrain.

If you want, I can turn this into a tighter deliverable next:
1. a vendor landscape table,
2. an incident timeline,
3. or a “where Rampart should fit” competitor map.