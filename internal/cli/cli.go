// Package cli implements the snare command-line interface.
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/peg/snare/internal/bait"
	"github.com/peg/snare/internal/config"
	"github.com/peg/snare/internal/token"
)

// httpClient is used for all outbound HTTP calls so they have a uniform timeout.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// reliability returns a human-readable reliability label per canary type.
//
// Tiers:
//
//	precision — fires via existing SDK/OS plumbing, no agent hunting needed,
//	            no DNS dependency, zero false positives
//	high      — fires when credential is actively used, but requires agent to
//	            find and use it, or has a DNS/runtime dependency
//	medium    — fires conditionally: depends on dotenv loading, base URL
//	            override support, or agent doing explicit credential scanning
func reliability(t string) string {
	switch bait.Type(t) {
	// Precision: fires via SDK/OS hooks before or during connection, no DNS needed
	case bait.TypeAWSProc, bait.TypeSSH, bait.TypeK8s:
		return "precision"
	// High: fires on active credential use, requires agent to find+use the cred
	case bait.TypeAWS, // endpoint_url fires on any AWS SDK call with that profile
		bait.TypeGCP,  // token_uri fires on GCP SDK auth (needs explicit file load)
		bait.TypePyPI, // extra-index-url fires on pip install (own installs too — see warning)
		bait.TypeNPM,  // scoped registry fires on npm install (scoped packages only)
		bait.TypeGit:  // credential.helper fires if agent does git credential fill
		return "high"
	// Medium: dotenv-dependent, DNS-dependent, or requires explicit credential scanning
	default:
		return "medium"
	}
}

const usage = `snare — compromise detection for AI agents via deception

Quick start:
  snare arm --webhook <url>    arm this machine (init + plant precision canaries + test)
  snare disarm                 remove all canaries and clean up
  snare status                 show active canaries

Commands:
  snare arm [flags]            one-command setup: init + plant + test
  snare disarm [flags]         one-command teardown
  snare status                 show active canaries
  snare scan                   check canary integrity on disk
  snare events                 fetch recent alert events from snare.sh
  snare test                   fire a test alert to verify your webhook
  snare doctor                 validate configuration and canary health
  snare config                 show current config
  snare config set webhook <url>  update webhook URL
  snare serve [flags]          run self-hosted callback server (replaces snare.sh)

Advanced:
  snare init                   initialize snare on this machine
  snare plant [flags]          plant individual canary credentials
  snare teardown [flags]       remove specific canaries
  snare rotate                 rotate device secret (if leaked)
  snare uninstall [-y] [--force]  disarm + remove config + remove binary

Flags (arm):
  --webhook <url>              webhook URL (Discord, Slack, Telegram, or custom)
  --label <name>               name your canary (e.g. prod-admin-legacy-2024) — defaults to hostname
  --all                        plant all canary types including dotenv-based ones
  --dry-run                    show what would be planted without writing

Flags (plant):
  --label <name>               name your canary (e.g. prod-admin-legacy-2024) — defaults to hostname
  --type <type>                canary type: aws, awsproc, gcp, github, stripe, openai, anthropic, ssh, k8s, npm, mcp, pypi, huggingface, docker, azure, git, terraform, generic
  --all                        plant all canary types at once
  --dry-run                    show what would be planted without writing anything

Flags (disarm/teardown):
  --token <id>                 remove a single canary by ID
  --force                      remove even if content hash mismatches
  --purge                      also remove ~/.snare/ config directory
  --dry-run                    show what would be removed without writing anything

Flags (serve):
  --port <n>                   HTTP listen port (default: 8080)
  --db <path>                  SQLite database path (default: ~/.snare/serve/snare.db)
  --tls-domain <domain>        enable Let's Encrypt HTTPS for this domain
  --webhook-url <url>          global fallback webhook URL for alerts
  --dashboard-token <token>    required: token to protect the dashboard (min 16 chars)
                               also: SNARE_DASHBOARD_TOKEN env var
  --trusted-proxy <cidr,...>   trust X-Forwarded-For / X-Real-IP only from these proxy CIDRs
`

// Run dispatches the CLI command.
func Run(args []string, version string) {
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(0)
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "arm":
		cmdArm(rest)
	case "disarm":
		cmdDisarm(rest)
	case "rotate":
		cmdRotate(rest)
	case "init":
		cmdInit(rest)
	case "plant":
		cmdPlant(rest)
	case "status":
		cmdStatus(rest)
	case "scan":
		cmdScan(rest)
	case "events":
		cmdEvents(rest)
	case "test":
		cmdTest(rest)
	case "teardown":
		cmdTeardown(rest)
	case "uninstall":
		cmdUninstall(rest)
	case "config":
		cmdConfig(rest)
	case "doctor":
		cmdDoctor(rest)
	case "serve":
		cmdServe(rest)
	case "help", "--help", "-h":
		fmt.Print(usage)
	case "version", "--version", "-v":
		fmt.Printf("snare %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usage)
		os.Exit(1)
	}
}

// buildParams generates all template parameters for a canary.
func buildParams(bt bait.Type, label string, cfg *config.Config) (bait.Params, error) {
	tokenID, err := token.NewID(label)
	if err != nil {
		return bait.Params{}, err
	}

	callbackURL := cfg.CallbackURL(tokenID)
	callbackNoProto := strings.TrimPrefix(callbackURL, "https://")
	callbackNoProto = strings.TrimPrefix(callbackNoProto, "http://")

	p := bait.Params{
		TokenID:            tokenID,
		CallbackURL:        callbackURL,
		CallbackURLNoProto: callbackNoProto,
		Label:              label,
	}

	switch bt {
	case bait.TypeAWS:
		p.FakeKeyID, err = token.NewAWSKeyID()
		if err != nil {
			return p, err
		}
		p.FakeSecret, err = token.NewAWSSecretKey()
		if err != nil {
			return p, err
		}
		p.ProfileName = token.NewProfileName(label)

	case bait.TypeGCP:
		p.FakeProjID = token.NewGCPProjectID()
		p.FakeKeyID, err = token.NewGCPPrivateKeyID()
		if err != nil {
			return p, err
		}
		p.FakeSecret = token.NewGCPClientID()
		p.FakePrivateKey, err = token.NewFakeRSAPrivateKey()
		if err != nil {
			return p, err
		}

	case bait.TypeStripe:
		p.FakeToken, err = token.NewStripeKey()
		if err != nil {
			return p, err
		}
		// test_mode_api_key needs a short alphanumeric suffix
		keyID, err2 := token.NewGCPPrivateKeyID()
		if err2 != nil {
			return p, err2
		}
		p.FakeKeyID = keyID[:24] // 24 hex chars
		p.ProfileName = token.NewProfileName(label)

	case bait.TypeGitHub:
		p.FakeToken, err = token.NewGitHubToken()
		if err != nil {
			return p, err
		}
		// ProfileName used as the fake GitHub Enterprise hostname component
		// e.g. git.acme-internal.io — use label or generate a plausible corp name
		if label != "" {
			p.ProfileName = label + "-internal"
		} else {
			p.ProfileName = "corp-internal"
		}

	case bait.TypeOpenAI:
		p.FakeToken, err = token.NewOpenAIKey()
		if err != nil {
			return p, err
		}

	case bait.TypeAnthropic:
		p.FakeToken, err = token.NewAnthropicKey()
		if err != nil {
			return p, err
		}

	case bait.TypePyPI:
		// ProfileName is the fake package scope/org
		scopes := []string{"internal", "corp", "platform", "infra", "data", "ml"}
		sc := scopes[token.MustRandInt(len(scopes))]
		if label != "" {
			p.ProfileName = label + "-" + sc
		} else {
			p.ProfileName = sc + "-packages"
		}

	case bait.TypeAWSProc:
		// Two-profile pattern: visible assume-role + hidden credential_process source
		p.FakeKeyID, err = token.NewAWSKeyID()
		if err != nil {
			return p, err
		}
		// FakeToken used as the SecretAccessKey in credential_process output
		p.FakeSecret = token.NewGCPClientID() // 12-digit account ID for role_arn
		p.FakeToken, err = token.NewAWSSecretKey()
		if err != nil {
			return p, err
		}
		// Profile name for the visible assume-role profile
		envs := []string{"prod", "staging", "infra", "platform", "data"}
		roles := []string{"admin", "deploy", "readonly", "power-user"}
		e := envs[token.MustRandInt(len(envs))]
		r := roles[token.MustRandInt(len(roles))]
		if label != "" {
			p.ProfileName = label + "-" + e + "-" + r
		} else {
			p.ProfileName = e + "-" + r
		}

	case bait.TypeMCP:
		// ProfileName used as the org/team prefix for fake MCP server names
		orgs := []string{"platform", "infra", "backend", "data", "core", "internal"}
		o := orgs[token.MustRandInt(len(orgs))]
		if label != "" {
			p.ProfileName = label + "-" + o
		} else {
			p.ProfileName = o
		}
		p.FakeToken, err = token.NewGitHubToken() // JWT-like token for DB_TOKEN
		if err != nil {
			return p, err
		}
		p.FakeSecret = token.NewGCPClientID() // numeric for VAULT_TOKEN

	case bait.TypeSSH:
		// ProfileName is the fake hostname — looks like a bastion/jump box
		hosts := []string{"bastion", "jump", "gateway", "relay", "vpn"}
		envs := []string{"prod", "staging", "internal", "legacy", "corp"}
		h := hosts[token.MustRandInt(len(hosts))]
		e := envs[token.MustRandInt(len(envs))]
		if label != "" {
			p.ProfileName = h + "-" + label + "-" + e
		} else {
			p.ProfileName = h + "-" + e
		}

	case bait.TypeK8s:
		// ProfileName is the fake cluster name
		clusters := []string{"staging", "prod-us", "prod-eu", "dev", "infra", "platform"}
		suffixes := []string{"deploy", "legacy", "backup", "readonly", "migrate"}
		c := clusters[token.MustRandInt(len(clusters))]
		s := suffixes[token.MustRandInt(len(suffixes))]
		if label != "" {
			p.ProfileName = c + "-" + label + "-" + s
		} else {
			p.ProfileName = c + "-" + s
		}
		// Fake k8s service account token (looks like a JWT)
		p.FakeToken, err = token.NewK8sToken()
		if err != nil {
			return p, err
		}

	case bait.TypeNPM:
		// ProfileName is the npm scope (without @)
		scopes := []string{"internal", "corp", "platform", "infra", "backend", "core"}
		sc := scopes[token.MustRandInt(len(scopes))]
		if label != "" {
			p.ProfileName = label + "-" + sc
		} else {
			p.ProfileName = sc + "-pkg"
		}
		p.FakeToken, err = token.NewNPMToken()
		if err != nil {
			return p, err
		}

	case bait.TypeGeneric:
		p.FakeToken, err = token.NewGitHubToken() // reuse format
		if err != nil {
			return p, err
		}
		p.ProfileName = label

	case bait.TypeHuggingFace:
		p.FakeToken, err = token.NewHuggingFaceToken()
		if err != nil {
			return p, err
		}
		// ProfileName used as a comment label in the .env.hf file
		if label != "" {
			p.ProfileName = label + "-hf"
		} else {
			p.ProfileName = "ml-team"
		}

	case bait.TypeDocker:
		p.FakeRegistry, err = token.NewDockerRegistryName()
		if err != nil {
			return p, err
		}
		// FakeToken used as a base64-encoded "auth" value (username:password)
		// Docker stores base64(user:pass) in the auths section
		rawToken, err2 := token.NewNPMToken() // reuse a random token format
		if err2 != nil {
			return p, err2
		}
		p.FakeToken = rawToken
		p.ProfileName = label

	case bait.TypeAzure:
		// FakeKeyID = client ID (UUID)
		p.FakeKeyID, err = token.NewAzureClientID()
		if err != nil {
			return p, err
		}
		// FakeTenantID = tenant ID (UUID)
		p.FakeTenantID, err = token.NewAzureClientID()
		if err != nil {
			return p, err
		}
		// FakeSecret = client secret
		p.FakeSecret, err = token.NewAzureClientSecret()
		if err != nil {
			return p, err
		}
		// FakeProjID = subscription ID (UUID, reusing GCPClientID format for numeric look
		// — actually Azure subscription IDs are UUIDs, so generate one)
		p.FakeProjID, err = token.NewAzureClientID()
		if err != nil {
			return p, err
		}
		// ProfileName is a friendly name for the subscription
		envs := []string{"prod", "staging", "dev", "platform", "infra"}
		e := envs[token.MustRandInt(len(envs))]
		if label != "" {
			p.ProfileName = label + "-" + e
		} else {
			p.ProfileName = e
		}

	case bait.TypeGit:
		// ProfileName is the fake git server domain component
		// e.g. git.acme-internal.io becomes ProfileName = acme-internal
		corps := []string{"acme", "contoso", "initech", "tyrell", "weyland"}
		c := corps[token.MustRandInt(len(corps))]
		if label != "" {
			p.ProfileName = label + "-internal"
		} else {
			p.ProfileName = c + "-internal"
		}

	case bait.TypeTerraform:
		// ProfileName is the fake provider namespace prefix
		// e.g. registry.terraform.io/{{.ProfileName}}-internal/* looks like an internal namespace
		if label != "" {
			p.ProfileName = label + "-internal"
		} else {
			p.ProfileName = "terraform-internal"
		}
	}

	return p, nil
}

// requireConfig loads config and gives a helpful error if not initialized.
func requireConfig() (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("snare not initialized — run `snare init` first")
	}
	return cfg, nil
}

// authedPost sends a POST with Authorization: Bearer <device_secret>.
func authedGet(url string, cfg *config.Config) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if cfg != nil && cfg.DeviceSecret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.DeviceSecret)
		req.Header.Set("X-Snare-Device-Id", cfg.DeviceID)
	}
	return httpClient.Do(req)
}

func authedPost(url string, payload interface{}, cfg *config.Config) (*http.Response, error) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.DeviceSecret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.DeviceSecret)
	}
	return httpClient.Do(req)
}

// registerToken registers a per-token webhook with snare.sh.
func registerToken(cfg *config.Config, tokenID, canaryType, label string) error {
	webhookURL := cfg.WebhookURL
	if webhookURL == "" {
		// No local webhook — register with sentinel to bind ownership for events auth
		webhookURL = "use-global"
	}
	resp, err := authedPost(cfg.RegisterURL(), map[string]string{
		"token_id":    tokenID,
		"webhook_url": webhookURL,
		"device_id":   cfg.DeviceID,
		"canary_type": canaryType,
		"label":       label,
	}, cfg)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		// Try to extract error message from JSON response
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("registration failed: %s", errResp.Error)
		}
		return fmt.Errorf("registration failed: HTTP %d", resp.StatusCode)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	return nil
}

// revokeToken deregisters a token webhook from snare.sh.
func revokeToken(cfg *config.Config, tokenID string) error {
	resp, err := authedPost(cfg.RevokeURL(), map[string]string{
		"token_id":  tokenID,
		"device_id": cfg.DeviceID,
	}, cfg)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	return nil
}

// httpGet fires a GET request to url using net/http.
func httpGet(url string) error {
	resp, err := httpClient.Get(url) //nolint:noctx
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// Flag helpers

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func flagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
