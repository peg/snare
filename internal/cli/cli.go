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
//	precision — real-client tested and scoped to explicit use of a planted
//	            fake target, with near-zero false positives
//	high       — fires when credential is actively used, but requires agent to
//	             find and use it
//	high-noisy — fires readily, but may also fire during normal developer work
//	medium     — fires conditionally: depends on dotenv loading, base URL
//	             override support, or agent doing explicit credential scanning
func reliability(t string) string {
	switch bait.Type(t) {
	// Precision: real-client tested and narrowly scoped to a planted fake target.
	case bait.TypeAWSProc, bait.TypeSSH, bait.TypeK8s, bait.TypeGit, bait.TypeNPM:
		return "precision"
	// High: fires on active credential use, requires agent to find+use the cred
	case bait.TypeAWS, // endpoint_url fires on any AWS SDK call with that profile
		bait.TypeGCP,        // token_uri fires on GCP SDK auth (needs explicit file load)
		bait.TypePyPIUpload: // named repository fires on explicit publishing use
		return "high"
	// High-noisy: strong trigger, but global config can fire during normal work
	case bait.TypePyPI: // extra-index-url fires on pip install (own installs too — see warning)
		return "high-noisy"
	// Medium: dotenv-dependent, DNS-dependent, or requires explicit credential scanning
	default:
		return "medium"
	}
}

type reliabilityDetails struct {
	tier        string
	marker      string
	description string
}

func reliabilityDetailsFor(t string) reliabilityDetails {
	switch reliability(t) {
	case "precision":
		return reliabilityDetails{
			tier:        "precision",
			marker:      "◆",
			description: "active-use only; near-zero false positives",
		}
	case "high":
		return reliabilityDetails{
			tier:        "high",
			marker:      "●",
			description: "fires on credential use",
		}
	case "high-noisy":
		return reliabilityDetails{
			tier:        "high-noisy",
			marker:      "▲",
			description: "fires readily; may trigger during normal work",
		}
	default:
		return reliabilityDetails{
			tier:        "medium",
			marker:      "◐",
			description: "conditional trigger path",
		}
	}
}

func isKnownCanaryType(t string) bool {
	for _, bt := range allCanaryTypes {
		if string(bt) == t {
			return true
		}
	}
	_, retired := retiredCanaryTypes[bait.Type(t)]
	return retired
}

func isSupportedCanaryType(t bait.Type) bool {
	for _, bt := range allCanaryTypes {
		if bt == t {
			return true
		}
	}
	return false
}

func normalizeAutoLabel(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	lastHyphen := false
	for _, r := range value {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if valid {
			if b.Len() >= 48 {
				break
			}
			b.WriteRune(r)
			lastHyphen = false
			continue
		}
		if b.Len() > 0 && !lastHyphen && b.Len() < 48 {
			b.WriteByte('-')
			lastHyphen = true
		}
	}
	label := strings.Trim(b.String(), "-")
	if label == "" {
		return "snare"
	}
	return label
}

func webhookSummary(webhookURL string) string {
	if webhookURL == "" {
		return "using global snare.sh fallback"
	}

	lower := strings.ToLower(webhookURL)
	switch {
	case strings.Contains(lower, "discord.com/api/webhooks"):
		return "configured (Discord)"
	case strings.Contains(lower, "hooks.slack.com"):
		return "configured (Slack)"
	case strings.Contains(lower, "api.telegram.org"):
		return "configured (Telegram)"
	default:
		return "configured (custom)"
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
  snare repair                 safely re-sync token registrations + test health
  snare sync                   alias for snare repair
  snare prove [flags]          guided proof flow for precision and MCP canaries
  snare events                 fetch recent alert events from snare.sh
  snare test                   fire a test alert to verify your webhook
  snare doctor [--test]        confidence screen: config, API, canaries, ownership, callbacks
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
  --select                     interactive checklist to pick which canaries to arm
  --dry-run                    show what would be planted without writing

Flags (prove):
  --pack <pack>                proof pack: precision, mcp, or all (default: precision)
  --type <type>                proof canary type: awsproc, ssh, k8s, git, npm, or mcp
  --run                        execute safe trigger commands and verify callbacks
  --report                     print a first-success proof report
  --format text|json           output format for proof reports (json implies --report)

Flags (plant):
  --label <name>               name your canary (e.g. prod-admin-legacy-2024) — defaults to hostname
  --type <type>                canary type: aws, awsproc, gcp, openai, anthropic, ssh, k8s, npm, mcp, pypi, pypi-upload, huggingface, git, terraform, generic
  --all                        plant all canary types at once
  --dry-run                    show what would be planted without writing anything

Flags (disarm/teardown):
  --token <id>                 remove a single canary by ID
  --type <type>                remove active canaries of this type only
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
  --enrollment-token <token>   required: separate token for new device enrollment (min 32 chars)
                               also: SNARE_ENROLLMENT_TOKEN env var
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
	case "repair", "sync":
		cmdRepair(rest)
	case "prove":
		cmdProve(rest)
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

	case bait.TypePyPI, bait.TypePyPIUpload:
		// ProfileName is the fake package scope/org
		scopes := []string{"internal", "corp", "platform", "infra", "data", "ml"}
		sc := scopes[token.MustRandInt(len(scopes))]
		if label != "" {
			p.ProfileName = label + "-" + sc
		} else {
			p.ProfileName = sc + "-packages"
		}
		if bt == bait.TypePyPIUpload {
			p.FakeToken, err = token.NewNPMToken()
			if err != nil {
				return p, err
			}
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
		return nil, fmt.Errorf("snare not initialized — run `snare arm` first")
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
