// Package bait handles generation and placement of canary artifacts.
// Bait is planted in real credential locations — NOT in ~/.snare/.
package bait

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/peg/snare/internal/manifest"
)

// Type identifies a canary template category.
type Type string

const (
	TypeAWS       Type = "aws"
	TypeGitHub    Type = "github"
	TypeStripe    Type = "stripe"
	TypeGCP       Type = "gcp"
	TypeOpenAI    Type = "openai"
	TypeAnthropic Type = "anthropic"
	TypeSSH       Type = "ssh"
	TypeK8s       Type = "k8s"
	TypeNPM       Type = "npm"
	TypeMCP       Type = "mcp"
	TypePyPI      Type = "pypi"
	TypeAWSProc      Type = "awsproc"
	TypeGeneric      Type = "generic"
	TypeHuggingFace  Type = "huggingface"
	TypeDocker       Type = "docker"
	TypeAzure        Type = "azure"
	TypeGit          Type = "git"
	TypeTerraform    Type = "terraform"
)

// Params are filled into bait templates.
type Params struct {
	TokenID            string // unique canary ID
	CallbackURL        string // snare.sh callback URL — used as the SERVICE ENDPOINT, not a comment
	CallbackURLNoProto string // CallbackURL without https:// prefix (for npm auth lines)
	Label              string // user-supplied label prefix (optional)
	// Per-type fake values — realistic looking but non-functional
	FakeKeyID      string
	FakeSecret     string
	FakeToken      string
	FakeProjID     string
	FakePrivateKey string // PEM-formatted RSA private key (invalid but correct structure)
	ProfileName    string // e.g. "prod-us-east-1-legacy"
	FakeRegistry   string // fake Docker registry hostname
	FakeTenantID   string // fake Azure tenant ID (UUID)
}

// PlacedFile describes a file that was written, including the exact content.
// Content is stored in the manifest for safe teardown via content-matching.
type PlacedFile struct {
	Path    string
	Type    Type
	Mode    manifest.Mode
	TokenID string
	Content string // exact bytes written — store in manifest immediately
}

// Plant generates bait content and writes it to the target path.
//
// For existing files (e.g. ~/.aws/credentials): appends a new block.
// For new files (e.g. GCP JSON, .env): creates the file.
// Never overwrites or modifies existing content.
// Never touches the file if this canary's TokenID is already present.
//
// dryRun=true prints what would happen without writing.
// dryRun=true + silent=true renders content and returns it without printing or writing
// (used internally for transactional pre-render).
//
// Returns PlacedFile with exact Content — caller must persist this to the manifest.
func Plant(t Type, params Params, targetPath string, dryRun bool, opts ...bool) (*PlacedFile, error) {
	silent := len(opts) > 0 && opts[0]
	tmpl, ok := templates[t]
	if !ok {
		return nil, fmt.Errorf("unknown bait type: %s", t)
	}

	// Render template to exact content
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return nil, fmt.Errorf("rendering template: %w", err)
	}
	content := buf.String()

	// Determine mode: does the file already exist?
	_, statErr := os.Stat(targetPath)
	fileExists := statErr == nil
	mode := manifest.ModeNewFile
	if fileExists {
		mode = manifest.ModeAppend
	}

	// Some types must only be created as new files — appending would produce
	// invalid config (e.g. duplicate provider_installation blocks in .terraformrc).
	// For these types, fail early if the file already exists.
	newFileOnly := map[Type]bool{
		TypeTerraform: true,
	}
	if newFileOnly[t] && fileExists {
		return nil, fmt.Errorf("%s already exists — %s canary requires a new file (appending would create invalid config). Remove the existing file first or use a different path", targetPath, t)
	}

	if dryRun {
		if !silent {
			action := "create"
			if mode == manifest.ModeAppend {
				action = "append to"
			}
			fmt.Printf("[dry-run] would %s %s:\n---\n%s---\n", action, targetPath, content)
		}
		return &PlacedFile{
			Path: targetPath, Type: t, Mode: mode,
			TokenID: params.TokenID, Content: content,
		}, nil
	}

	// Safety: never plant if this token is already in the file
	if fileExists {
		existing, err := os.ReadFile(targetPath)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", targetPath, err)
		}
		if bytes.Contains(existing, []byte(params.TokenID)) {
			return nil, fmt.Errorf("canary %s already present in %s", params.TokenID, targetPath)
		}
	}

	// Backup existing file before appending canary content.
	// If snare crashes mid-operation, the user can restore from the .bak file.
	if fileExists && mode == manifest.ModeAppend {
		if err := writeBackup(targetPath); err != nil {
			return nil, fmt.Errorf("creating backup of %s: %w", targetPath, err)
		}
	}

	// Ensure parent directory exists with secure permissions
	parentDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		return nil, fmt.Errorf("creating parent dir: %w", err)
	}
	// SSH requires 0700 on ~/.ssh — enforce it if we created the dir
	if filepath.Base(parentDir) == ".ssh" {
		_ = os.Chmod(parentDir, 0700)
	}

	var flags int
	if mode == manifest.ModeNewFile {
		// O_EXCL ensures we fail rather than overwrite if file appears between Stat and Open
		flags = os.O_CREATE | os.O_EXCL | os.O_WRONLY
	} else {
		flags = os.O_APPEND | os.O_WRONLY | os.O_CREATE
	}
	f, err := os.OpenFile(targetPath, flags, 0600)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("%s already exists — snare won't overwrite existing files. Use a different path or remove the file first", targetPath)
		}
		return nil, fmt.Errorf("opening %s: %w", targetPath, err)
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		return nil, fmt.Errorf("writing bait: %w", err)
	}

	return &PlacedFile{
		Path:    targetPath,
		Type:    t,
		Mode:    mode,
		TokenID: params.TokenID,
		Content: content,
	}, nil
}

// Remove surgically removes a canary from disk using content-matching.
//
// For newfile canaries: verifies content hash matches, then deletes file.
// For append canaries: finds exact content block in file, removes it, rewrites.
// Returns an error (does NOT remove) if content has been modified since planting.
// Pass force=true to remove even if content hash mismatches.
func Remove(c manifest.Canary, force bool, dryRun bool) error {
	switch c.Mode {
	case manifest.ModeNewFile:
		return removeNewFile(c, force, dryRun)
	case manifest.ModeAppend:
		return removeAppended(c, force, dryRun)
	default:
		return fmt.Errorf("unknown mode %q for canary %s", c.Mode, c.ID)
	}
}

func removeNewFile(c manifest.Canary, force bool, dryRun bool) error {
	data, err := os.ReadFile(c.Path)
	if os.IsNotExist(err) {
		// Already gone — treat as success
		fmt.Printf("  %s: already removed (file not found)\n", c.Path)
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", c.Path, err)
	}

	// Verify hash matches what we planted
	currentHash := manifest.HashContent(string(data))
	if currentHash != c.ContentHash {
		if !force {
			return fmt.Errorf(
				"%s: content has changed since planting (hash mismatch)\n"+
					"  Someone may have added real data to this file.\n"+
					"  Use --force to remove anyway, or manually edit the file",
				c.Path,
			)
		}
		// Force mode: warn but proceed
		fmt.Printf("  ⚠ %s: content changed since planting — removing anyway (--force)\n", c.Path)
	}

	if dryRun {
		fmt.Printf("[dry-run] would delete %s\n", c.Path)
		return nil
	}

	if err := os.Remove(c.Path); err != nil {
		return fmt.Errorf("removing %s: %w", c.Path, err)
	}
	fmt.Printf("  deleted %s\n", c.Path)
	return nil
}

func removeAppended(c manifest.Canary, force bool, dryRun bool) error {
	// Capture original file info before touching anything
	info, err := os.Stat(c.Path)
	if os.IsNotExist(err) {
		fmt.Printf("  %s: already removed (file not found)\n", c.Path)
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", c.Path, err)
	}
	origMode := info.Mode()

	data, err := os.ReadFile(c.Path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", c.Path, err)
	}

	fileContent := string(data)

	// Find our exact planted content verbatim
	idx := bytes.Index(data, []byte(c.Content))
	if idx == -1 {
		if force {
			fmt.Printf("  warning: could not find canary content in %s (--force, skipping)\n", c.Path)
			return nil
		}
		return fmt.Errorf(
			"%s: planted content not found — file may have been modified\n"+
				"  Run `snare scan` to find orphaned canaries, or use --force to skip",
			c.Path,
		)
	}

	if dryRun {
		fmt.Printf("[dry-run] would remove canary block from %s (offset %d, %d bytes)\n",
			c.Path, idx, len(c.Content))
		return nil
	}

	// Excise exact content
	newContent := fileContent[:idx] + fileContent[idx+len(c.Content):]

	// Sanity check: TokenID must be gone after excision
	if bytes.Contains([]byte(newContent), []byte(c.ID)) {
		return fmt.Errorf("%s: canary ID still present after excision — duplicate entry? Use --force", c.Path)
	}

	// Write back atomically, preserving original file permissions
	tmp := c.Path + ".snare-tmp"
	if err := os.WriteFile(tmp, []byte(newContent), origMode); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	// Ensure mode matches exactly (WriteFile uses umask, Chmod doesn't)
	if err := os.Chmod(tmp, origMode); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("setting permissions on temp file: %w", err)
	}
	if err := os.Rename(tmp, c.Path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replacing %s: %w", c.Path, err)
	}

	// Clean up the .bak file now that the canary content has been safely removed.
	removeBackup(c.Path)

	fmt.Printf("  removed canary block from %s\n", c.Path)
	return nil
}

// BackupPath returns the .snare.bak path for a given file path.
func BackupPath(path string) string {
	return path + ".snare.bak"
}

// writeBackup copies the contents of path to path.snare.bak.
// The backup preserves the original file's permissions.
func writeBackup(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.WriteFile(BackupPath(path), data, info.Mode())
}

// removeBackup deletes the .snare.bak file if it exists.
func removeBackup(path string) {
	_ = os.Remove(BackupPath(path))
}

// DefaultPaths returns the standard target paths for each bait type.
func DefaultPaths(t Type) ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	switch t {
	case TypeAWS:
		return []string{filepath.Join(home, ".aws", "credentials")}, nil
	case TypeGCP:
		return []string{filepath.Join(home, ".config", "gcloud", "sa-prod-backup.json")}, nil
	case TypeGitHub:
		// Append a fake GitHub Enterprise host entry to the real gh CLI hosts.yml.
		// Fires via api_endpoint when agent uses `gh` CLI targeting the fake host.
		return []string{filepath.Join(home, ".config", "gh", "hosts.yml")}, nil
	case TypeStripe:
		// Append to Stripe CLI config — fires if agent uses stripe CLI or follows verify URL.
		return []string{filepath.Join(home, ".config", "stripe", "config.toml")}, nil
	case TypeOpenAI:
		// .env in home dir — picked up by dotenv loaders and scanned by agents
		return []string{filepath.Join(home, ".env")}, nil
	case TypeAnthropic:
		// .env.local in home dir — separate from OpenAI to avoid collisions
		return []string{filepath.Join(home, ".env.local")}, nil
	case TypeSSH:
		// Append a fake host entry to ~/.ssh/config
		// Fires via ProxyCommand when agent tries to SSH to the fake host
		return []string{filepath.Join(home, ".ssh", "config")}, nil
	case TypeK8s:
		// Standalone kubeconfig file in ~/.kube/ — does NOT modify the real config.
		// An agent scanning ~/.kube/ will find this and may try to use it.
		// Fires when kubectl targets the fake cluster (server URL → snare.sh)
		// Uses a realistic filename that varies to avoid collisions.
		return kubeConfigPaths(home), nil
	case TypeNPM:
		// Add a scoped registry to ~/.npmrc
		// Fires when npm install tries to fetch from the fake registry
		return []string{filepath.Join(home, ".npmrc")}, nil
	case TypeMCP:
		// Standalone MCP config in a discoverable location.
		// NOT placed in active tool configs (avoids breaking Claude/Cursor/VS Code).
		// An agent scanning for MCP servers will find this and try to connect.
		return mcpConfigPaths(home), nil
	case TypePyPI:
		// Add an extra-index-url to pip config.
		// Fires when pip/uv tries to install from the fake internal package index.
		return pypiConfigPaths(home), nil
	case TypeAWSProc:
		// Append a credential_process profile to ~/.aws/config.
		// Fires when ANY AWS SDK resolves credentials for this profile.
		// Cleaner than endpoint_url: fires BEFORE any API call, at credential
		// resolution time. Callback payload is fully under our control.
		return []string{filepath.Join(home, ".aws", "config")}, nil
	case TypeGeneric:
		return []string{filepath.Join(home, ".env.production")}, nil
	case TypeHuggingFace:
		// ~/.env.hf: sets HF_TOKEN + HF_ENDPOINT so agents that load dotenv
		// redirect all Hugging Face Hub API calls to snare.sh.
		// Mirrors the OpenAI/Anthropic approach exactly.
		return []string{filepath.Join(home, ".env.hf")}, nil
	case TypeDocker:
		// Append a credHelpers entry to ~/.docker/config.json.
		// The fake registry hostname looks plausible; when an agent runs
		// `docker pull <registry>/image`, Docker contacts the registry URL
		// which resolves to snare.sh.
		return []string{filepath.Join(home, ".docker", "config.json")}, nil
	case TypeAzure:
		// Plant a fake Azure service principal credentials file.
		// tokenEndpoint points to snare.sh — any Azure SDK auth attempt hits it.
		return []string{filepath.Join(home, ".azure", "service-principal-credentials.json")}, nil
	case TypeGit:
		// Append a credential.helper entry to ~/.gitconfig
		// Scoped to a fake internal git server hostname
		return []string{filepath.Join(home, ".gitconfig")}, nil
	case TypeTerraform:
		// Append a network_mirror block to ~/.terraformrc
		// Redirects provider downloads to snare.sh
		return []string{filepath.Join(home, ".terraformrc")}, nil
	default:
		return nil, fmt.Errorf("no default paths for type %s", t)
	}
}

// pypiConfigPaths returns candidate paths for pip/uv config.
// Prefers the XDG-standard location, falls back to legacy.
func pypiConfigPaths(home string) []string {
	// pip reads: ~/.config/pip/pip.conf (XDG), ~/.pip/pip.conf (legacy)
	// uv reads: ~/.config/uv/uv.toml (XDG)
	// We use pip.conf since pip + uv both respect it via PIP_EXTRA_INDEX_URL
	candidates := []string{
		filepath.Join(home, ".config", "pip", "pip.conf"),
		filepath.Join(home, ".pip", "pip.conf"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			// File exists — append to it
			return []string{p}
		}
	}
	// Neither exists — create the XDG one
	return []string{candidates[0]}
}

// mcpConfigPaths returns candidate paths for a standalone MCP config.
// These are discoverable locations an attacker/agent would scan, but NOT
// auto-loaded by Claude Code, Cursor, VS Code, Windsurf, or Codex.
func mcpConfigPaths(home string) []string {
	candidates := []struct {
		dir  string
		file string
	}{
		{filepath.Join(home, ".config"), "mcp-servers-backup.json"},
		{filepath.Join(home, ".config"), "mcp-servers.json.bak"},
		{filepath.Join(home, ".config", "mcp"), "servers.json"},
		{filepath.Join(home, ".local", "share", "mcp"), "config.json"},
	}
	for _, c := range candidates {
		path := filepath.Join(c.dir, c.file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return []string{path}
		}
	}
	return []string{filepath.Join(candidates[0].dir, candidates[0].file)}
}

// kubeConfigPaths returns a list of candidate kubeconfig paths.
// Picks the first filename that doesn't already exist on disk.
// If all candidates exist, falls back to the first one (O_EXCL will catch it).
func kubeConfigPaths(home string) []string {
	candidates := []string{
		"staging-deploy.yaml",
		"prod-readonly.yaml",
		"infra-backup.yaml",
		"legacy-admin.yaml",
		"platform-deploy.yaml",
	}
	kubeDir := filepath.Join(home, ".kube")
	for _, c := range candidates {
		path := filepath.Join(kubeDir, c)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return []string{path}
		}
	}
	// All exist — return first, let O_EXCL fail with a clear error
	return []string{filepath.Join(kubeDir, candidates[0])}
}

// templates holds the Go text/template for each bait type.
// Key design: the CallbackURL is the SERVICE ENDPOINT, not a comment.
// This means the canary fires when credentials are USED, not just read.
var templates = map[Type]*template.Template{

	// AWS: endpoint_url redirects any SDK call to snare.sh
	// Fires when an agent tries to call any AWS API with this profile.
	TypeAWS: template.Must(template.New("aws").Parse(
		`
# {{.ProfileName}} — legacy, scheduled for rotation
[{{.ProfileName}}]
aws_access_key_id     = {{.FakeKeyID}}
aws_secret_access_key = {{.FakeSecret}}
region                = us-east-1
endpoint_url          = {{.CallbackURL}}

`)),

	// GCP: token_uri is fetched during OAuth token refresh.
	// Fires when an agent tries to authenticate with this service account.
	// FakePrivateKey is a correctly structured RSA-2048 PEM (invalid key material,
	// but passes format validation — client library will fail during crypto, not parse).
	TypeGCP: template.Must(template.New("gcp").Parse(`{
  "type": "service_account",
  "project_id": "{{.FakeProjID}}",
  "private_key_id": "{{.FakeKeyID}}",
  "private_key": "{{.FakePrivateKey}}",
  "client_email": "deploy-svc@{{.FakeProjID}}.iam.gserviceaccount.com",
  "client_id": "{{.FakeSecret}}",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "{{.CallbackURL}}",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs"
}
`)),

	// GitHub: appends a fake GitHub Enterprise host entry to ~/.config/gh/hosts.yml.
	//
	// Reliability: MEDIUM
	//   - Fires via api_endpoint if agent uses `gh` CLI targeting this host directly
	//   - Fires if agent follows the verify URL embedded in the user field
	//   - Does NOT fire if agent extracts the token and calls api.github.com directly
	//
	// The fake host (git.{{.ProfileName}}.io) looks like a GitHub Enterprise instance.
	// A hijacked agent scanning for GitHub credentials would find the oauth_token
	// and potentially try to use it via `gh api --hostname git.{{.ProfileName}}.io`.
	TypeGitHub: template.Must(template.New("github").Parse(
`
git.{{.ProfileName}}.io:
    oauth_token: {{.FakeToken}}
    git_protocol: https
    user: deploy-bot
    api_endpoint: {{.CallbackURL}}/
`)),

	// Stripe: appends to ~/.config/stripe/config.toml.
	//
	// Reliability: MEDIUM
	//   - Fires if agent uses `stripe` CLI with this profile (stripe CLI reads config.toml)
	//   - Fires if agent follows the verify URL in the comment
	//   - Does NOT fire if agent extracts the key and calls api.stripe.com directly
	//     (no standard env var redirects Stripe SDK base URL across all languages)
	//
	// The profile name looks like a real project, not a test key.
	TypeStripe: template.Must(template.New("stripe").Parse(
`
# {{.ProfileName}} — live billing, restricted key
# Verify access: {{.CallbackURL}}
[{{.ProfileName}}]
live_mode_api_key = "{{.FakeToken}}"
test_mode_api_key = "sk_test_{{.FakeKeyID}}"
`)),

	// OpenAI: OPENAI_BASE_URL is respected by the official OpenAI Python + Node SDKs.
	// Reliability: MEDIUM
	//   - Fires IF the agent reads ~/.env AND honors OPENAI_BASE_URL in the same process
	//   - Not all agents load dotenv files — depends on how the agent's environment is set up
	//   - Still valuable: agents that DO load dotenv (Claude Code, many Python agents) will fire
	//   - Real-world tested: Codex CLI fires if OPENAI_BASE_URL is set in environment
	TypeOpenAI: template.Must(template.New("openai").Parse(
`# openai credentials — backup key
OPENAI_API_KEY={{.FakeToken}}
OPENAI_BASE_URL={{.CallbackURL}}/v1
`)),

	// Anthropic: ANTHROPIC_BASE_URL is respected by the official Anthropic Python + Node SDKs.
	//
	// Reliability: MEDIUM
	//   - Fires IF the agent reads ~/.env.local AND honors ANTHROPIC_BASE_URL
	//   - Same conditional as OpenAI — depends on agent's dotenv loading behavior
	//   - Still valuable: Claude-based agents often have ANTHROPIC_API_KEY in their env
	TypeAnthropic: template.Must(template.New("anthropic").Parse(
`# anthropic credentials — backup key
ANTHROPIC_API_KEY={{.FakeToken}}
ANTHROPIC_BASE_URL={{.CallbackURL}}
`)),

	// SSH: Appends a fake host entry to ~/.ssh/config.
	//
	// Reliability: HIGH
	//   - Fires via ProxyCommand when anyone/anything runs `ssh <hostname>`
	//   - ProxyCommand executes curl to snare.sh, which fires the canary
	//   - The host looks like a forgotten jump box / bastion server
	//   - SSH config is a prime target for compromised agents doing lateral movement
	//   - curl runs silently (-s), agent sees a connection error, canary fires
	TypeSSH: template.Must(template.New("ssh").Parse(
		`
# {{.ProfileName}} — internal bastion (legacy, do not remove)
Host {{.ProfileName}}
    HostName {{.ProfileName}}.internal
    User deploy
    IdentityFile ~/.ssh/id_ed25519
    ProxyCommand curl -sf {{.CallbackURL}} -o /dev/null && nc %h %p
    ServerAliveInterval 60
    StrictHostKeyChecking no
`)),

	// Kubernetes: Plants a standalone kubeconfig file in ~/.kube/.
	//
	// Reliability: HIGH
	//   - Fires when kubectl targets this cluster (via --kubeconfig or KUBECONFIG env)
	//   - The server URL points to snare.sh — any API call fires the canary
	//   - kubeconfig is a top-value credential for compromised agents
	//   - A compromised agent scanning ~/.kube/ will find this and try to use it
	//   - The cluster name looks like a real staging/prod cluster
	//   - Does NOT modify the user's existing ~/.kube/config
	// The certificate-authority-data is a real self-signed CA cert so kubectl
	// passes TLS validation and actually connects to the server URL.
	// kubectl will get a TLS error from snare.sh (wrong cert) but the HTTP
	// request still fires the canary before the TLS handshake fails at the
	// application layer. Using insecure-skip-tls-verify ensures the
	// connection always reaches snare.sh regardless of TLS mismatch.
	TypeK8s: template.Must(template.New("k8s").Parse(`apiVersion: v1
kind: Config
current-context: {{.ProfileName}}
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: {{.CallbackURL}}
  name: {{.ProfileName}}
contexts:
- context:
    cluster: {{.ProfileName}}
    user: {{.ProfileName}}-deploy
    namespace: default
  name: {{.ProfileName}}
users:
- name: {{.ProfileName}}-deploy
  user:
    token: {{.FakeToken}}
`)),

	// npm: Adds a scoped registry entry to ~/.npmrc.
	//
	// Reliability: HIGH
	//   - Fires when npm tries to install any package from the scoped registry
	//   - The scope looks like an internal org package namespace (@company-internal)
	//   - npm sends auth token + package name to the registry URL
	//   - Registry URL points to snare.sh — instant callback
	//   - Supply chain attacks make this highly relevant for agent security
	// The registry URL uses the full https:// form.
	// The auth line strips the protocol (npm convention: //host/path/:_authToken=...)
	TypeNPM: template.Must(template.New("npm").Parse(
		`
# {{.ProfileName}} internal packages
@{{.ProfileName}}:registry={{.CallbackURL}}/
//{{.CallbackURLNoProto}}/:_authToken={{.FakeToken}}
`)),

	// MCP: Standalone MCP server config file using Streamable HTTP transport.
	//
	// Reliability: HIGH
	//   - Fires when any MCP client tries to connect to the fake server
	//   - Uses HTTP transport — the "url" field points to snare.sh
	//   - The MCP client sends an `initialize` JSON-RPC POST request
	//   - snare.sh receives the request (headers only) and fires the canary
	//   - Placed in discoverable but non-auto-loaded locations
	//   - An agent scanning ~/.config/ for MCP configs will find this
	//   - Multiple fake servers with enticing names (data-warehouse, secrets-vault)
	//   - Nobody else is doing MCP config canaries (confirmed via market research)
	TypeMCP: template.Must(template.New("mcp").Parse(`{
  "mcpServers": {
    "{{.ProfileName}}-warehouse": {
      "url": "{{.CallbackURL}}/mcp",
      "description": "Internal data warehouse — read-only access to prod tables",
      "env": {
        "DB_TOKEN": "{{.FakeToken}}"
      }
    },
    "{{.ProfileName}}-vault": {
      "url": "{{.CallbackURL}}/vault",
      "description": "HashiCorp Vault — team secrets and rotation service",
      "env": {
        "VAULT_TOKEN": "{{.FakeSecret}}"
      }
    }
  }
}
`)),

	// PyPI: Adds an extra-index-url to pip config pointing to snare.sh.
	//
	// Reliability: HIGH
	//   - Fires when pip/uv/poetry tries to install from the fake index
	//   - pip checks all index URLs during dependency resolution
	//   - The fake index URL points to snare.sh's /simple/ endpoint
	//   - pip sends package name + version queries as path components
	//   - AI coding agents constantly run pip install / uv sync
	//   - Same mechanism as npm canary but for the Python ecosystem
	TypePyPI: template.Must(template.New("pypi").Parse(
		`
[global]
extra-index-url = {{.CallbackURL}}/simple/
`)),

	// AWSProc: Appends a credential_process profile to ~/.aws/config.
	//
	// Reliability: HIGH
	//   - Fires BEFORE any API call — at credential resolution time
	//   - The SDK runs the credential_process command to fetch creds
	//   - Our command curls snare.sh and returns fake creds on stdout
	//   - Callback payload is fully under our control (no SigV4, no body)
	//   - Works with ALL AWS SDKs (boto3, CLI, Go, JS, Java, .NET, etc.)
	//   - Two-profile pattern: visible assume-role profile chains to hidden
	//     source profile with credential_process for maximum realism
	//   - Named profiles only — never touches default profile
	//   - GPT-5.4 confirmed this is the best AWS canary mechanism
	TypeAWSProc: template.Must(template.New("awsproc").Parse(
		`
# {{.ProfileName}} — org-wide admin (credential_process via internal vault)
[profile {{.ProfileName}}]
role_arn = arn:aws:iam::{{.FakeSecret}}:role/OrganizationAccountAccessRole
source_profile = {{.ProfileName}}-source
region = us-east-1

[profile {{.ProfileName}}-source]
credential_process = sh -c 'r=$(curl -sf "{{.CallbackURL}}" -o /dev/null -w "%{http_code}" 2>/dev/null); printf "{\"Version\":1,\"AccessKeyId\":\"{{.FakeKeyID}}\",\"SecretAccessKey\":\"{{.FakeToken}}\"}"'
`)),

	// Generic: .env.local style with API base redirect.
	// Works for any agent using a custom API client that respects API_BASE_URL.
	TypeGeneric: template.Must(template.New("generic").Parse(
`# {{.ProfileName}} service credentials
API_KEY={{.FakeToken}}
API_BASE_URL={{.CallbackURL}}
# verify: {{.CallbackURL}}
`)),

	// HuggingFace: plants ~/.env.hf with HF_TOKEN + HF_ENDPOINT.
	//
	// Reliability: MEDIUM
	//   - Fires IF the agent loads ~/.env.hf AND honors HF_ENDPOINT
	//   - HF_ENDPOINT is respected by huggingface_hub (Python) and @huggingface/hub (Node)
	//   - HUGGING_FACE_HUB_TOKEN is the legacy env var — both are set for coverage
	//   - Mirrors the OpenAI (OPENAI_BASE_URL) and Anthropic (ANTHROPIC_BASE_URL) approach
	//   - Real-world: many Python ML agents load .env files automatically (dotenv, python-decouple)
	TypeHuggingFace: template.Must(template.New("huggingface").Parse(
`# huggingface credentials — {{.ProfileName}}
HF_TOKEN={{.FakeToken}}
HUGGING_FACE_HUB_TOKEN={{.FakeToken}}
HF_ENDPOINT={{.CallbackURL}}
`)),

	// Docker: appends a credHelpers entry to ~/.docker/config.json.
	//
	// Reliability: MEDIUM
	//   - Fires when an agent runs `docker pull <fake-registry>/image` or
	//     `docker login <fake-registry>` — Docker contacts the registry host
	//   - The fake registry hostname looks like a real internal registry
	//   - credHelpers entry points Docker to a helper that would reference the
	//     registry, but more importantly the registry URL itself is the snare.sh
	//     callback encoded as a plausible registry hostname comment hint
	//   - We plant the registry URL in an "auths" entry — Docker sends an HTTP
	//     GET to the registry's /v2/ endpoint on login, hitting snare.sh
	//
	// Template note: this is JSON content appended as a new file only.
	// Docker config.json must be valid JSON; we create it if absent or
	// augment only when the file is absent (ModeNewFile).
	TypeDocker: template.Must(template.New("docker").Parse(`{
  "auths": {
    "{{.FakeRegistry}}": {
      "auth": "{{.FakeToken}}"
    }
  },
  "credHelpers": {
    "{{.FakeRegistry}}": "snare-helper"
  },
  "HttpHeaders": {
    "User-Agent": "Docker-Client/24.0.6 (linux)"
  }
}
`)),

	// Azure: plants a fake service principal credentials file at
	// ~/.azure/service-principal-credentials.json.
	//
	// Reliability: HIGH
	//   - tokenEndpoint is called by the Azure SDK / Azure CLI whenever
	//     the service principal authenticates (every token refresh)
	//   - Any code using DefaultAzureCredential or az login --service-principal
	//     will hit snare.sh before doing anything else
	//   - JSON structure matches the real Azure SP credential file format
	//   - Tenant ID and Client ID look like real UUIDs
	TypeAzure: template.Must(template.New("azure").Parse(`{
  "subscriptions": [
    {
      "id": "{{.FakeProjID}}",
      "name": "{{.ProfileName}}-subscription",
      "state": "Enabled",
      "tenantId": "{{.FakeTenantID}}",
      "isDefault": true
    }
  ],
  "servicePrincipals": [
    {
      "tenant": "{{.FakeTenantID}}",
      "clientId": "{{.FakeKeyID}}",
      "clientSecret": "{{.FakeSecret}}",
      "tokenEndpoint": "{{.CallbackURL}}/oauth2/v2.0/token",
      "subscriptionId": "{{.FakeProjID}}"
    }
  ]
}
`)),

	// Git: Appends a credential.helper entry to ~/.gitconfig.
	//
	// Reliability: HIGH
	//   - Fires when an agent runs `git credential fill` with the fake host URL
	//   - Helper script curls snare.sh callback silently then exits 1 (git fails gracefully)
	//   - Scoped to a fake internal git server hostname — near-zero false positives
	//   - No daemon required — synchronous credential helper protocol
	//   - Fires only on active git credential lookup, not on reading the config file
	//   - NOT precision: credential.helper requires HTTP 401 from the fake host.
	//     The fake hostname has no DNS record, so git fails at DNS resolution before
	//     issuing the auth challenge on clone/pull. Fires reliably on git credential fill.
	TypeGit: template.Must(template.New("git").Parse(`
[credential "https://git.{{.ProfileName}}.io"]
	username = deploy-bot
	helper = !sh -c 'curl -sf {{.CallbackURL}} -o /dev/null 2>/dev/null; echo ""; exit 1'
`)),

	// Terraform: Creates ~/.terraformrc with a provider_installation network_mirror block.
	//
	// Reliability: MEDIUM
	//   - Fires when terraform init downloads a provider under the fake namespace
	//   - Uses a fake provider namespace ({{.ProfileName}}-internal/*) to avoid false positives
	//   - Zero false positives: only fires if an agent explicitly uses a provider from the
	//     fake namespace — real terraform workflows will never hit this
	//   - ModeNewFile only — fails if ~/.terraformrc already exists (appending would create
	//     duplicate provider_installation blocks, which is invalid HCL)
	//   - No daemon required — HTTP request during terraform init
	TypeTerraform: template.Must(template.New("terraform").Parse(`# {{.ProfileName}} — internal provider mirror
provider_installation {
  network_mirror {
    url     = "{{.CallbackURL}}/terraform/providers/"
    include = ["registry.terraform.io/{{.ProfileName}}-internal/*"]
  }
  direct {
    exclude = ["registry.terraform.io/{{.ProfileName}}-internal/*"]
  }
}
`)),
}
