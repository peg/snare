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
	TypeGeneric   Type = "generic"
)

// Params are filled into bait templates.
type Params struct {
	TokenID        string // unique canary ID
	CallbackURL    string // snare.sh callback URL — used as the SERVICE ENDPOINT, not a comment
	Label          string // user-supplied label prefix (optional)
	// Per-type fake values — realistic looking but non-functional
	FakeKeyID      string
	FakeSecret     string
	FakeToken      string
	FakeProjID     string
	FakePrivateKey string // PEM-formatted RSA private key (invalid but correct structure)
	ProfileName    string // e.g. "prod-us-east-1-legacy"
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

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
		return nil, fmt.Errorf("creating parent dir: %w", err)
	}

	var flags int
	if mode == manifest.ModeNewFile {
		// O_EXCL ensures we fail rather than overwrite if file appears between Stat and Open
		flags = os.O_CREATE | os.O_EXCL | os.O_WRONLY
	} else {
		flags = os.O_APPEND | os.O_WRONLY
	}
	f, err := os.OpenFile(targetPath, flags, 0600)
	if err != nil {
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
	if currentHash != c.ContentHash && !force {
		return fmt.Errorf(
			"%s: content has changed since planting (hash mismatch)\n"+
				"  Use --force to remove anyway (file will be deleted regardless)",
			c.Path,
		)
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

	fmt.Printf("  removed canary block from %s\n", c.Path)
	return nil
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
	case TypeOpenAI, TypeAnthropic:
		// .env.local in home dir — picked up by dotenv loaders and scanned by agents
		return []string{filepath.Join(home, ".env.local")}, nil
	case TypeGeneric:
		return []string{filepath.Join(home, ".env.local")}, nil
	default:
		return nil, fmt.Errorf("no default paths for type %s", t)
	}
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
	// Fires when an agent makes any OpenAI API call using these credentials.
	// This is particularly relevant: a compromised agent might read its own API keys.
	TypeOpenAI: template.Must(template.New("openai").Parse(
`# openai credentials — backup key
OPENAI_API_KEY={{.FakeToken}}
OPENAI_BASE_URL={{.CallbackURL}}/v1
`)),

	// Anthropic: ANTHROPIC_BASE_URL is respected by the official Anthropic Python + Node SDKs.
	// Same threat model as OpenAI — an agent reading its own runtime credentials.
	TypeAnthropic: template.Must(template.New("anthropic").Parse(
`# anthropic credentials — backup key
ANTHROPIC_API_KEY={{.FakeToken}}
ANTHROPIC_BASE_URL={{.CallbackURL}}
`)),

	// Generic: .env.local style with API base redirect.
	// Works for any agent using a custom API client that respects API_BASE_URL.
	TypeGeneric: template.Must(template.New("generic").Parse(
`# {{.ProfileName}} service credentials
API_KEY={{.FakeToken}}
API_BASE_URL={{.CallbackURL}}
# verify: {{.CallbackURL}}
`)),
}
