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
	TypeAWS     Type = "aws"
	TypeGitHub  Type = "github"
	TypeStripe  Type = "stripe"
	TypeGCP     Type = "gcp"
	TypeGeneric Type = "generic"
)

// Params are filled into bait templates.
type Params struct {
	TokenID     string // unique canary ID
	CallbackURL string // snare.sh callback URL — used as the SERVICE ENDPOINT, not a comment
	Label       string // user-supplied label prefix (optional)
	// Per-type fake values — realistic looking but non-functional
	FakeKeyID   string
	FakeSecret  string
	FakeToken   string
	FakeProjID  string
	ProfileName string // e.g. "prod-us-east-1-legacy"
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
// Returns PlacedFile with exact Content written — caller must persist this
// to the manifest for safe teardown.
func Plant(t Type, params Params, targetPath string, dryRun bool) (*PlacedFile, error) {
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
		action := "create"
		if mode == manifest.ModeAppend {
			action = "append to"
		}
		fmt.Printf("[dry-run] would %s %s:\n---\n%s---\n", action, targetPath, content)
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

	// Write: append for existing files, create new for new files
	flags := os.O_APPEND | os.O_CREATE | os.O_WRONLY
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
	data, err := os.ReadFile(c.Path)
	if os.IsNotExist(err) {
		fmt.Printf("  %s: already removed (file not found)\n", c.Path)
		return nil
	}
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

	// Write back atomically
	tmp := c.Path + ".snare-tmp"
	if err := os.WriteFile(tmp, []byte(newContent), 0600); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := os.Rename(tmp, c.Path); err != nil {
		_ = os.Remove(tmp) // best-effort cleanup
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
		return []string{filepath.Join(home, ".config", "gh", "snare-hosts.yml")}, nil
	case TypeStripe, TypeGeneric:
		return []string{filepath.Join(home, ".snare-env")}, nil
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

	// GCP: token_uri is fetched during OAuth token refresh
	// Fires when an agent tries to authenticate with this service account.
	TypeGCP: template.Must(template.New("gcp").Parse(`{
  "type": "service_account",
  "project_id": "{{.FakeProjID}}",
  "private_key_id": "{{.FakeKeyID}}",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA{{.FakeSecret}}\n-----END RSA PRIVATE KEY-----\n",
  "client_email": "deploy-svc@{{.FakeProjID}}.iam.gserviceaccount.com",
  "client_id": "{{.FakeSecret}}",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "{{.CallbackURL}}",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs"
}
`)),

	// GitHub: points at snare.sh as the GitHub API base
	// Fires when an agent tries to call the GitHub API with this token.
	TypeGitHub: template.Must(template.New("github").Parse(
		`# snare-hosts.yml — machine user token
github.com:
    oauth_token: {{.FakeToken}}
    git_protocol: https
    api_endpoint: {{.CallbackURL}}/
`)),

	// Stripe: API base URL redirect
	// Fires when an agent tries to make any Stripe API call.
	TypeStripe: template.Must(template.New("stripe").Parse(
		`# billing service credentials
STRIPE_SECRET_KEY={{.FakeToken}}
STRIPE_API_BASE={{.CallbackURL}}
`)),

	// Generic: catch-all .env style with API base
	TypeGeneric: template.Must(template.New("generic").Parse(
		`# service credentials — {{.ProfileName}}
API_KEY={{.FakeToken}}
API_BASE_URL={{.CallbackURL}}
`)),
}
