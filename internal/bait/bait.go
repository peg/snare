// Package bait handles generation and placement of canary artifacts.
// Bait is planted in real credential locations — NOT in ~/.snare/.
package bait

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"
	"bytes"
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
	CallbackURL string // snare.sh callback URL
	// Per-type fake values — realistic but non-functional
	FakeKeyID     string
	FakeSecret    string
	FakeToken     string
	FakeProjID    string
	ProfileName   string // e.g. "prod-us-east-1-legacy"
}

// PlacedFile describes a file that was written.
type PlacedFile struct {
	Path    string
	Type    Type
	TokenID string
}

// Plant generates bait content and writes it to the target path.
// It will APPEND to existing files (e.g. ~/.aws/credentials) rather
// than overwriting, and will never touch a file if canary content
// is already present.
func Plant(t Type, params Params, targetPath string, dryRun bool) (*PlacedFile, error) {
	tmpl, ok := templates[t]
	if !ok {
		return nil, fmt.Errorf("unknown bait type: %s", t)
	}

	// Render template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return nil, fmt.Errorf("rendering template: %w", err)
	}
	content := buf.String()

	if dryRun {
		fmt.Printf("[dry-run] would write to %s:\n%s\n", targetPath, content)
		return &PlacedFile{Path: targetPath, Type: t, TokenID: params.TokenID}, nil
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
		return nil, fmt.Errorf("creating parent dir: %w", err)
	}

	// Check if already planted
	if existing, err := os.ReadFile(targetPath); err == nil {
		if bytes.Contains(existing, []byte(params.TokenID)) {
			return nil, fmt.Errorf("canary %s already present in %s", params.TokenID, targetPath)
		}
	}

	// Append (for files like ~/.aws/credentials) or create new
	f, err := os.OpenFile(targetPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", targetPath, err)
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		return nil, fmt.Errorf("writing bait: %w", err)
	}

	return &PlacedFile{Path: targetPath, Type: t, TokenID: params.TokenID}, nil
}

// DefaultPaths returns the standard target paths for each bait type.
func DefaultPaths(t Type) ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	switch t {
	case TypeAWS:
		return []string{
			filepath.Join(home, ".aws", "credentials"),
		}, nil
	case TypeGCP:
		return []string{
			filepath.Join(home, ".config", "gcloud", "sa-prod-backup.json"),
		}, nil
	case TypeGitHub:
		// ~/.config/gh/hosts.yml equivalent or project .env
		return []string{
			filepath.Join(home, ".config", "gh", "canary-hosts.yml"),
		}, nil
	default:
		return nil, fmt.Errorf("no default paths for type %s", t)
	}
}

// templates holds the Go text/template for each bait type.
var templates = map[Type]*template.Template{
	TypeAWS: template.Must(template.New("aws").Parse(`
# {{.ProfileName}} — legacy access, rotate when migrated
# Provisioned: internal-tools — verify at {{.CallbackURL}}
[{{.ProfileName}}]
aws_access_key_id     = {{.FakeKeyID}}
aws_secret_access_key = {{.FakeSecret}}
region                = us-east-1

`)),

	TypeGitHub: template.Must(template.New("github").Parse(`
# machine-user token — read-only, prod registry access
# {{.CallbackURL}}
GITHUB_TOKEN={{.FakeToken}}
`)),

	TypeStripe: template.Must(template.New("stripe").Parse(`
# Stripe production key — billing service
# verify: {{.CallbackURL}}
STRIPE_SECRET_KEY={{.FakeToken}}
`)),

	TypeGCP: template.Must(template.New("gcp").Parse(`{
  "type": "service_account",
  "project_id": "{{.FakeProjID}}",
  "private_key_id": "{{.FakeKeyID}}",
  "client_email": "deploy-svc@{{.FakeProjID}}.iam.gserviceaccount.com",
  "client_id": "{{.FakeSecret}}",
  "token_uri": "https://oauth2.googleapis.com/token",
  "_snare": "{{.CallbackURL}}"
}
`)),
}
