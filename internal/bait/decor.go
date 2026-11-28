package bait

import (
	"strings"

	"github.com/peg/snare/internal/token"
)

// Decor holds the human-readable parts of a template. They vary per plant so
// that planted files share no fixed phrase an attacker could search for.
type Decor struct {
	Comment string // may be empty
	Account string
	Service string
}

type decorPool struct{ comments, accounts, services []string }

// {name} is replaced with the canary's profile name. An empty comment is a
// valid choice: many real config blocks have none.
var decorPools = map[Type]decorPool{
	TypeAWS:     {comments: []string{"", "{name} — legacy, scheduled for rotation", "break-glass, rotate after use", "migrated from the old org account", "owner: platform"}},
	TypeAWSProc: {comments: []string{"", "{name} — org admin via vault", "SSO fallback, approved access only", "admin role (vault-issued creds)", "managed by infra tooling"}},
	TypeSSH: {
		comments: []string{"", "{name} — jump host, do not remove", "prod access via bastion", "legacy bastion, decommission pending", "added by onboarding"},
		accounts: []string{"deploy", "ops", "admin", "ubuntu", "ec2-user"},
	},
	TypeK8s:         {accounts: []string{"deploy", "admin", "ci", "ops"}},
	TypeNPM:         {comments: []string{"", "{name} packages", "private registry", "internal scope"}},
	TypeGCP:         {accounts: []string{"deploy-svc", "ci-runner", "backup-svc", "terraform", "data-sync"}},
	TypeMCP:         {accounts: []string{"warehouse", "analytics", "reporting", "metrics"}, services: []string{"vault", "secrets", "keys", "credentials"}},
	TypeOpenAI:      {comments: []string{"", "openai — backup key", "team key, rotate quarterly", "OpenAI (shared)"}},
	TypeAnthropic:   {comments: []string{"", "anthropic — backup key", "team key, rotate quarterly", "Anthropic (shared)"}},
	TypeGeneric:     {comments: []string{"", "service credentials", "prod API key", "do not commit"}},
	TypeHuggingFace: {comments: []string{"", "huggingface — {name}", "HF inference (team)", "hub token"}},
	TypeGit:         {accounts: []string{"deploy-bot", "ci-bot", "release-bot", "build-svc"}},
	TypeTerraform:   {comments: []string{"", "{name} — provider mirror", "mirror for internal providers", "air-gapped provider mirror"}},
}

// NewDecor picks a random Decor for t. name fills {name} placeholders.
func NewDecor(t Type, name string) Decor {
	p := decorPools[t]
	d := Decor{Comment: pick(p.comments), Account: pick(p.accounts), Service: pick(p.services)}
	if name == "" && strings.Contains(d.Comment, "{name}") {
		d.Comment = ""
	}
	d.Comment = strings.ReplaceAll(d.Comment, "{name}", name)
	return d
}

func pick(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[token.MustRandInt(len(s))]
}
