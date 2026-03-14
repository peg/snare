package serve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// canaryTypeMeta holds display metadata for each canary type.
type canaryTypeMeta struct {
	Emoji string
	Name  string
}

var canaryTypes = map[string]canaryTypeMeta{
	"aws":       {Emoji: "🔑", Name: "AWS"},
	"gcp":       {Emoji: "☁️", Name: "GCP"},
	"github":    {Emoji: "⬛", Name: "GitHub"},
	"stripe":    {Emoji: "💳", Name: "Stripe"},
	"openai":    {Emoji: "🤖", Name: "OpenAI"},
	"anthropic": {Emoji: "🟠", Name: "Anthropic"},
	"ssh":       {Emoji: "🔒", Name: "SSH"},
	"k8s":       {Emoji: "☸️", Name: "Kubernetes"},
	"npm":       {Emoji: "📦", Name: "npm"},
	"mcp":       {Emoji: "🔌", Name: "MCP"},
	"pypi":      {Emoji: "🐍", Name: "PyPI"},
	"awsproc":   {Emoji: "⚙️", Name: "AWS (credential_process)"},
	"docker":    {Emoji: "🐳", Name: "Docker"},
	"generic":   {Emoji: "🗝️", Name: "Generic"},
}

var defaultCanaryType = canaryTypeMeta{Emoji: "🪤", Name: "Canary"}

// cloudProviders is a list of known cloud/AI infrastructure org name fragments.
var cloudProviders = []string{
	"amazon", "google", "microsoft", "openai", "anthropic",
	"digitalocean", "linode", "akamai", "vultr", "hetzner",
	"fly.io", "railway", "render", "lambda labs", "coreweave",
	"together", "replicate", "modal",
}

// alertPayload is the generic JSON payload sent to webhooks.
type alertPayload struct {
	Token      string `json:"token"`
	Timestamp  string `json:"timestamp"`
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
	CanaryType string `json:"canary_type,omitempty"`
	Label      string `json:"label,omitempty"`
	IsTest     bool   `json:"is_test"`
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	Country    string `json:"country,omitempty"`
	City       string `json:"city,omitempty"`
	ASN        string `json:"asn,omitempty"`
	ASNOrg     string `json:"asn_org,omitempty"`
}

// deliverWebhook sends an alert to the configured webhook URL.
// It selects the appropriate format based on the URL.
func deliverWebhook(webhookURL string, e event, reg *tokenReg) {
	if webhookURL == "" || webhookURL == "use-global" {
		return
	}

	isDiscord := strings.Contains(webhookURL, "discord.com/api/webhooks")
	isSlack := strings.Contains(webhookURL, "hooks.slack.com")

	ct := defaultCanaryType
	if reg != nil {
		if m, ok := canaryTypes[reg.CanaryType]; ok {
			ct = m
		}
	}

	asnLower := strings.ToLower(e.ASNOrg)
	fromCloud := false
	for _, p := range cloudProviders {
		if strings.Contains(asnLower, p) {
			fromCloud = true
			break
		}
	}

	var body []byte
	var err error

	switch {
	case isDiscord:
		body, err = json.Marshal(buildDiscordPayload(e, reg, ct, fromCloud))
	case isSlack:
		body, err = json.Marshal(buildSlackPayload(e, reg, ct, fromCloud))
	default:
		body, err = json.Marshal(buildGenericPayload(e, reg, ct, fromCloud))
	}
	if err != nil {
		log.Printf("webhook marshal error: %v", err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", webhookURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("webhook request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "snare-server/1.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("webhook delivery error token=%s: %v", e.TokenID, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("webhook returned %d for token=%s url=%s", resp.StatusCode, e.TokenID, webhookURL)
	}
}

func buildDiscordPayload(e event, reg *tokenReg, ct canaryTypeMeta, fromCloud bool) map[string]interface{} {
	ts := strings.Replace(e.Timestamp, "T", " ", 1)
	ts = strings.TrimSuffix(ts, "Z") + " UTC"
	loc := joinNonEmpty(e.City, e.Country)
	if loc == "" {
		loc = "unknown"
	}
	network := e.ASNOrg
	if network == "" {
		network = e.IP
	}
	if network == "" {
		network = "unknown"
	}

	var title string
	if e.IsTest {
		title = fmt.Sprintf("🧪 Test alert — %s", ct.Name)
	} else if reg != nil && reg.Label != "" {
		title = fmt.Sprintf("%s %s canary fired — %s", ct.Emoji, ct.Name, reg.Label)
	} else {
		title = fmt.Sprintf("%s %s canary fired", ct.Emoji, ct.Name)
	}

	fields := []map[string]interface{}{
		{"name": "Token", "value": "`" + e.TokenID + "`", "inline": false},
		{"name": "Time", "value": ts, "inline": true},
		{"name": "Method", "value": e.Method, "inline": true},
		{"name": "IP", "value": e.IP, "inline": true},
		{"name": "Location", "value": loc, "inline": true},
		{"name": "Network", "value": network, "inline": true},
		{"name": "UA", "value": "`" + truncate(e.UserAgent, 120) + "`", "inline": false},
	}
	if fromCloud && !e.IsTest {
		fields = append(fields, map[string]interface{}{
			"name":   "⚠️ Likely AI agent",
			"value":  fmt.Sprintf("Request from **%s** — cloud infrastructure", e.ASNOrg),
			"inline": false,
		})
	}

	color := 0xB2121A
	if e.IsTest {
		color = 0x888888
	}

	return map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":     title,
				"color":     color,
				"fields":    fields,
				"footer":    map[string]string{"text": "snare-server · request body was never captured"},
				"timestamp": e.Timestamp,
			},
		},
	}
}

func buildSlackPayload(e event, reg *tokenReg, ct canaryTypeMeta, fromCloud bool) map[string]interface{} {
	loc := joinNonEmpty(e.City, e.Country)
	if loc == "" {
		loc = "unknown"
	}

	var title string
	if e.IsTest {
		title = fmt.Sprintf("🧪 Test alert — %s", ct.Name)
	} else if reg != nil && reg.Label != "" {
		title = fmt.Sprintf("%s *%s canary fired* — %s", ct.Emoji, ct.Name, reg.Label)
	} else {
		title = fmt.Sprintf("%s *%s canary fired*", ct.Emoji, ct.Name)
	}

	fields := []map[string]string{
		{"title": "Token", "value": "`" + e.TokenID + "`", "short": "false"},
		{"title": "IP", "value": e.IP, "short": "true"},
		{"title": "Location", "value": loc, "short": "true"},
		{"title": "UA", "value": truncate(e.UserAgent, 100), "short": "false"},
	}
	if fromCloud && !e.IsTest {
		fields = append(fields, map[string]string{
			"title": "⚠️ Source",
			"value": "Cloud infrastructure: " + e.ASNOrg,
			"short": "false",
		})
	}

	return map[string]interface{}{
		"text": title,
		"attachments": []map[string]interface{}{
			{
				"color":  "#B2121A",
				"fields": fields,
				"footer": "snare-server · request body was never captured",
			},
		},
	}
}

func buildGenericPayload(e event, reg *tokenReg, ct canaryTypeMeta, fromCloud bool) map[string]interface{} {
	var canaryType, label string
	if reg != nil {
		canaryType = reg.CanaryType
		label = reg.Label
	}
	return map[string]interface{}{
		"event":       "canary.fired",
		"is_test":     e.IsTest,
		"token":       e.TokenID,
		"canary_type": canaryType,
		"label":       label,
		"timestamp":   e.Timestamp,
		"ip":          e.IP,
		"user_agent":  e.UserAgent,
		"location": map[string]string{
			"city":    e.City,
			"country": e.Country,
		},
		"network": map[string]interface{}{
			"asn":      e.ASN,
			"org":      e.ASNOrg,
			"is_cloud": fromCloud,
		},
		"request": map[string]string{
			"method": e.Method,
			"path":   e.Path,
		},
		"privacy": "request_body_never_captured",
	}
}

func joinNonEmpty(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
