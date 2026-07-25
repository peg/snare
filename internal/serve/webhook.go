package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// canaryTypeMeta holds display metadata for each canary type.
type canaryTypeMeta struct {
	Emoji string
	Name  string
}

var canaryTypes = map[string]canaryTypeMeta{
	"aws":         {Emoji: "🔑", Name: "AWS"},
	"gcp":         {Emoji: "☁️", Name: "GCP"},
	"github":      {Emoji: "⬛", Name: "GitHub"},
	"stripe":      {Emoji: "💳", Name: "Stripe"},
	"openai":      {Emoji: "🤖", Name: "OpenAI"},
	"anthropic":   {Emoji: "🟠", Name: "Anthropic"},
	"ssh":         {Emoji: "🔒", Name: "SSH"},
	"k8s":         {Emoji: "☸️", Name: "Kubernetes"},
	"npm":         {Emoji: "📦", Name: "npm"},
	"mcp":         {Emoji: "🔌", Name: "MCP"},
	"pypi":        {Emoji: "🐍", Name: "PyPI"},
	"awsproc":     {Emoji: "⚙️", Name: "AWS (credential_process)"},
	"huggingface": {Emoji: "🤗", Name: "Hugging Face"},
	"docker":      {Emoji: "🐳", Name: "Docker"},
	"azure":       {Emoji: "🔷", Name: "Azure"},
	"git":         {Emoji: "🌿", Name: "Git"},
	"terraform":   {Emoji: "🧱", Name: "Terraform"},
	"generic":     {Emoji: "🗝️", Name: "Generic"},
}

var defaultCanaryType = canaryTypeMeta{Emoji: "🪤", Name: "Canary"}

// cloudProviders is a list of known cloud/AI infrastructure org name fragments.
var cloudProviders = []string{
	"amazon", "google", "microsoft", "openai", "anthropic",
	"digitalocean", "linode", "akamai", "vultr", "hetzner",
	"fly.io", "railway", "render", "lambda labs", "coreweave",
	"together", "replicate", "modal",
}

type lookupIPFunc func(context.Context, string) ([]net.IPAddr, error)

var blockedWebhookPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func validateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("malformed URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme must be https")
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("host is required")
	}
	if u.User != nil {
		return fmt.Errorf("userinfo is not allowed")
	}
	if u.Fragment != "" {
		return fmt.Errorf("fragments are not allowed")
	}
	if strings.Contains(u.Hostname(), "%") {
		return fmt.Errorf("IPv6 zones are not allowed")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !isPublicWebhookIP(ip) {
		return fmt.Errorf("host must use a public IP address")
	}
	return nil
}

func isPublicWebhookIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range blockedWebhookPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func newWebhookClient(lookup lookupIPFunc) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("invalid webhook address: %w", err)
			}

			var resolved []net.IPAddr
			if literal := net.ParseIP(host); literal != nil {
				resolved = []net.IPAddr{{IP: literal}}
			} else {
				resolved, err = lookup(ctx, host)
				if err != nil {
					return nil, fmt.Errorf("resolve webhook host: %w", err)
				}
			}
			if len(resolved) == 0 {
				return nil, fmt.Errorf("webhook host resolved to no addresses")
			}
			for _, candidate := range resolved {
				if !isPublicWebhookIP(candidate.IP) {
					return nil, fmt.Errorf("webhook host resolved to a non-public address")
				}
			}

			var lastErr error
			for _, candidate := range resolved {
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, fmt.Errorf("dial webhook host: %w", lastErr)
		},
	}

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// deliverWebhook sends an alert to the configured webhook URL.
// It selects the appropriate format based on the URL.
func deliverWebhook(client *http.Client, webhookURL string, e event, reg *tokenReg) {
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

	req, err := http.NewRequest("POST", webhookURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("webhook request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "snare-server/1.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("webhook delivery error token=*** url=***: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		log.Printf("webhook returned %d for token=*** url=***", resp.StatusCode)
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
				"footer":    map[string]string{"text": "snare-server · IP, UA, timestamp only — no request body"},
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
				"footer": "snare-server · IP, UA, timestamp only — no request body",
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
