package serve

import (
	"html/template"
	"net/http"
	"time"
)

// dashboardTmpl is the server-side rendered dashboard.
// Dark monospace theme, auto-refreshes every 10 seconds.
var dashboardTmpl = template.Must(template.New("dashboard").Funcs(template.FuncMap{
	"canaryEmoji": func(ct string) string {
		if m, ok := canaryTypes[ct]; ok {
			return m.Emoji
		}
		return "🪤"
	},
	"canaryName": func(ct string) string {
		if m, ok := canaryTypes[ct]; ok {
			return m.Name
		}
		if ct == "" {
			return "—"
		}
		return ct
	},
	"shortToken": func(t string) string {
		if len(t) > 20 {
			return t[:20] + "…"
		}
		return t
	},
	"fmtTime": func(ts string) string {
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return ts
		}
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	},
	"shortUA": func(ua string) string {
		if len(ua) > 60 {
			return ua[:60] + "…"
		}
		if ua == "" {
			return "—"
		}
		return ua
	},
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="10">
<title>snare — dashboard</title>
<style>
  :root {
    --bg:      #0d0d0d;
    --surface: #141414;
    --border:  #2a2a2a;
    --accent:  #b2121a;
    --green:   #3fb950;
    --dim:     #555;
    --text:    #c9c9c9;
    --bright:  #eaeaea;
    --mono:    'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Courier New', monospace;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    font-size: 13px;
    line-height: 1.6;
  }

  /* ── Layout ── */
  header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 12px 24px;
    display: flex;
    align-items: center;
    gap: 16px;
  }
  header h1 {
    font-size: 16px;
    font-weight: 700;
    color: var(--bright);
    letter-spacing: 0.05em;
  }
  header h1 span { color: var(--accent); }
  .badge {
    background: var(--accent);
    color: #fff;
    border-radius: 4px;
    padding: 1px 7px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.08em;
  }
  .status-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--green);
    display: inline-block;
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%,100% { opacity: 1; }
    50%      { opacity: 0.4; }
  }
  .ts {
    margin-left: auto;
    color: var(--dim);
    font-size: 11px;
  }

  main { padding: 24px; max-width: 1200px; }

  /* ── Sections ── */
  .section { margin-bottom: 32px; }
  .section-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 12px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 6px;
  }
  .section-header h2 {
    font-size: 12px;
    font-weight: 600;
    color: var(--dim);
    text-transform: uppercase;
    letter-spacing: 0.12em;
  }
  .count {
    color: var(--dim);
    font-size: 11px;
  }

  /* ── Table ── */
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  th {
    text-align: left;
    padding: 6px 12px;
    color: var(--dim);
    font-weight: 500;
    text-transform: uppercase;
    font-size: 10px;
    letter-spacing: 0.1em;
    border-bottom: 1px solid var(--border);
  }
  td {
    padding: 7px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    color: var(--text);
  }
  tr:hover td { background: var(--surface); }
  tr:last-child td { border-bottom: none; }

  .token-id {
    font-family: var(--mono);
    color: var(--bright);
    font-size: 11px;
  }
  .test-badge {
    background: #333;
    color: #888;
    border-radius: 3px;
    padding: 1px 5px;
    font-size: 10px;
    margin-left: 4px;
  }
  .ip { color: #7db5e8; }
  .ua { color: var(--dim); font-size: 11px; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .method { color: #e8a84f; font-weight: 600; }
  .ts-cell { color: var(--dim); white-space: nowrap; }
  .canary-type { color: var(--bright); }
  .label { color: var(--dim); font-size: 11px; }
  .empty { color: var(--dim); padding: 20px 12px; font-style: italic; }
</style>
</head>
<body>

<header>
  <span class="status-dot"></span>
  <h1><span>snare</span> — self-hosted</h1>
  <span class="badge">LIVE</span>
  <span class="ts">auto-refresh every 10s &nbsp;·&nbsp; {{.GeneratedAt}}</span>
</header>

<main>

  <!-- Recent Alerts -->
  <div class="section">
    <div class="section-header">
      <h2>🪤 Recent alerts</h2>
      <span class="count">({{len .Events}} shown)</span>
    </div>
    {{if .Events}}
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Token</th>
          <th>Type</th>
          <th>IP</th>
          <th>Method</th>
          <th>User-Agent</th>
        </tr>
      </thead>
      <tbody>
        {{range .Events}}
        <tr>
          <td class="ts-cell">{{fmtTime .Timestamp}}</td>
          <td>
            <span class="token-id">{{shortToken .TokenID}}</span>
            {{if .IsTest}}<span class="test-badge">TEST</span>{{end}}
          </td>
          <td class="canary-type">
            {{canaryEmoji .CanaryType}} {{canaryName .CanaryType}}
            {{if .Label}}<br><span class="label">{{.Label}}</span>{{end}}
          </td>
          <td class="ip">{{or .IP "—"}}</td>
          <td class="method">{{or .Method "—"}}</td>
          <td class="ua">{{shortUA .UserAgent}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{else}}
    <p class="empty">No alerts yet. Canaries are armed and watching.</p>
    {{end}}
  </div>

  <!-- Devices -->
  <div class="section">
    <div class="section-header">
      <h2>📡 Registered devices</h2>
      <span class="count">({{len .Devices}})</span>
    </div>
    {{if .Devices}}
    <table>
      <thead>
        <tr>
          <th>Device ID</th>
          <th>Registered</th>
          <th>Tokens</th>
        </tr>
      </thead>
      <tbody>
        {{range .Devices}}
        <tr>
          <td class="token-id">{{.DeviceID}}</td>
          <td class="ts-cell">{{fmtTime .CreatedAt}}</td>
          <td>{{.TokenCount}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{else}}
    <p class="empty">No devices registered. Run <code>snare arm --webhook ...</code> pointing at this server.</p>
    {{end}}
  </div>

</main>
</body>
</html>
`))

type dashboardData struct {
	Events      []dashEvent
	Devices     []deviceRow
	GeneratedAt string
}

type dashEvent struct {
	ID         int64
	TokenID    string
	CanaryType string
	Label      string
	IsTest     bool
	Timestamp  string
	IP         string
	UserAgent  string
	Method     string
}

// handleDashboard renders the full dashboard HTML page.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	events, err := s.db.recentEvents(50)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	devices, err := s.db.listDevices()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// Enrich events with registration metadata (cached inline)
	cache := map[string]*tokenReg{}
	dashEvents := make([]dashEvent, len(events))
	for i, e := range events {
		reg := cache[e.TokenID]
		if reg == nil {
			reg, _ = s.db.getToken(e.TokenID)
			cache[e.TokenID] = reg
		}
		de := dashEvent{
			ID:        e.ID,
			TokenID:   e.TokenID,
			IsTest:    e.IsTest,
			Timestamp: e.Timestamp,
			IP:        e.IP,
			UserAgent: e.UserAgent,
			Method:    e.Method,
		}
		if reg != nil {
			de.CanaryType = reg.CanaryType
			de.Label = reg.Label
		}
		dashEvents[i] = de
	}

	data := dashboardData{
		Events:      dashEvents,
		Devices:     devices,
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTmpl.Execute(w, data); err != nil {
		// Template error after headers are sent — log only.
		_ = err
	}
}
