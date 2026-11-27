package cli_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/peg/snare/internal/manifest"
)

func eventsCommandHome(t *testing.T, base string, tokens ...string) string {
	t.Helper()
	home := t.TempDir()
	writeTestConfig(t, home, base+"/c", "dev-events-test", strings.Repeat("a", 64), "")
	m := manifest.Manifest{Version: 2, DeviceID: "dev-events-test"}
	for _, token := range tokens {
		m.Canaries = append(m.Canaries, manifest.Canary{ID: token, Type: "aws", Label: "test placement", Active: true, PlantedAt: time.Now()})
	}
	writeTestManifest(t, home, m)
	return home
}

func TestCmdEventsFailuresNeverReportEmpty(t *testing.T) {
	snareBinary(t)
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"unavailable", 503, `{"error":"DO_NOT_PRINT_RAW_SERVER_ERROR"}`, "HTTP 503"},
		{"rate_limited", 429, `{"error":"rate limited"}`, "HTTP 429"},
		{"unexpected_success_status", 202, `{"events":[]}`, "HTTP 202"},
		{"malformed_json", 200, `{"events":`, "invalid events response"},
		{"missing_events", 200, `{"error":"unavailable"}`, "invalid events response"},
		{"wrong_events_type", 200, `{"events":{}}`, "invalid events response"},
		{"null_event", 200, `{"events":[null]}`, "invalid events response"},
		{"oversized_response", 200, strings.Repeat("x", 1024*1024+1), "exceeds size limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			home := eventsCommandHome(t, srv.URL, "eventstok001")
			for _, args := range [][]string{{"events"}, {"events", "--summary"}} {
				stdout, stderr, code := runSnareWithEnv(t, home, nil, args...)
				if code == 0 || !strings.Contains(stderr, tc.want) || !strings.Contains(stderr, "Event results incomplete") {
					t.Fatalf("failure was not visible: code=%d stdout=%q stderr=%q", code, stdout, stderr)
				}
				if strings.Contains(stdout, "No real") || strings.Contains(stderr, "DO_NOT_PRINT_RAW_SERVER_ERROR") {
					t.Fatalf("failure misrepresented or raw body printed: stdout=%q stderr=%q", stdout, stderr)
				}
			}
		})
	}
}

func TestCmdEventsTransportAndIncompleteBody(t *testing.T) {
	snareBinary(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = io.WriteString(w, `{"events":[]}`)
	}))
	home := eventsCommandHome(t, srv.URL, "eventstok001")
	stdout, stderr, code := runSnareWithEnv(t, home, nil, "events")
	if code == 0 || !strings.Contains(stderr, "could not read events response") || strings.Contains(stdout, "No real") {
		t.Fatalf("truncated body looked empty: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	srv.Close()
	stdout, stderr, code = runSnareWithEnv(t, home, nil, "events")
	if code == 0 || !strings.Contains(stderr, "Event results incomplete") || strings.Contains(stdout, "No real") {
		t.Fatalf("transport failure looked empty: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCmdEventsActualEmptyRemainsCompatible(t *testing.T) {
	snareBinary(t)
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"empty_array", 200, `{"events":[]}`},
		{"legacy_null_slice", 200, `{"events":null}`},
		{"legacy_not_found", 404, `{"error":"not found"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			home := eventsCommandHome(t, srv.URL, "eventstok001")
			stdout, stderr, code := runSnareWithEnv(t, home, nil, "events")
			if code != 0 || stderr != "" || !strings.Contains(stdout, "No real events recorded yet") {
				t.Fatalf("empty history regression: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestCmdEventsPartialReadKeepsEvidenceAndReportsFailure(t *testing.T) {
	snareBinary(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "eventstok002") {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
			return
		}
		_, _ = io.WriteString(w, `{"events":[{"timestamp":"2026-09-11T12:00:00Z","ip":"192.0.2.10","userAgent":"legacy-client","method":"GET"}]}`)
	}))
	defer srv.Close()
	home := eventsCommandHome(t, srv.URL, "eventstok001", "eventstok002")
	stdout, stderr, code := runSnareWithEnv(t, home, nil, "events")
	if code == 0 || !strings.Contains(stdout, "legacy-client") || !strings.Contains(stderr, "read 1 of 2 canaries") || strings.Contains(stdout, "No real") {
		t.Fatalf("partial results incorrect: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	stdout, stderr, code = runSnareWithEnv(t, home, nil, "events", "--summary")
	if code == 0 || !strings.Contains(stdout, "Partial event summary") || !strings.Contains(stderr, "HTTP 503") {
		t.Fatalf("partial summary incorrect: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCmdEventsDisplaysSuppressionAndDeliveryFailures(t *testing.T) {
	snareBinary(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"events":[
			{"timestamp":"2026-09-11T12:00:01Z","classification":"activity","asnOrg":"Amazon AWS","deliveries":[{"state":"failed","attempts":5,"error_code":"http_503"},{"state":"pending","attempts":0,"error_code":null}]},
			{"timestamp":"2026-09-11T12:00:00Z","classification":"preview","notification_suppressed":"preview","deliveries":[]}
		]}`)
	}))
	defer srv.Close()
	home := eventsCommandHome(t, srv.URL, "eventstok001")
	stdout, stderr, code := runSnareWithEnv(t, home, nil, "events")
	if code != 0 || stderr != "" {
		t.Fatalf("events failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, want := range []string{"Classification: activity", "Classification: preview", "Notification suppressed: preview", "Delivery: failed (attempts: 5; error: http_503)", "Delivery: pending (attempts: 0)"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q in %q", want, stdout)
		}
	}
	stdout, stderr, code = runSnareWithEnv(t, home, nil, "events", "--summary")
	if code != 0 || stderr != "" || strings.Contains(stdout, "Likely AI agent") {
		t.Fatalf("summary incorrect: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, want := range []string{"Cloud infrastructure:  1 of 2 events", "Notification suppressed: 1 events", "Deliveries failed: 1", "Deliveries pending: 1"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q in %q", want, stdout)
		}
	}
}
