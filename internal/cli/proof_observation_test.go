package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peg/snare/internal/config"
	"github.com/peg/snare/internal/manifest"
)

func TestProofObservationRejectsUnrelatedEvents(t *testing.T) {
	want := strings.Repeat("a", 32)
	for _, candidate := range []apiEvent{
		{ID: "31", ProofID: strings.Repeat("b", 32), Timestamp: time.Now().Format(time.RFC3339)},
		{ID: "32", Timestamp: time.Now().Format(time.RFC3339)},
		{ID: "33", ProofID: want, IsTest: true},
		{ProofID: want},
	} {
		t.Run(fmt.Sprintf("%s-%v", candidate.ID, candidate.IsTest), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Emulate an older server that ignores the requested filter.
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"events": []apiEvent{candidate}})
			}))
			defer srv.Close()
			cfg := &config.Config{CallbackBase: srv.URL + "/c", DeviceID: "dev-test", DeviceSecret: strings.Repeat("a", 64)}
			if _, err := waitForProofEvent(cfg, "proof-token-123", want, false, 20*time.Millisecond); err == nil {
				t.Fatal("unrelated, mismatched-kind, or unidentified event satisfied proof")
			}
		})
	}
}

func TestRepeatedWebhookProofsSurviveFullHistoryAndConcurrentTraffic(t *testing.T) {
	var mu sync.Mutex
	events := make([]apiEvent, 30)
	for i := range events {
		events[i] = apiEvent{ID: fmt.Sprint(i + 1), IsTest: true, Timestamp: "2026-09-11T00:00:00Z"}
	}
	nextID := 31
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/api/register":
			_, _ = w.Write([]byte(`{"status":"registered"}`))
		case strings.HasPrefix(r.URL.Path, "/c/"):
			parts := strings.Split(r.URL.Path, "/")
			if len(parts) != 5 || parts[3] != "proof" || len(parts[4]) != 32 {
				t.Errorf("missing nonce callback path: %s", r.URL.Path)
				w.WriteHeader(400)
				return
			}
			events = append(events, apiEvent{ID: fmt.Sprint(nextID), ProofID: parts[4], IsTest: true, Timestamp: "2026-09-11T01:00:00Z"})
			nextID++
			// More than one full page of unrelated traffic arrives after the proof.
			for range 30 {
				events = append(events, apiEvent{ID: fmt.Sprint(nextID), IsTest: true, Timestamp: "2026-09-11T02:00:00Z"})
				nextID++
			}
		case strings.HasPrefix(r.URL.Path, "/api/events/"):
			proofID := r.URL.Query().Get("proof_id")
			if proofID == "" {
				t.Error("proof observation did not request correlation filter")
			}
			filtered := []apiEvent{}
			for i := len(events) - 1; i >= 0 && len(filtered) < 10; i-- {
				if events[i].ProofID == proofID {
					filtered = append(filtered, events[i])
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"events": filtered})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cfg := &config.Config{CallbackBase: srv.URL + "/c", DeviceID: "dev-test", DeviceSecret: strings.Repeat("a", 64)}
	for range 3 {
		result := runWebhookTest(cfg)
		if result.RegisterErr != nil || result.FireErr != nil || result.ObserveErr != nil || result.ObservedAt != "2026-09-11T01:00:00Z" {
			t.Fatalf("full history hid correlated proof: %+v", result)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	seen := map[string]bool{}
	for _, event := range events {
		if event.ProofID != "" {
			if seen[event.ProofID] {
				t.Fatal("repeated proof reused its nonce")
			}
			seen[event.ProofID] = true
		}
	}
	if len(seen) != 3 {
		t.Fatalf("got %d distinct proofs, want 3", len(seen))
	}
}

func TestPrepareCorrelatedProofVerifiesOriginalAndCleansCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	const callback = "https://snare.example/c/correlated-mcp-token"
	content := `{"mcpServers":{"backup":{"url":"` + callback + `/mcp"}}}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	canary := manifest.Canary{ID: "correlated-mcp-token", Type: "mcp", Path: path, Content: content, ContentHash: manifest.HashContent(content), Mode: manifest.ModeNewFile, CallbackURL: callback}
	recipe, err := buildProofRecipe(canary)
	if err != nil {
		t.Fatal(err)
	}
	correlated, proofID, cleanup, err := prepareCorrelatedProof(&config.Config{}, recipe)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if correlated.Canary.Path == path || len(proofID) != 32 || !strings.Contains(correlated.Command, callback+"/proof/"+proofID+"/mcp") {
		t.Fatalf("incorrect correlated copy: %+v %s", correlated, proofID)
	}
	info, err := os.Stat(correlated.Canary.Path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("insecure proof copy: %v %v", info, err)
	}
	original, err := os.ReadFile(path)
	if err != nil || string(original) != content {
		t.Fatalf("original changed: %s %v", original, err)
	}
	cleanup()
	if _, err := os.Stat(correlated.Canary.Path); !os.IsNotExist(err) {
		t.Fatalf("temporary config remains: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(content, "/mcp", "/different")), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := prepareCorrelatedProof(&config.Config{}, recipe); err == nil {
		t.Fatal("modified original config passed integrity verification")
	}
}
