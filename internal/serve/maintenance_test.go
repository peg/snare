package serve

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func maintenanceRequest(s *Server, method, path, body, secret string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func TestRevocationRetainsOwnership(t *testing.T) {
	for _, withHistory := range []bool{false, true} {
		t.Run(fmt.Sprintf("history=%v", withHistory), func(t *testing.T) {
			s := testServer(t)
			a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
			for device, secret := range map[string]string{"dev-a": a, "dev-b": b} {
				if err := s.db.createDevice(device, secret); err != nil {
					t.Fatal(err)
				}
			}
			const token = "owned-history-token"
			registration := func(device string) string {
				return fmt.Sprintf(`{"token_id":%q,"device_id":%q,"webhook_url":"use-global"}`, token, device)
			}
			if rec := maintenanceRequest(s, "POST", "/api/register", registration("dev-a"), a); rec.Code != 200 {
				t.Fatalf("initial claim: %d %s", rec.Code, rec.Body.String())
			}
			if withHistory {
				s.processAlert(token, "192.0.2.1", "test", "GET", "/c/"+token, "2026-09-11T00:00:00Z", false)
			}
			if rec := maintenanceRequest(s, "POST", "/api/revoke", registration("dev-a"), a); rec.Code != 200 {
				t.Fatalf("owner revoke: %d %s", rec.Code, rec.Body.String())
			}
			wantRevoked := 401
			if withHistory {
				wantRevoked = 200
			}
			if rec := maintenanceRequest(s, "GET", "/api/events/"+token, "", a); rec.Code != wantRevoked {
				t.Fatalf("revoked state: %d, want %d", rec.Code, wantRevoked)
			}
			if rec := maintenanceRequest(s, "POST", "/api/register", registration("dev-b"), b); rec.Code != 403 {
				t.Fatalf("new owner claim must fail: %d %s", rec.Code, rec.Body.String())
			}
			if rec := maintenanceRequest(s, "GET", "/api/events/"+token, "", b); rec.Code != 401 {
				t.Fatalf("another device read history: %d %s", rec.Code, rec.Body.String())
			}
			if rec := maintenanceRequest(s, "POST", "/api/revoke", registration("dev-b"), b); rec.Code != 403 {
				t.Fatalf("another device revoked ownership tombstone: %d", rec.Code)
			}
			if rec := maintenanceRequest(s, "POST", "/api/register", registration("dev-a"), a); rec.Code != 200 {
				t.Fatalf("original owner cannot re-register: %d %s", rec.Code, rec.Body.String())
			}
			want := 404
			if withHistory {
				want = 200
			}
			if rec := maintenanceRequest(s, "GET", "/api/events/"+token, "", a); rec.Code != want {
				t.Fatalf("original owner history: %d, want %d", rec.Code, want)
			}
		})
	}
}

func TestConcurrentTokenClaimsHaveOneOwnerAcrossConnections(t *testing.T) {
	s := testServer(t)
	other, err := openDB(s.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer other.close()
	for _, device := range []string{"dev-a", "dev-b"} {
		if err := s.db.createDevice(device, strings.Repeat(device, 16)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 20; i++ {
		token := fmt.Sprintf("racing-token-%03d", i)
		start := make(chan struct{})
		type result struct {
			device string
			err    error
		}
		results := make(chan result, 2)
		for index, db := range []*DB{s.db, other} {
			device := []string{"dev-a", "dev-b"}[index]
			go func() {
				<-start
				results <- result{device, db.upsertToken(tokenReg{TokenID: token, DeviceID: device, WebhookURL: "use-global"})}
			}()
		}
		close(start)
		winner := ""
		for range 2 {
			result := <-results
			if result.err == nil {
				if winner != "" {
					t.Fatal("two owners claimed the same token")
				}
				winner = result.device
			} else if !errors.Is(result.err, errTokenOwned) {
				t.Fatalf("claim failed with an operational error: %v", result.err)
			}
		}
		owner, err := s.db.tokenOwner(token)
		if err != nil || owner == "" || owner != winner {
			t.Fatalf("owner=%q winner=%q err=%v", owner, winner, err)
		}
		reg, err := other.getToken(token)
		if err != nil || reg == nil || reg.DeviceID != winner {
			t.Fatalf("registration differs from winning claim: %+v %v", reg, err)
		}
	}
}

func TestLegacyOwnershipMigrationReservesAmbiguousHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range []string{"dev-a", "dev-b"} {
		if err := db.createDevice(device, strings.Repeat(device, 16)); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []event{
		{TokenID: "legacy-owner", DeviceID: "dev-a"},
		{TokenID: "legacy-ambiguous", DeviceID: "dev-a"},
		{TokenID: "legacy-ambiguous", DeviceID: "dev-b"},
		{TokenID: "legacy-ownerless"},
	} {
		if err := db.insertEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.db.Exec(`DROP TABLE token_owners`); err != nil {
		t.Fatal(err)
	}
	db.close()
	db, err = openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.close()
	for _, token := range []string{"legacy-owner", "legacy-ambiguous", "legacy-ownerless"} {
		if err := db.upsertToken(tokenReg{TokenID: token, DeviceID: "dev-b"}); !errors.Is(err, errTokenOwned) {
			t.Fatalf("legacy token %s can be reassigned: %v", token, err)
		}
	}
	if err := db.upsertToken(tokenReg{TokenID: "legacy-owner", DeviceID: "dev-a"}); err != nil {
		t.Fatalf("known original owner cannot restore registration: %v", err)
	}
}

func TestEventsAreOrderedAndProofFilterPrecedesLimit(t *testing.T) {
	s := testServer(t)
	secret := strings.Repeat("a", 64)
	if err := s.db.createDevice("dev-events", secret); err != nil {
		t.Fatal(err)
	}
	const token = "ordered-proof-token"
	if err := s.db.upsertToken(tokenReg{TokenID: token, DeviceID: "dev-events"}); err != nil {
		t.Fatal(err)
	}
	proofID := strings.Repeat("a", 32)
	s.processAlert(token, "192.0.2.1", "client", "GET", "/c/"+token+"/proof/"+proofID+"/api", "2026-09-11T00:00:00Z", false)
	for i := 0; i < 40; i++ {
		// Equal timestamps exercise the stable insertion-order tiebreaker.
		if err := s.db.insertEvent(event{TokenID: token, DeviceID: "dev-events", Timestamp: "2026-09-11T00:00:00Z"}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := s.db.getEvents(token)
	if err != nil || len(events) != 20 || events[0].ID != 41 || events[19].ID != 22 {
		t.Fatalf("wrong recent event window: %+v %v", events, err)
	}
	rec := maintenanceRequest(s, http.MethodGet, "/api/events/"+token+"?proof_id="+proofID, "", secret)
	var result struct {
		Events []struct {
			ID      string `json:"id"`
			ProofID string `json:"proof_id"`
			IsTest  bool   `json:"is_test"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || len(result.Events) != 1 || result.Events[0].ID != "1" || result.Events[0].ProofID != proofID || result.Events[0].IsTest {
		t.Fatalf("proof was hidden or misclassified: %d %s", rec.Code, rec.Body.String())
	}
	for _, invalid := range []string{"short", strings.Repeat("A", 32), strings.Repeat("a", 33)} {
		if got := callbackProofID(token, "/c/"+token+"/proof/"+invalid); got != "" {
			t.Fatalf("accepted invalid callback proof %q", got)
		}
		if rec := maintenanceRequest(s, http.MethodGet, "/api/events/"+token+"?proof_id="+invalid, "", secret); rec.Code != 400 {
			t.Fatalf("accepted invalid filter %q: %d", invalid, rec.Code)
		}
	}
}
