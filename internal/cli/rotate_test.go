package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/peg/snare/internal/config"
)

func TestRotateDeviceSecretOnServerUsesOldSecret(t *testing.T) {
	const (
		oldSecret = "oldsecret000000000000000000000001"
		newSecret = "newsecret000000000000000000000001"
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/rotate" {
			t.Fatalf("path = %s, want /api/rotate", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+oldSecret {
			t.Fatalf("Authorization = %q, want old secret", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body["new_secret"] != newSecret {
			t.Fatalf("new_secret = %q, want %q", body["new_secret"], newSecret)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"rotated"}`))
	}))
	defer srv.Close()

	cfg := &config.Config{
		DeviceID:     "dev-rotate-test",
		DeviceSecret: newSecret,
		CallbackBase: srv.URL + "/c",
	}

	resp, err := rotateDeviceSecretOnServer(cfg, oldSecret, newSecret)
	if err != nil {
		t.Fatalf("rotateDeviceSecretOnServer: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
