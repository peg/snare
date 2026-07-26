package token

import (
	"regexp"
	"strings"
	"testing"
)

func TestNewID(t *testing.T) {
	t.Run("format with label", func(t *testing.T) {
		id, err := NewID("myhost")
		if err != nil {
			t.Fatalf("NewID: %v", err)
		}
		if !strings.HasPrefix(id, "myhost-") {
			t.Errorf("expected prefix 'myhost-', got %q", id)
		}
		// Should be label + "-" + 32 hex chars
		parts := strings.SplitN(id, "-", 2)
		if len(parts) != 2 {
			t.Fatalf("expected label-hex format, got %q", id)
		}
		hex := parts[1]
		if len(hex) != 32 {
			t.Errorf("hex portion should be 32 chars, got %d: %q", len(hex), hex)
		}
		if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(hex) {
			t.Errorf("hex portion should be lowercase hex, got %q", hex)
		}
	})

	t.Run("format without label", func(t *testing.T) {
		id, err := NewID("")
		if err != nil {
			t.Fatalf("NewID: %v", err)
		}
		if len(id) != 32 {
			t.Errorf("expected 32 chars, got %d: %q", len(id), id)
		}
		if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) {
			t.Errorf("expected lowercase hex, got %q", id)
		}
	})

	t.Run("uniqueness", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 1000; i++ {
			id, err := NewID("test-unique")
			if err != nil {
				t.Fatalf("NewID: %v", err)
			}
			if seen[id] {
				t.Fatalf("duplicate ID generated: %s", id)
			}
			seen[id] = true
		}
	})

	t.Run("minimum length", func(t *testing.T) {
		id, err := NewID("")
		if err != nil {
			t.Fatalf("NewID: %v", err)
		}
		if len(id) < MinTokenLen {
			t.Errorf("ID length %d is below MinTokenLen %d", len(id), MinTokenLen)
		}
	})
}

func TestNewIDRejectsUnsafeLabels(t *testing.T) {
	for _, label := range []string{
		"UPPERCASE",
		"has spaces",
		"../escape",
		"line\nbreak",
		"section]name",
		"-leading",
		"trailing-",
		strings.Repeat("a", maxLabelLen+1),
	} {
		t.Run(label, func(t *testing.T) {
			if _, err := NewID(label); err == nil {
				t.Fatalf("NewID(%q) unexpectedly accepted an unsafe label", label)
			}
		})
	}
}

func TestNewAWSKeyID(t *testing.T) {
	t.Run("format", func(t *testing.T) {
		key, err := NewAWSKeyID()
		if err != nil {
			t.Fatalf("NewAWSKeyID: %v", err)
		}
		if !strings.HasPrefix(key, "AKIA") {
			t.Errorf("expected prefix 'AKIA', got %q", key)
		}
		if len(key) != 20 {
			t.Errorf("expected 20 chars (AKIA + 16), got %d: %q", len(key), key)
		}
		if !regexp.MustCompile(`^AKIA[A-Z0-9]{16}$`).MatchString(key) {
			t.Errorf("invalid format: %q", key)
		}
	})

	t.Run("no giveaway strings", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			key, err := NewAWSKeyID()
			if err != nil {
				t.Fatalf("NewAWSKeyID: %v", err)
			}
			for _, s := range giveawayStrings {
				if strings.Contains(strings.ToUpper(key[4:]), strings.ToUpper(s)) {
					t.Errorf("giveaway string %q found in key: %s", s, key)
				}
			}
		}
	})

	t.Run("uniqueness", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 1000; i++ {
			key, err := NewAWSKeyID()
			if err != nil {
				t.Fatalf("NewAWSKeyID: %v", err)
			}
			if seen[key] {
				t.Fatalf("duplicate key: %s", key)
			}
			seen[key] = true
		}
	})
}

func TestNewAWSSecretKey(t *testing.T) {
	t.Run("format", func(t *testing.T) {
		key, err := NewAWSSecretKey()
		if err != nil {
			t.Fatalf("NewAWSSecretKey: %v", err)
		}
		if len(key) != 40 {
			t.Errorf("expected 40 chars, got %d: %q", len(key), key)
		}
		if !regexp.MustCompile(`^[a-zA-Z0-9+/]{40}$`).MatchString(key) {
			t.Errorf("invalid charset: %q", key)
		}
	})
}

func TestNewGitHubToken(t *testing.T) {
	t.Run("format", func(t *testing.T) {
		tok, err := NewGitHubToken()
		if err != nil {
			t.Fatalf("NewGitHubToken: %v", err)
		}
		if !strings.HasPrefix(tok, "ghp_") {
			t.Errorf("expected prefix 'ghp_', got %q", tok)
		}
		if len(tok) != 40 { // ghp_ + 36
			t.Errorf("expected 40 chars, got %d: %q", len(tok), tok)
		}
		if !regexp.MustCompile(`^ghp_[a-zA-Z0-9]{36}$`).MatchString(tok) {
			t.Errorf("invalid format: %q", tok)
		}
	})
}

func TestNewStripeKey(t *testing.T) {
	t.Run("format", func(t *testing.T) {
		key, err := NewStripeKey()
		if err != nil {
			t.Fatalf("NewStripeKey: %v", err)
		}
		if !strings.HasPrefix(key, "sk_live_") {
			t.Errorf("expected prefix 'sk_live_', got %q", key)
		}
		if len(key) != 32 { // sk_live_ (8) + 24
			t.Errorf("expected 32 chars, got %d: %q", len(key), key)
		}
	})
}

func TestNewOpenAIKey(t *testing.T) {
	t.Run("format", func(t *testing.T) {
		key, err := NewOpenAIKey()
		if err != nil {
			t.Fatalf("NewOpenAIKey: %v", err)
		}
		if !strings.HasPrefix(key, "sk-proj-") {
			t.Errorf("expected prefix 'sk-proj-', got %q", key)
		}
		if len(key) != 56 { // sk-proj- (8) + 48
			t.Errorf("expected 56 chars, got %d: %q", len(key), key)
		}
		if !regexp.MustCompile(`^sk-proj-[a-zA-Z0-9]{48}$`).MatchString(key) {
			t.Errorf("invalid format: %q", key)
		}
	})
}

func TestNewAnthropicKey(t *testing.T) {
	t.Run("format", func(t *testing.T) {
		key, err := NewAnthropicKey()
		if err != nil {
			t.Fatalf("NewAnthropicKey: %v", err)
		}
		if !strings.HasPrefix(key, "sk-ant-api03-") {
			t.Errorf("expected prefix 'sk-ant-api03-', got %q", key)
		}
		if len(key) != 61 { // sk-ant-api03- (13) + 48
			t.Errorf("expected 61 chars, got %d: %q", len(key), key)
		}
	})
}

func TestNewK8sToken(t *testing.T) {
	t.Run("format", func(t *testing.T) {
		tok, err := NewK8sToken()
		if err != nil {
			t.Fatalf("NewK8sToken: %v", err)
		}
		// Should look like a JWT: header.payload.signature
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			t.Errorf("expected 3 JWT parts, got %d", len(parts))
		}
		// Header should be the fixed k8s SA token header
		if parts[0] != "eyJhbGciOiJSUzI1NiIsImtpZCI6IkNnY3cifQ" {
			t.Errorf("unexpected JWT header: %q", parts[0])
		}
		// Payload and signature should be non-empty
		if len(parts[1]) == 0 || len(parts[2]) == 0 {
			t.Error("payload and signature must be non-empty")
		}
	})
}

func TestNewNPMToken(t *testing.T) {
	t.Run("format", func(t *testing.T) {
		tok, err := NewNPMToken()
		if err != nil {
			t.Fatalf("NewNPMToken: %v", err)
		}
		if !strings.HasPrefix(tok, "npm_") {
			t.Errorf("expected prefix 'npm_', got %q", tok)
		}
		if len(tok) != 40 { // npm_ (4) + 36 hex chars
			t.Errorf("expected 40 chars, got %d: %q", len(tok), tok)
		}
		if !regexp.MustCompile(`^npm_[0-9a-f]{36}$`).MatchString(tok) {
			t.Errorf("invalid format: %q", tok)
		}
	})
}

func TestNewFakeRSAPrivateKey(t *testing.T) {
	t.Run("PEM structure", func(t *testing.T) {
		key, err := NewFakeRSAPrivateKey()
		if err != nil {
			t.Fatalf("NewFakeRSAPrivateKey: %v", err)
		}
		if !strings.HasPrefix(key, "-----BEGIN RSA PRIVATE KEY-----\\n") {
			t.Error("missing PEM header")
		}
		if !strings.HasSuffix(key, "-----END RSA PRIVATE KEY-----\\n") {
			t.Error("missing PEM footer")
		}
		// Should contain base64 content between header and footer
		if len(key) < 100 {
			t.Errorf("key seems too short: %d chars", len(key))
		}
	})

	t.Run("uniqueness", func(t *testing.T) {
		key1, _ := NewFakeRSAPrivateKey()
		key2, _ := NewFakeRSAPrivateKey()
		if key1 == key2 {
			t.Error("two generated keys should not be identical")
		}
	})
}

func TestNewGCPProjectID(t *testing.T) {
	t.Run("format", func(t *testing.T) {
		id := NewGCPProjectID()
		// Format: adjective-noun-digits
		if !regexp.MustCompile(`^[a-z]+-[a-z]+-\d{6}$`).MatchString(id) {
			t.Errorf("unexpected project ID format: %q", id)
		}
	})

	t.Run("uniqueness", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			id := NewGCPProjectID()
			seen[id] = true
		}
		// With random adjective, noun, and 6-digit number, collisions should be rare
		if len(seen) < 50 {
			t.Errorf("too many collisions: only %d unique out of 100", len(seen))
		}
	})
}

func TestNewGCPClientID(t *testing.T) {
	t.Run("format", func(t *testing.T) {
		id := NewGCPClientID()
		if !regexp.MustCompile(`^\d{12}$`).MatchString(id) {
			t.Errorf("expected 12-digit numeric string, got %q", id)
		}
	})
}

func TestNewGCPPrivateKeyID(t *testing.T) {
	t.Run("format", func(t *testing.T) {
		id, err := NewGCPPrivateKeyID()
		if err != nil {
			t.Fatalf("NewGCPPrivateKeyID: %v", err)
		}
		if len(id) != 40 {
			t.Errorf("expected 40 hex chars, got %d: %q", len(id), id)
		}
		if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(id) {
			t.Errorf("expected lowercase hex, got %q", id)
		}
	})
}

func TestNoGiveawayStringsInAnyToken(t *testing.T) {
	// Generate many tokens and ensure no giveaway strings leak through
	generators := map[string]func() (string, error){
		"AWSKeyID":  NewAWSKeyID,
		"AWSSecret": NewAWSSecretKey,
		"GitHub":    NewGitHubToken,
		"Stripe":    NewStripeKey,
		"OpenAI":    NewOpenAIKey,
		"Anthropic": NewAnthropicKey,
		"K8s":       NewK8sToken,
		"NPM":       NewNPMToken,
	}
	for name, gen := range generators {
		for i := 0; i < 50; i++ {
			val, err := gen()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			upper := strings.ToUpper(val)
			for _, s := range giveawayStrings {
				if strings.Contains(upper, strings.ToUpper(s)) {
					t.Errorf("%s generated token containing giveaway %q: %s", name, s, val)
				}
			}
		}
	}
}

func TestMustRandInt(t *testing.T) {
	t.Run("range", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			n := MustRandInt(10)
			if n < 0 || n >= 10 {
				t.Fatalf("MustRandInt(10) = %d, want [0,10)", n)
			}
		}
	})

	t.Run("distribution", func(t *testing.T) {
		// Crude check: all values in [0,5) should appear in 1000 tries
		seen := make(map[int]bool)
		for i := 0; i < 1000; i++ {
			seen[MustRandInt(5)] = true
		}
		if len(seen) != 5 {
			t.Errorf("expected all 5 values to appear, got %d", len(seen))
		}
	})
}
