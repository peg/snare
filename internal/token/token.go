// Package token generates cryptographically random canary identifiers
// and realistic-looking fake credential values.
package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	// MinTokenLen is the minimum acceptable canary token length.
	// Short tokens are enumerable — 32 chars gives 256 bits of entropy.
	MinTokenLen = 32
)

// NewID generates a cryptographically random canary token ID.
// Format: <label>-<hex> e.g. "openclaw-aws-a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5"
func NewID(label string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating token ID: %w", err)
	}
	id := hex.EncodeToString(b)
	if label != "" {
		return label + "-" + id, nil
	}
	return id, nil
}

// NewAWSKeyID generates a realistic AWS access key ID.
// Format: AKIA + 16 uppercase alphanumeric chars (matches real AWS key format).
// Does NOT contain "SNARE", "FAKE", "TEST", or any giveaway string.
func NewAWSKeyID() (string, error) {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		b[i] = chars[n.Int64()]
	}
	return "AKIA" + string(b), nil
}

// NewAWSSecretKey generates a realistic AWS secret access key.
// Format: 40 chars of base64url-like characters (matches real AWS secret format).
func NewAWSSecretKey() (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
	b := make([]byte, 40)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		b[i] = chars[n.Int64()]
	}
	return string(b), nil
}

// NewGitHubToken generates a realistic GitHub PAT.
// Format: ghp_ + 36 alphanumeric chars (matches classic PAT format).
func NewGitHubToken() (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 36)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		b[i] = chars[n.Int64()]
	}
	return "ghp_" + string(b), nil
}

// NewStripeKey generates a realistic Stripe secret key.
// Format: sk_live_ + 24 alphanumeric chars.
func NewStripeKey() (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 24)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		b[i] = chars[n.Int64()]
	}
	return "sk_live_" + string(b), nil
}

// NewGCPProjectID generates a realistic GCP project ID.
// Format: <adjective>-<noun>-<digits> e.g. "prod-gateway-382941"
func NewGCPProjectID() string {
	adjectives := []string{"prod", "staging", "internal", "core", "infra", "platform", "backend", "data"}
	nouns := []string{"gateway", "services", "pipeline", "cluster", "registry", "hub", "api", "vault"}

	adj := adjectives[mustRandInt(len(adjectives))]
	noun := nouns[mustRandInt(len(nouns))]
	digits := fmt.Sprintf("%06d", mustRandInt(999999))
	return adj + "-" + noun + "-" + digits
}

// NewGCPClientID generates a realistic GCP client ID (numeric string).
func NewGCPClientID() string {
	return fmt.Sprintf("%d", 100000000000+mustRandInt(899999999999))
}

// NewProfileName generates a convincing AWS credential profile name.
func NewProfileName(label string) string {
	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}
	suffixes := []string{"legacy", "backup", "old", "archive", "readonly"}
	year := time.Now().Year() - mustRandInt(3) - 1 // 1-3 years old

	region := regions[mustRandInt(len(regions))]
	suffix := suffixes[mustRandInt(len(suffixes))]

	parts := []string{}
	if label != "" {
		parts = append(parts, label)
	}
	parts = append(parts, region, suffix, fmt.Sprintf("%d", year))
	return strings.Join(parts, "-")
}

// NewGCPPrivateKeyID generates a realistic GCP private key ID (hex string).
func NewGCPPrivateKeyID() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NewOpenAIKey generates a realistic OpenAI API key.
// Format: sk-proj- + 48 alphanumeric chars (matches current OpenAI key format).
func NewOpenAIKey() (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 48)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		b[i] = chars[n.Int64()]
	}
	return "sk-proj-" + string(b), nil
}

// NewAnthropicKey generates a realistic Anthropic API key.
// Format: sk-ant-api03- + 48 alphanumeric chars.
func NewAnthropicKey() (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	b := make([]byte, 48)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		b[i] = chars[n.Int64()]
	}
	return "sk-ant-api03-" + string(b), nil
}

// NewFakeRSAPrivateKey generates a fully valid RSA-2048 PEM key for use as a
// GCP canary. The key is generated fresh each time — it's a throwaway canary
// credential with no real value. It passes all library validation, allowing
// JWT construction and the token_uri call to proceed.
// The key is JSON-safe (newlines as \n).
func NewFakeRSAPrivateKey() (string, error) {
	// Generate a real RSA-2048 key — this is a disposable canary key,
	// not protecting any real data. The private key never leaves the machine.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("generating RSA key: %w", err)
	}

	der := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	})
	// Convert to JSON-safe form: replace literal newlines with \n
	jsonSafe := strings.ReplaceAll(string(pemBlock), "\n", "\\n")
	// Remove trailing \\n to match GCP format
	jsonSafe = strings.TrimSuffix(jsonSafe, "\\n") + "\\n"
	return jsonSafe, nil
}

func encodeBase64Lines(data []byte, lineLen int) string {
	const b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// Standard base64 encode
	encoded := make([]byte, (len(data)+2)/3*4)
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	_ = b64chars
	di, si := 0, 0
	n := (len(data) / 3) * 3
	for si < n {
		val := uint(data[si+0])<<16 | uint(data[si+1])<<8 | uint(data[si+2])
		encoded[di+0] = enc[val>>18&0x3F]
		encoded[di+1] = enc[val>>12&0x3F]
		encoded[di+2] = enc[val>>6&0x3F]
		encoded[di+3] = enc[val>>0&0x3F]
		si += 3
		di += 4
	}
	rem := len(data) - si
	if rem == 2 {
		val := uint(data[si+0])<<16 | uint(data[si+1])<<8
		encoded[di+0] = enc[val>>18&0x3F]
		encoded[di+1] = enc[val>>12&0x3F]
		encoded[di+2] = enc[val>>6&0x3F]
		encoded[di+3] = '='
	} else if rem == 1 {
		val := uint(data[si+0]) << 16
		encoded[di+0] = enc[val>>18&0x3F]
		encoded[di+1] = enc[val>>12&0x3F]
		encoded[di+2] = '='
		encoded[di+3] = '='
	}

	// Chunk into lines
	var result strings.Builder
	for i := 0; i < len(encoded); i += lineLen {
		end := i + lineLen
		if end > len(encoded) {
			end = len(encoded)
		}
		result.Write(encoded[i:end])
		result.WriteString("\\n")
	}
	return result.String()
}

// NewK8sToken generates a realistic-looking Kubernetes service account token.
// Format: eyJhbGciOiJ... (JWT-like, base64url header.payload.signature)
// Not a valid JWT — just looks like one to pass visual inspection.
func NewK8sToken() (string, error) {
	// JWT header (always the same for k8s SA tokens)
	header := "eyJhbGciOiJSUzI1NiIsImtpZCI6IkNnY3cifQ"
	// Random payload (64 bytes → ~86 base64url chars)
	payload := make([]byte, 64)
	if _, err := rand.Read(payload); err != nil {
		return "", err
	}
	// Random signature (128 bytes → ~172 base64url chars)
	sig := make([]byte, 128)
	if _, err := rand.Read(sig); err != nil {
		return "", err
	}
	return header + "." + base64url(payload) + "." + base64url(sig), nil
}

// NewNPMToken generates a realistic npm auth token.
// Format: npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (36 hex chars)
func NewNPMToken() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "npm_" + hex.EncodeToString(b), nil
}

func base64url(data []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var result strings.Builder
	for i := 0; i < len(data)-2; i += 3 {
		val := uint(data[i])<<16 | uint(data[i+1])<<8 | uint(data[i+2])
		result.WriteByte(enc[val>>18&0x3F])
		result.WriteByte(enc[val>>12&0x3F])
		result.WriteByte(enc[val>>6&0x3F])
		result.WriteByte(enc[val>>0&0x3F])
	}
	return result.String()
}

// MustRandInt returns a random int in [0, max). Exported for use by CLI.
func MustRandInt(max int) int {
	return mustRandInt(max)
}

func mustRandInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand failure: %v", err))
	}
	return int(n.Int64())
}
