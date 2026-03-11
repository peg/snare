// Package token generates cryptographically random canary identifiers
// and realistic-looking fake credential values.
package token

import (
	"crypto/rand"
	"encoding/hex"
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

// NewFakeRSAPrivateKey generates a correctly-formatted RSA-2048 PEM block
// containing invalid key material. It passes structural/format checks
// but will fail during actual cryptographic operations.
// The key is JSON-safe (newlines as \n).
func NewFakeRSAPrivateKey() (string, error) {
	// RSA-2048 DER is ~1190 bytes → ~1588 base64 chars → ~25 lines of 64 chars
	// We generate random bytes of that length — wrong ASN.1 structure but right size.
	raw := make([]byte, 1190)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating fake RSA key: %w", err)
	}

	// Base64-encode and chunk into 64-char lines
	encoded := encodeBase64Lines(raw, 64)

	pem := "-----BEGIN RSA PRIVATE KEY-----\\n" + encoded + "-----END RSA PRIVATE KEY-----\\n"
	return pem, nil
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

func mustRandInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand failure: %v", err))
	}
	return int(n.Int64())
}
