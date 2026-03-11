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

func mustRandInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand failure: %v", err))
	}
	return int(n.Int64())
}
