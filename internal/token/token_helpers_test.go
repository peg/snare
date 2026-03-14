package token

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestNewProfileName(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		pattern *regexp.Regexp
	}{
		{
			name:    "with label",
			label:   "agent01",
			pattern: regexp.MustCompile(`^agent01-(us-east-1|us-west-2|eu-west-1|ap-southeast-1)-(legacy|backup|old|archive|readonly)-\d{4}$`),
		},
		{
			name:    "without label",
			label:   "",
			pattern: regexp.MustCompile(`^(us-east-1|us-west-2|eu-west-1|ap-southeast-1)-(legacy|backup|old|archive|readonly)-\d{4}$`),
		},
	}

	currentYear := time.Now().Year()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := NewProfileName(tt.label)
			if !tt.pattern.MatchString(profile) {
				t.Fatalf("NewProfileName(%q) = %q, pattern mismatch", tt.label, profile)
			}

			parts := strings.Split(profile, "-")
			yearText := parts[len(parts)-1]
			year := 0
			if _, err := fmt.Sscanf(yearText, "%d", &year); err != nil {
				t.Fatalf("parsing year from %q: %v", profile, err)
			}
			if year < currentYear-3 || year > currentYear-1 {
				t.Fatalf("year = %d, want [%d,%d]", year, currentYear-3, currentYear-1)
			}
		})
	}
}

func TestEncodeBase64Lines(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		lineLen int
		want    string
	}{
		{name: "full 3-byte chunk", data: []byte("Man"), lineLen: 4, want: "TWFu\\n"},
		{name: "two-byte remainder", data: []byte("Ma"), lineLen: 4, want: "TWE=\\n"},
		{name: "one-byte remainder", data: []byte("M"), lineLen: 4, want: "TQ==\\n"},
		{name: "wraps long output", data: []byte("foobar"), lineLen: 4, want: "Zm9v\\nYmFy\\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodeBase64Lines(tt.data, tt.lineLen); got != tt.want {
				t.Fatalf("encodeBase64Lines(%q, %d) = %q, want %q", tt.data, tt.lineLen, got, tt.want)
			}
		})
	}
}

func TestBase64URL(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "empty", data: []byte{}, want: ""},
		{name: "single byte dropped", data: []byte{0x61}, want: ""},
		{name: "two bytes dropped", data: []byte{0x61, 0x62}, want: ""},
		{name: "three bytes encoded", data: []byte("foo"), want: "Zm9v"},
		{name: "six bytes encoded", data: []byte("foobar"), want: "Zm9vYmFy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := base64url(tt.data); got != tt.want {
				t.Fatalf("base64url(%q) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}
