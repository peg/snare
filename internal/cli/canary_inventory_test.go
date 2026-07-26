package cli

import (
	"testing"

	"github.com/peg/snare/internal/bait"
)

func TestAllCanaryTypesMatchesImplementedInventory(t *testing.T) {
	want := []bait.Type{
		bait.TypeAWSProc,
		bait.TypeSSH,
		bait.TypeK8s,
		bait.TypeGit,
		bait.TypeNPM,
		bait.TypeAWS,
		bait.TypeGCP,
		bait.TypePyPIUpload,
		bait.TypePyPI,
		bait.TypeOpenAI,
		bait.TypeAnthropic,
		bait.TypeMCP,
		bait.TypeHuggingFace,
		bait.TypeTerraform,
		bait.TypeGeneric,
	}

	if len(allCanaryTypes) != len(want) {
		t.Fatalf("allCanaryTypes has %d entries, want %d", len(allCanaryTypes), len(want))
	}
	if len(allSelectEntries) != len(want) {
		t.Fatalf("allSelectEntries has %d entries, want %d", len(allSelectEntries), len(want))
	}

	seen := map[bait.Type]bool{}
	for i, bt := range allCanaryTypes {
		if bt != want[i] {
			t.Fatalf("allCanaryTypes[%d] = %s, want %s", i, bt, want[i])
		}
		if allSelectEntries[i].t != bt {
			t.Fatalf("allSelectEntries[%d] = %s, want %s", i, allSelectEntries[i].t, bt)
		}
		if seen[bt] {
			t.Fatalf("duplicate canary type in allCanaryTypes: %s", bt)
		}
		seen[bt] = true
		if detectionProof[bt] == "" {
			t.Fatalf("supported canary %s has no proof classification", bt)
		}
	}
}

func TestReliabilityDetailsForPrecisionTypes(t *testing.T) {
	for _, bt := range []bait.Type{bait.TypeAWSProc, bait.TypeSSH, bait.TypeK8s, bait.TypeGit, bait.TypeNPM} {
		details := reliabilityDetailsFor(string(bt))
		if details.tier != "precision" {
			t.Fatalf("%s tier = %s, want precision", bt, details.tier)
		}
		if details.marker == "●" {
			t.Fatalf("%s marker should not reuse high-reliability marker", bt)
		}
		if details.description == "" {
			t.Fatalf("%s description is empty", bt)
		}
	}
}

func TestRetiredCanariesRemainKnownButUnsupported(t *testing.T) {
	for _, bt := range []bait.Type{bait.TypeAzure, bait.TypeDocker, bait.TypeGitHub, bait.TypeStripe} {
		if !isKnownCanaryType(string(bt)) {
			t.Errorf("retired type %s must remain recognizable for status and teardown", bt)
		}
		if isSupportedCanaryType(bt) {
			t.Errorf("retired type %s must not be plantable", bt)
		}
		if retiredCanaryTypes[bt] == "" {
			t.Errorf("retired type %s is missing an explanation", bt)
		}
	}
}

func TestNormalizeAutoLabel(t *testing.T) {
	for input, want := range map[string]string{
		"Agent_01.local": "agent-01-local",
		"--BUILD HOST--": "build-host",
		"":               "snare",
	} {
		if got := normalizeAutoLabel(input); got != want {
			t.Errorf("normalizeAutoLabel(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestReliabilityDemotionsAndNoisyTier(t *testing.T) {
	if got := reliability(string(bait.TypeAzure)); got != "medium" {
		t.Fatalf("azure reliability = %s, want medium", got)
	}
	if got := reliability(string(bait.TypeDocker)); got != "medium" {
		t.Fatalf("docker reliability = %s, want medium", got)
	}
	if got := reliability(string(bait.TypePyPI)); got != "high-noisy" {
		t.Fatalf("pypi reliability = %s, want high-noisy", got)
	}
	details := reliabilityDetailsFor(string(bait.TypePyPI))
	if details.marker != "▲" || details.description == "" {
		t.Fatalf("unexpected pypi reliability details: %+v", details)
	}
}
