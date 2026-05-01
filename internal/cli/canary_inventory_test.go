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
		bait.TypeAWS,
		bait.TypeGCP,
		bait.TypeNPM,
		bait.TypeGit,
		bait.TypePyPI,
		bait.TypeAzure,
		bait.TypeOpenAI,
		bait.TypeAnthropic,
		bait.TypeMCP,
		bait.TypeGitHub,
		bait.TypeStripe,
		bait.TypeHuggingFace,
		bait.TypeDocker,
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
	}
}
