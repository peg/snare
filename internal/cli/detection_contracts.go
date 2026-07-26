package cli

import "github.com/peg/snare/internal/bait"

// proofLevel records the strongest automated evidence Snare has for a
// detection mechanism. Keeping this separate from marketing-oriented
// reliability prevents a rendered template from being mistaken for proof that
// a real client honors it.
type proofLevel string

const (
	proofRealClient  proofLevel = "real-client"
	proofManualProbe proofLevel = "manual-probe"
	proofTemplate    proofLevel = "template-only"
	proofRetired     proofLevel = "retired"
)

var detectionProof = map[bait.Type]proofLevel{
	bait.TypeAWSProc:     proofRealClient,
	bait.TypeSSH:         proofRealClient,
	bait.TypeK8s:         proofRealClient,
	bait.TypeGit:         proofRealClient,
	bait.TypeNPM:         proofRealClient,
	bait.TypeAWS:         proofRealClient,
	bait.TypeGCP:         proofRealClient,
	bait.TypePyPIUpload:  proofTemplate,
	bait.TypePyPI:        proofTemplate,
	bait.TypeOpenAI:      proofTemplate,
	bait.TypeAnthropic:   proofTemplate,
	bait.TypeMCP:         proofManualProbe,
	bait.TypeHuggingFace: proofTemplate,
	bait.TypeTerraform:   proofTemplate,
	bait.TypeGeneric:     proofTemplate,
}

func proofLevelFor(t bait.Type) proofLevel {
	if level := detectionProof[t]; level != "" {
		return level
	}
	if _, retired := retiredCanaryTypes[t]; retired {
		return proofRetired
	}
	return ""
}
