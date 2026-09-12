package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peg/snare/internal/config"
	"github.com/peg/snare/internal/manifest"
)

func newProofID() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate proof identifier: %w", err)
	}
	return hex.EncodeToString(nonce[:]), nil
}

// prepareCorrelatedProof verifies the planted snippet before copying it. Only
// the callback path changes; original files and ordinary callback traffic are
// untouched. A copy avoids temporarily modifying live credential files.
func prepareCorrelatedProof(cfg *config.Config, recipe proofRecipe) (proofRecipe, string, func(), error) {
	canary := recipe.Canary
	data, err := os.ReadFile(canary.Path)
	if err != nil {
		return proofRecipe{}, "", nil, fmt.Errorf("read planted file: %w", err)
	}
	if canary.Content == "" || (canary.ContentHash != "" && manifest.HashContent(canary.Content) != canary.ContentHash) {
		return proofRecipe{}, "", nil, fmt.Errorf("manifest content is missing or does not match its hash")
	}
	if !strings.Contains(string(data), canary.Content) || (canary.Mode == manifest.ModeNewFile && string(data) != canary.Content) {
		return proofRecipe{}, "", nil, fmt.Errorf("planted content changed or is missing; inspect `snare scan` before proving")
	}
	callbackURL := cfg.CallbackURL(canary.ID)
	if canary.CallbackURL != "" {
		callbackURL = canary.CallbackURL
	}
	if !strings.Contains(canary.Content, callbackURL) {
		return proofRecipe{}, "", nil, fmt.Errorf("callback URL is not present in planted content")
	}
	proofID, err := newProofID()
	if err != nil {
		return proofRecipe{}, "", nil, err
	}
	dir, err := os.MkdirTemp("", "snare-proof-")
	if err != nil {
		return proofRecipe{}, "", nil, fmt.Errorf("create proof directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	canary.Path = filepath.Join(dir, "config")
	canary.Content = strings.ReplaceAll(canary.Content, callbackURL, callbackURL+"/proof/"+proofID)
	if err := os.WriteFile(canary.Path, []byte(canary.Content), 0600); err != nil {
		cleanup()
		return proofRecipe{}, "", nil, fmt.Errorf("write proof config: %w", err)
	}
	correlated, err := buildProofRecipe(canary)
	if err != nil {
		cleanup()
		return proofRecipe{}, "", nil, err
	}
	return correlated, proofID, cleanup, nil
}

func waitForProofEvent(cfg *config.Config, tokenID, proofID string, testOnly bool, timeout time.Duration) (apiEvent, error) {
	if proofID == "" {
		return apiEvent{}, fmt.Errorf("missing proof identifier")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		probe := probeTokenProofEvents(cfg, tokenID, proofID)
		if probe.AuthFailed {
			return apiEvent{}, fmt.Errorf("events API auth failed")
		}
		if probe.OwnedReadable {
			for _, event := range probe.Events {
				// Also check locally: an old server may ignore the query filter.
				if event.ProofID == proofID && event.ID != "" && event.IsTest == testOnly {
					return event, nil
				}
			}
		}
		time.Sleep(min(300*time.Millisecond, time.Until(deadline)))
	}
	return apiEvent{}, fmt.Errorf("no matching proof callback observed within %s; receiver must support proof_id and event.id", timeout.Round(time.Second))
}
