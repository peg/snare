package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/peg/snare/internal/config"
)

// Event correlation for `snare prove`, `doctor --test` and the arm self-test.
//
// The events API returns a capped list, so "the count went up" stops working
// once a token has more stored events than the cap. Correlation instead looks
// for a specific event: one tagged with our proof nonce, or one whose identity
// was not in the list before the trigger ran.

func newProofID() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate proof identifier: %w", err)
	}
	return hex.EncodeToString(nonce[:]), nil
}

// eventIdentity is the receiver's event id, or a best-effort fingerprint for
// receivers that predate event ids.
func eventIdentity(e apiEvent) string {
	if e.ID != "" {
		return "id:" + e.ID
	}
	return "fp:" + e.Timestamp + "|" + e.IP + "|" + e.UserAgent + "|" + e.Path
}

func eventIdentities(events []apiEvent) map[string]bool {
	seen := make(map[string]bool, len(events))
	for _, e := range events {
		seen[eventIdentity(e)] = true
	}
	return seen
}

func matchesProof(e apiEvent, proofID string) bool {
	// Older receivers do not parse proof_id but still record the request path.
	return e.ProofID == proofID || strings.HasSuffix(e.Path, "/proof/"+proofID)
}

// waitForProofEvent waits for the callback carrying proofID.
func waitForProofEvent(cfg *config.Config, tokenID, proofID string, testOnly bool, timeout time.Duration) (apiEvent, error) {
	if proofID == "" {
		return apiEvent{}, fmt.Errorf("missing proof identifier")
	}
	return waitForEvent(cfg, tokenID, proofID, timeout, func(e apiEvent) bool {
		return e.IsTest == testOnly && matchesProof(e, proofID)
	})
}

// waitForNewEvent waits for a non-test event that was not present in before.
// Used when the trigger runs the real planted config and so cannot carry a nonce.
func waitForNewEvent(cfg *config.Config, tokenID string, before []apiEvent, timeout time.Duration) (apiEvent, error) {
	seen := eventIdentities(before)
	return waitForEvent(cfg, tokenID, "", timeout, func(e apiEvent) bool {
		return !e.IsTest && !seen[eventIdentity(e)]
	})
}

func waitForEvent(cfg *config.Config, tokenID, proofID string, timeout time.Duration, match func(apiEvent) bool) (apiEvent, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		probe := probeTokenProofEvents(cfg, tokenID, proofID)
		if probe.AuthFailed {
			return apiEvent{}, fmt.Errorf("events API auth failed")
		}
		if probe.OwnedReadable {
			for _, e := range probe.Events {
				if match(e) {
					return e, nil
				}
			}
		}
		time.Sleep(min(300*time.Millisecond, time.Until(deadline)))
	}
	return apiEvent{}, fmt.Errorf("no new callback observed within %s", timeout.Round(time.Second))
}
