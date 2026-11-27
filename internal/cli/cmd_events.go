package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/peg/snare/internal/manifest"
)

// isCloudInfrastructureASN identifies hosting providers, not who operated a
// client or whether it was an AI agent.
func isCloudInfrastructureASN(asnOrg string) bool {
	providers := []string{
		"Amazon", "Google", "Microsoft", "Cloudflare",
		"Hetzner", "DigitalOcean", "Linode", "Vultr",
		"OVH", "Oracle", "IBM", "Alibaba",
	}
	lower := strings.ToLower(asnOrg)
	for _, p := range providers {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// cmdEvents fetches recent alert events from snare.sh for active canaries.
func cmdEvents(args []string) {
	// Parse --summary flag
	summary := false
	var rest []string
	for _, a := range args {
		if a == "--summary" {
			summary = true
		} else {
			rest = append(rest, a)
		}
	}
	_ = rest // reserved for future flags

	cfg, err := requireConfig()
	if err != nil {
		fatal(err)
	}

	m, err := manifest.Load()
	if err != nil {
		fatal(err)
	}

	active := m.Active()
	if len(active) == 0 {
		fmt.Println("No active canaries.")
		return
	}

	// Build API base from callback base
	apiBase := strings.TrimSuffix(cfg.CallbackBase, "/c")

	// eventRecord holds a single event with canary context.
	type eventRecord struct {
		Timestamp              string `json:"timestamp"`
		IP                     string `json:"ip"`
		City                   string `json:"city"`
		Country                string `json:"country"`
		AsnOrg                 string `json:"asnOrg"`
		UserAgent              string `json:"userAgent"`
		Method                 string `json:"method"`
		Classification         string `json:"classification"`
		NotificationSuppressed string `json:"notification_suppressed"`
		Deliveries             []struct {
			State     string `json:"state"`
			Attempts  int    `json:"attempts"`
			ErrorCode string `json:"error_code"`
		} `json:"deliveries"`
	}

	type canaryEvents struct {
		ID     string
		Label  string
		Events []eventRecord
	}

	fmt.Printf("Fetching events for %d canary(s)...\n\n", len(active))

	var allCanaries []canaryEvents
	totalEvents := 0
	authFailed := false

	for _, c := range active {
		url := apiBase + "/api/events/" + c.ID
		resp, err := authedGet(url, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", c.ID, err)
			continue
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			fmt.Fprintf(os.Stderr, "  ✗ auth failed — run `snare repair` to re-sync registrations and auth\n")
			authFailed = true
			break
		}

		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			label := c.Label
			if label == "" {
				label = c.Type
			}
			allCanaries = append(allCanaries, canaryEvents{ID: c.ID, Label: label})
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			fmt.Fprintf(os.Stderr, "  ✗ %s: events API returned HTTP %d\n", c.ID, resp.StatusCode)
			continue
		}

		var result struct {
			Events json.RawMessage `json:"events"`
		}

		const maxResponseBytes = 1024 * 1024
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		resp.Body.Close()
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: could not read events response: %v\n", c.ID, readErr)
			continue
		}
		if len(data) > maxResponseBytes {
			fmt.Fprintf(os.Stderr, "  ✗ %s: events response exceeds size limit\n", c.ID)
			continue
		}
		var events []eventRecord
		if err := json.Unmarshal(data, &result); err != nil || len(result.Events) == 0 {
			fmt.Fprintf(os.Stderr, "  ✗ %s: invalid events response\n", c.ID)
			continue
		}
		// Older receivers may encode a nil event slice as null. Missing the
		// events field entirely is an invalid response, not an empty history.
		if err := json.Unmarshal(result.Events, &events); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: invalid events response\n", c.ID)
			continue
		}
		validEvents := true
		for _, event := range events {
			if _, err := time.Parse(time.RFC3339Nano, event.Timestamp); err != nil {
				validEvents = false
				break
			}
			for _, delivery := range event.Deliveries {
				if delivery.State == "" || delivery.Attempts < 0 {
					validEvents = false
				}
			}
		}
		if !validEvents {
			fmt.Fprintf(os.Stderr, "  ✗ %s: invalid events response\n", c.ID)
			continue
		}

		label := c.Label
		if label == "" {
			label = c.Type
		}

		ce := canaryEvents{ID: c.ID, Label: label, Events: events}
		allCanaries = append(allCanaries, ce)
		totalEvents += len(ce.Events)
	}

	if authFailed {
		os.Exit(1)
	}
	incomplete := len(allCanaries) != len(active)
	if incomplete {
		fmt.Fprintf(os.Stderr, "Event results incomplete: read %d of %d canaries; history may be unavailable.\n", len(allCanaries), len(active))
	}

	if summary {
		// Aggregate summary across all canaries
		asnCount := map[string]int{}
		uaCount := map[string]int{}
		cloudHits := 0
		suppressedEvents := 0
		deliveryCounts := map[string]int{}

		for _, ce := range allCanaries {
			for _, e := range ce.Events {
				if e.AsnOrg != "" {
					asnCount[e.AsnOrg]++
				}
				ua := e.UserAgent
				if ua == "" {
					ua = "(unknown)"
				}
				uaCount[ua]++
				if isCloudInfrastructureASN(e.AsnOrg) {
					cloudHits++
				}
				if e.NotificationSuppressed != "" {
					suppressedEvents++
				}
				for _, delivery := range e.Deliveries {
					deliveryCounts[delivery.State]++
				}
			}
		}

		if incomplete {
			fmt.Print("Partial event summary")
		} else {
			fmt.Print("Event summary")
		}
		fmt.Printf(" (last %d events across %d canaries):\n\n", totalEvents, len(allCanaries))

		// ASN distribution — sorted by count desc
		fmt.Println("  ASN distribution:")
		if len(asnCount) == 0 {
			fmt.Println("    (none)")
		} else {
			type kv struct {
				key string
				val int
			}
			var asnList []kv
			for k, v := range asnCount {
				asnList = append(asnList, kv{k, v})
			}
			// sort descending by count, then alphabetically
			for i := 0; i < len(asnList); i++ {
				for j := i + 1; j < len(asnList); j++ {
					if asnList[j].val > asnList[i].val ||
						(asnList[j].val == asnList[i].val && asnList[j].key < asnList[i].key) {
						asnList[i], asnList[j] = asnList[j], asnList[i]
					}
				}
			}
			for _, kv := range asnList {
				fmt.Printf("    %-44s %d\n", kv.key, kv.val)
			}
		}
		fmt.Println()

		// User-Agent breakdown
		fmt.Println("  SDK / User-Agent:")
		if len(uaCount) == 0 {
			fmt.Println("    (none)")
		} else {
			type kv struct {
				key string
				val int
			}
			var uaList []kv
			for k, v := range uaCount {
				uaList = append(uaList, kv{k, v})
			}
			for i := 0; i < len(uaList); i++ {
				for j := i + 1; j < len(uaList); j++ {
					if uaList[j].val > uaList[i].val ||
						(uaList[j].val == uaList[i].val && uaList[j].key < uaList[i].key) {
						uaList[i], uaList[j] = uaList[j], uaList[i]
					}
				}
			}
			for _, kv := range uaList {
				ua := kv.key
				if len(ua) > 60 {
					ua = ua[:60] + "..."
				}
				fmt.Printf("    %-44s %d\n", ua, kv.val)
			}
		}
		fmt.Println()

		fmt.Printf("  Cloud infrastructure:  %d of %d events\n", cloudHits, totalEvents)
		if suppressedEvents > 0 {
			fmt.Printf("  Notification suppressed: %d events\n", suppressedEvents)
		}
		var deliveryStates []string
		for state := range deliveryCounts {
			deliveryStates = append(deliveryStates, state)
		}
		sort.Strings(deliveryStates)
		for _, state := range deliveryStates {
			fmt.Printf("  Deliveries %s: %d\n", state, deliveryCounts[state])
		}
		fmt.Println()

		// Per-canary hit counts
		fmt.Println("  Per canary:")
		for _, ce := range allCanaries {
			hits := len(ce.Events)
			label := ce.Label
			if label == "" {
				label = ce.ID
			}
			display := ce.ID
			if label != ce.ID && label != "" {
				display = ce.ID
			}
			if hits == 0 {
				fmt.Printf("    %-44s 0 hits\n", display)
			} else {
				last := ce.Events[0].Timestamp
				hitWord := "hits"
				if hits == 1 {
					hitWord = "hit"
				}
				fmt.Printf("    %-44s %d %s  (last: %s)\n", display, hits, hitWord, last)
			}
		}
		if totalEvents == 0 && !incomplete {
			fmt.Println()
			fmt.Println("  No real hits yet. That is expected after first arm; canaries wait quietly")
			fmt.Println("  until someone actively uses a fake credential.")
		}
		if incomplete {
			os.Exit(1)
		}
		return
	}

	// Default: per-event detail view
	found := 0
	for _, ce := range allCanaries {
		if len(ce.Events) == 0 {
			continue
		}
		found++
		fmt.Printf("  🪤 %s (%s)\n", ce.ID, ce.Label)
		for _, e := range ce.Events {
			loc := strings.Join(filterEmpty(e.City, e.Country), ", ")
			if loc == "" {
				loc = "unknown location"
			}
			ua := e.UserAgent
			if len(ua) > 80 {
				ua = ua[:80] + "..."
			}
			fmt.Printf("    %s  %s  %s  %s\n", e.Timestamp, e.IP, loc, e.Method)
			fmt.Printf("    UA: %s\n", ua)
			if e.Classification != "" {
				fmt.Printf("    Classification: %s\n", e.Classification)
			}
			if e.NotificationSuppressed != "" {
				fmt.Printf("    Notification suppressed: %s\n", e.NotificationSuppressed)
			}
			for _, delivery := range e.Deliveries {
				fmt.Printf("    Delivery: %s (attempts: %d", delivery.State, delivery.Attempts)
				if delivery.ErrorCode != "" {
					fmt.Printf("; error: %s", delivery.ErrorCode)
				}
				fmt.Println(")")
			}
			fmt.Println()
		}
	}

	if found == 0 && !incomplete {
		fmt.Println("  No real events recorded yet.")
		fmt.Println("  That is expected after first arm; canaries wait quietly until someone")
		fmt.Println("  actively uses a fake credential.")
		fmt.Println("  Run `snare scan` to verify local files or `snare test` to verify delivery.")
	}
	if incomplete {
		os.Exit(1)
	}
}

func filterEmpty(ss ...string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
