package cli

import (
	"fmt"
)

// Run is the entry point for the snare CLI.
func Run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "init":
		return cmdInit(args[1:])
	case "plant":
		return cmdPlant(args[1:])
	case "status":
		return cmdStatus(args[1:])
	case "test":
		return cmdTest(args[1:])
	case "teardown":
		return cmdTeardown(args[1:])
	case "version":
		fmt.Println("snare dev")
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func printUsage() {
	fmt.Print(`snare — compromise detection for AI agents

Usage:
  snare init          register with snare.sh and generate canary tokens
  snare plant         deploy bait in credential locations
  snare status        show active canaries and last-seen timestamps
  snare test          fire a test alert to verify the pipeline
  snare teardown      remove all planted canaries

Options:
  --dry-run           show what would be planted without writing anything
  --dir <path>        plant project-level canaries in this directory
  --webhook <url>     set or override the alert webhook URL

`)
}

func cmdInit(args []string) error {
	fmt.Println("snare init — not yet implemented")
	return nil
}

func cmdPlant(args []string) error {
	fmt.Println("snare plant — not yet implemented")
	return nil
}

func cmdStatus(args []string) error {
	fmt.Println("snare status — not yet implemented")
	return nil
}

func cmdTest(args []string) error {
	fmt.Println("snare test — not yet implemented")
	return nil
}

func cmdTeardown(args []string) error {
	fmt.Println("snare teardown — not yet implemented")
	return nil
}
