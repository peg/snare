package main

import (
	"os"

	"github.com/peg/snare/internal/cli"
)

// version is set at build time via -ldflags="-X main.version=v0.1.0"
var version = "dev"

func main() {
	cli.Run(os.Args[1:], version)
}
