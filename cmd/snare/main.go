package main

import (
	"os"

	"github.com/peg/snare/internal/cli"
)

func main() {
	cli.Run(os.Args[1:])
}
