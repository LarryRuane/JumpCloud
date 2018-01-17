package main

// JumpCloud programming assignment.

import (
	"flag"
	"github.com/LarryRuane/JumpCloud/hash"
)

func main() {
	// normally you would only call this from a test-main
	port := flag.Int("port", 8080, "a nonzero integer")
	flag.Parse()

	// this never returns
	hash.HttpHashEncode(*port)
}
