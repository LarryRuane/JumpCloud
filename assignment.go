package main

// JumpCloud programming assignment.

import (
	"flag"
	"github.com/LarryRuane/JumpCloud/hash"
    "os"
    "fmt"
)

func main() {
	// normally you would only call this from a test-main
	hash.Test()
	port := flag.Int("port", 0, "a nonzero integer")
    id := flag.Bool("id", false, "boolean, use ID protocol")

    flag.Parse()
	if *port > 0 {
		// this never returns
		hash.HttpHashEncode(*port, *id)
	}

    // command-line arguments
	if len(os.Args) < 2 {
		fmt.Println("usage:", os.Args[0], "[-port N (to start HTTP server)] | passwordToHash [...]")
		os.Exit(1)
	}
    for _, pw := range os.Args[1:] {
	    fmt.Println(hash.HashEncode(pw))
    }
}
