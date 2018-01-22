package main

// JumpCloud programming assignment.

import (
	"flag"
	"github.com/LarryRuane/JumpCloud/hash"
	"log"
)

func main() {
	port := flag.Int("port", 8080, "a nonzero integer")
	flag.Parse()

	//go hash.HttpHashEncode(*port+1)
	err := hash.HttpHashEncode(*port)
	if err != nil {
		log.Fatal(err)
	}
}
