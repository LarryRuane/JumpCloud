package main

// First JumpCloud programming assignment.
//
// Print the Base64 encoding of the hash of the given password.

import (
	"fmt"
	"github.com/LarryRuane/JumpCloud/hash"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage:", os.Args[0], "passwordToHash")
		os.Exit(1)
	}
	fmt.Println(hash.HashEncode(os.Args[1]))
}
