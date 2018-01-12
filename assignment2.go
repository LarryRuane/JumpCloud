package main

// First JumpCloud programming assignment.
//
// Print the Base64 encoding of the hash of the given password.

import (
	"github.com/LarryRuane/JumpCloud/hash"
)

func main() {
    // normally you would only call this from a test-main
    hash.Test()

    // this never returns
    hash.HttpHashEncode()
}
