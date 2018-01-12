package hash

// JumpCloud assignment: password hashing and encoding
// (this is only step 1, more to do)

import (
	"crypto/sha512"
	"encoding/base64"
)

// Return the Base64 encoding of the hash of the given password.
func HashEncode(pw string) string {
	h := sha512.Sum512([]byte(pw))
	return base64.StdEncoding.EncodeToString(h[:])
}
