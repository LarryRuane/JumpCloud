package hash

// JumpCloud assignment: password hashing and encoding
// (this is for steps 1-2, more to do)

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

// Return the Base64 encoding of the hash of the given password.
func HashEncode(pw string) string {
	h := sha512.Sum512([]byte(pw))
	return base64.StdEncoding.EncodeToString(h[:])
}

func HttpHashEncode() {
	http.HandleFunc("/", handler) // each request calls handler
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}

// We have a request to process, write the hash of the password
func handler(w http.ResponseWriter, r *http.Request) {
	// simulate this request taking some time to process...
	time.Sleep(5 * time.Second)

	switch r.URL.Path {
	case "/hash":
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			break
		}
		pw, success := extractPassword(string(body))
		if success {
			fmt.Fprintf(w, HashEncode(pw))
		}
	}
}

// Look for a password in the given body; if found, return it and true
// else return false (unsuccessful).
//
// Body is of the form "foo=bar&password=angryMonkey&what=ever";
// in this case return "angryMonkey" and true.
func extractPassword(body string) (string, bool) {
	// adding these &s makes searching easier
	body = "&" + body + "&"

	// the string we're looking for
	key := "&password="

	start := strings.Index(body, key)
	if start == -1 {
		// no password given
		return "", false
	}
	// start of the password (e.g. "angryMonkey")
	pw := body[start+len(key):]
	end := strings.Index(pw, "&")
	if end == -1 {
		// this shouldn't be possible since we appended a &
		log.Fatalf("can't find trailing &: %s", body)
	}
	// just the password itself (there may be other stuff following)
	return pw[:end], true
}

// **** test code ****
// Extracting the password is a bit complex, so let's have some tests!
func testExtractPassword(body string, expectedPw string, expectedSuccess bool) {
	pw, success := extractPassword(body)
	if success != expectedSuccess {
		log.Fatalf("unit test failure: input: %s, expectedSuccess: %t, result: %t",
			body, expectedSuccess, success)
	}
	if success && pw != expectedPw {
		log.Fatalf("unit test failure: input: %s, expected: %s, result: %s",
			body, expectedPw, pw)
	}
}

func Test() {
	// arguments are:
	// html body, expected extracted password, whether the password was found
	testExtractPassword("password=mypw", "mypw", true)
	testExtractPassword("passwor=mypw", "dontcare", false)
	testExtractPassword("Password=mypw", "mypw", false)
	testExtractPassword("password=mypw&", "mypw", true)
	testExtractPassword("&password=mypw", "mypw", true)
	testExtractPassword("foo=bar&password=mypw", "mypw", true)
	testExtractPassword("password=mypw&foo=bar", "mypw", true)
	testExtractPassword("foo=bar&password=mypw&another=xx", "mypw", true)
	testExtractPassword("passwordX=not&password=mypw&foo=bar", "mypw", true)
	testExtractPassword("password =not&password=mypw&foo=bar", "mypw", true)
	testExtractPassword("password=mypw&password=bar", "mypw", true) // first found
}
