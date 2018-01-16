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
	"os"
	"strings"
	"sync"
	"time"
)

// Return the Base64 encoding of the hash of the given password.
func HashEncode(pw string) string {
	h := sha512.Sum512([]byte(pw))
	return base64.StdEncoding.EncodeToString(h[:])
}

// Start an HTTP server ait for an HTTP request to hash a password (reply with the base64
// encoding of the password)
func HttpHashEncode(port int, id bool) {
	var (
		shutdownPending bool
		running         sync.WaitGroup
	)

	// keep wait group count artificially incremented until a shutdown
    // request is received
	running.Add(1)

	// shutdown monitor
	go func() {
		running.Wait()
		// all requests have been processed, and a shutdown has been requested
		os.Exit(0)
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if shutdownPending {
			return
		}

		switch r.URL.Path {
		case "/hash":
			running.Add(1)

			// simulate this request taking some time to process...
			time.Sleep(5 * time.Second)

			// read the body from this hash request and process it
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				break
			}
			pw, success := extractPassword(string(body))
			if success {
				fmt.Fprintf(w, HashEncode(pw))
			}
			running.Done()

		case "/shutdown":
			shutdownPending = true
			// additional Done to allow the shutdown monitor to call Exit()
			running.Done()
		}
	})

    url := fmt.Sprintf("localhost:%d", port)
	log.Fatal(http.ListenAndServe(url, nil))
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
	const key = "&password="

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
