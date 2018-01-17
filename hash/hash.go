package hash

// JumpCloud assignment: password hashing and encoding

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Start an HTTP server, wait for an HTTP request to hash a password (reply with id)
// or, given an id, reply with the hash of a previously hashed and encoded password
func HttpHashEncode(port int) {
	var (
		shutdownPending bool
		running         sync.WaitGroup
		mu              sync.RWMutex
	)

	// translates a saved password to its id (protected by mu)
	passwordToId := make(map[string]int)

	// translates an id to a previously-calculated hashed-encoded password;
	// ids start at 1, so that id maps to idToHash[0]
	// (protected by mu)
	idToHash := make([]string, 0)

	// keep wait group count artificially incremented until a shutdown
	// request is received
	running.Add(1)

	// shutdown monitor
	go func() {
		running.Wait()
		// a shutdown request has been received, and no requests are active
		os.Exit(0)
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if shutdownPending {
			return
		}

		switch {
		case strings.Index(r.URL.Path, "/hash/") == 0:
			// look up the previously hashed password given by id
			h := "" // if not found, return empty string
			id, err := strconv.Atoi(r.URL.Path[len("/hash/"):])
			if err == nil && id > 0 {
				mu.RLock()
				if id <= len(idToHash) {
					h = idToHash[id-1]
				}
				mu.RUnlock()
			}
			fmt.Fprintf(w, "%s", h)
			break

		case r.URL.Path == "/hash":
			// return the id of the hash of this password,
			// computing it if necessary
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				break
			}
			pw, success := extractPassword(string(body))
			if !success {
				break
			}
			// return the id if it has already been seen and hashed
			{
				mu.RLock()
				id := passwordToId[pw]
				mu.RUnlock()
				if id > 0 {
					fmt.Fprintf(w, "%d", id)
					break
				}
			}
			// assign a new id (starting at 1), associate it with this password
			mu.Lock()
			id := len(idToHash) + 1
			idToHash = append(idToHash, "")
			passwordToId[pw] = id
			mu.Unlock()

			// simulate time-consuming hashing and encoding
			running.Add(1)
			time.Sleep(5 * time.Second)
			h := sha512.Sum512([]byte(pw))
			he := base64.StdEncoding.EncodeToString(h[:])

			// remember the result (for future lookup requests)
			mu.Lock()
			idToHash[id-1] = he
			mu.Unlock()

			fmt.Fprintf(w, "%d", id)
			running.Done()

		case r.URL.Path == "/shutdown":
			shutdownPending = true
			// remove the extra Add to allow the shutdown monitor to call Exit()
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
