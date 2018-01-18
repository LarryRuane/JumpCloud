package hash

// JumpCloud assignment: password hashing and encoding

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
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

// Start an HTTP server, wait for an HTTP request to hash a password
// (reply with id), or, given an id, reply with the hash of a previously
// hashed and encoded password
func HttpHashEncode(port int) {
	var (
		shutdownPending bool
		running         sync.WaitGroup
		mu              sync.Mutex
	)

	// translates a saved password to its id (protected by mu)
	passwordToId := make(map[string]int)

	// translates an id to a previously-calculated hashed-encoded password;
	// ids start at 1, so that id maps to idToHash[0]
	// (protected by mu)
	idToHash := make([]string, 0)

	// threads wait on this condition variable when the the hash they
	// need is being generated; each time a new hash is available,
	// all waiters are awakened
	newHash := sync.NewCond(&mu)

	// stats (protected by mu)
	var (
		totalRequests int64
		totalTime     time.Duration
	)

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
			// look up the previously hashed password given by id;
			// if not found or still calculating, return empty string
			h := ""
			id, err := strconv.Atoi(r.URL.Path[len("/hash/"):])
			if err == nil && id > 0 {
				mu.Lock()
				if id <= len(idToHash) {
					for idToHash[id-1] == "" {
						// hash still being computed
						newHash.Wait()
					}
					h = idToHash[id-1]
				}
				mu.Unlock()
			}
			fmt.Fprintf(w, "%s", h)
			break

		case r.URL.Path == "/hash":
			// return the id of the hash of this password,
			// computing it if necessary

			// stats
			defer func(start time.Time) {
				mu.Lock()
				totalTime += time.Since(start)
				totalRequests++
				mu.Unlock()
			}(time.Now())

			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				break
			}
			pw, success := extractPassword(string(body))
			if !success {
				break
			}
			mu.Lock()
			id := passwordToId[pw]
			if id == 0 {
				// we haven't seen this password yet; assign a new id
				// (starting at 1) for it, associate it from this password
				id = len(idToHash) + 1
				idToHash = append(idToHash, "")
				passwordToId[pw] = id

				// do time-consuming hashing and encoding in the background
				go func(id int) {
					// this work also counts toward stats total hash time
					defer func(start time.Time) {
						mu.Lock()
						totalTime += time.Since(start)
						mu.Unlock()
					}(time.Now())

					// keep shutdown from completing until we're done
					running.Add(1)
					defer running.Done()

					// simulate this taking a long time
					time.Sleep(5 * time.Second)
					h := sha512.Sum512([]byte(pw))
					he := base64.StdEncoding.EncodeToString(h[:])

					// remember the result (for future lookup requests)
					mu.Lock()
					idToHash[id-1] = he
					mu.Unlock()
					// wake up any goroutines waiting for a hash
					newHash.Broadcast()
				}(id)
			}
			mu.Unlock()
			fmt.Fprintf(w, "%d", id)

		case r.URL.Path == "/shutdown":
			mu.Lock()
			if !shutdownPending {
				// remove the extra Add so the shutdown monitor can call Exit()
				running.Done()
			}
			shutdownPending = true
			mu.Unlock()
		case r.URL.Path == "/stats":
			type stats struct {
				Total   int64         `json:"total"`
				Average time.Duration `json:"average"`
			}
			// avoid division by zero
			tr := totalRequests
			if tr == 0 {
				tr = 1
			}
			currentStats := stats{
				Total:   totalRequests,
				Average: totalTime / time.Millisecond / time.Duration(tr),
			}
			st, err := json.Marshal(currentStats)
			if err == nil {
				fmt.Fprintf(w, "%s", st)
			}
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
