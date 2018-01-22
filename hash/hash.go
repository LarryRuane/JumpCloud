package hash

// JumpCloud assignment: password hashing and encoding

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This is the state associated with a single long-running http
// password-hashing and lookup server.
type hashServer struct {
	srv          *http.Server
	port         int
	passwordToId map[string]int
	idToHash     []string
	mu           sync.Mutex
	newHash      *sync.Cond
	shutdownDone chan struct{}

	// stats (protected by mutex mu)
	totalRequests int64
	totalTime     time.Duration
}

// Run a password-hashing HTTP server, return when the server stops.
func HttpHashEncode(port int) error {
	hs := hashServer{port: port}

	// translates a saved password to its id (protected by mu)
	hs.passwordToId = make(map[string]int)

	// translates an id to a previously-calculated hashed-encoded password;
	// ids start at 1, so that id maps to idToHash[0]
	// (protected by mu)
	hs.idToHash = make([]string, 0)

	// threads wait on this condition variable when the the hash they
	// need is being generated; each time a new hash is available,
	// all waiters are awakened
	hs.newHash = sync.NewCond(&hs.mu)

	hs.srv = &http.Server{}
	hs.srv.Addr = fmt.Sprintf("localhost:%d", port)
	hs.shutdownDone = make(chan struct{})

	// start the server goroutine
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(&hs, w, r)
	})

	var err error
	if err = hs.srv.ListenAndServe(); err != nil {
		if err == http.ErrServerClosed {
			// this is expected, not an error
			err = nil
			// let shutdown() know the server is shut down
			<-hs.shutdownDone
		}
	}
	return err
}

// Respond to various URL formats
func handleRequest(hs *hashServer, w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.Index(r.URL.Path, "/hash/") == 0:
		lookupHash(hs, w, r)
	case r.URL.Path == "/hash":
		generateHash(hs, w, r)
	case r.URL.Path == "/stats":
		reportStats(hs, w, r)
	case r.URL.Path == "/shutdown":
		shutdown(hs)
	}
}

// Return the id of the hash of this password, computing it if necessary
func generateHash(hs *hashServer, w http.ResponseWriter, r *http.Request) {
	// stats
	defer func(start time.Time) {
		hs.mu.Lock()
		hs.totalTime += time.Since(start)
		hs.totalRequests++
		hs.mu.Unlock()
	}(time.Now())

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("malformed body", err)
		return
	}
	pw, success := extractPassword(string(body))
	if !success {
		fmt.Println("body contains no password")
		return
	}
	hs.mu.Lock()
	id := hs.passwordToId[pw]
	if id == 0 {
		// we haven't seen this password yet; assign a new id and compute
		// the hash asynchronously (pretend it takes a long time)
		id = len(hs.idToHash) + 1
		hs.idToHash = append(hs.idToHash, "")
		hs.passwordToId[pw] = id
		go startComputeHash(hs, id, pw)
	}
	hs.mu.Unlock()
	fmt.Fprintf(w, "%d", id)
}

func startComputeHash(hs *hashServer, id int, pw string) {
	// this work also counts toward stats total hash time
	defer func(start time.Time) {
		hs.mu.Lock()
		hs.totalTime += time.Since(start)
		hs.mu.Unlock()
	}(time.Now())

	// simulate this taking a long time
	time.Sleep(5 * time.Second)
	h := sha512.Sum512([]byte(pw))
	he := base64.StdEncoding.EncodeToString(h[:])

	// remember the result (for future lookup requests)
	hs.mu.Lock()
	hs.idToHash[id-1] = he
	hs.mu.Unlock()

	// wake up any goroutines waiting for a hash
	hs.newHash.Broadcast()
}

func lookupHash(hs *hashServer, w http.ResponseWriter, r *http.Request) {
	// look up the previously hashed password given by id;
	// if not found or still calculating, return empty string
	id, err := strconv.Atoi(r.URL.Path[len("/hash/"):])
	if err != nil {
		fmt.Println("id format error:", err)
		return
	}
	if id == 0 {
		fmt.Println("id must be greater than 0")
		return
	}
	hs.mu.Lock()
	maxId := len(hs.idToHash)
	if id > maxId {
		hs.mu.Unlock()
		fmt.Printf("invalid id (highest current id is %d)\n", maxId)
		return
	}
	for hs.idToHash[id-1] == "" {
		// hash still being computed (note, Wait() releases and reacquires mu)
		hs.newHash.Wait()
	}
	h := hs.idToHash[id-1]
	hs.mu.Unlock()
	fmt.Fprintf(w, "%s", h)
}

func reportStats(hs *hashServer, w http.ResponseWriter, r *http.Request) {
	type stats struct {
		Total   int64         `json:"total"`
		Average time.Duration `json:"average"`
	}
	// avoid division by zero
	tr := hs.totalRequests
	if tr == 0 {
		tr = 1
	}
	currentStats := stats{
		Total:   hs.totalRequests,
		Average: hs.totalTime / time.Millisecond / time.Duration(tr),
	}
	st, err := json.Marshal(currentStats)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(w, "%s", st)
}

// Graceful shutdown
func shutdown(hs *hashServer) {
	// It should take less than 10 seconds for pending hash requests to complete
	go func() {
		ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
		if err := hs.srv.Shutdown(ctx); err != nil {
			log.Fatal(err)
		}
		hs.shutdownDone <- struct{}{}
	}()
}

// Look for a password in the given body; if found, return it and true
// else return false (unsuccessful).
//
// Body is of the form "foo=bar&password=angryMonkey&what=ever";
// in this case return "angryMonkey" and true.
func extractPassword(body string) (string, bool) {
	// adding these separators makes searching easier
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
