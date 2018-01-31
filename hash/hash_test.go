package hash

import (
	"os/exec"
	"testing"
	"time"
)

func Test(t *testing.T) {
	// arguments are:
	// html body, expected extracted password, whether the password was found
	testExtractPassword(t, "password=mypw", "mypw", true)
	testExtractPassword(t, "passwor=mypw", "dontcare", false)
	testExtractPassword(t, "Password=mypw", "mypw", false)
	testExtractPassword(t, "password=mypw&", "mypw", true)
	testExtractPassword(t, "&password=mypw", "mypw", true)
	testExtractPassword(t, "foo=bar&password=mypw", "mypw", true)
	testExtractPassword(t, "password=mypw&foo=bar", "mypw", true)
	testExtractPassword(t, "foo=bar&password=mypw&another=xx", "mypw", true)
	testExtractPassword(t, "passwordX=not&password=mypw&foo=bar", "mypw", true)
	testExtractPassword(t, "password =not&password=mypw&foo=bar", "mypw", true)
	testExtractPassword(t, "password=mypw&password=bar", "mypw", true) // first

	testHashServer(t)
}

// Extracting the password is a bit complex, so let's have some tests!
func testExtractPassword(t *testing.T, body string,
	expectedPw string, expectedSuccess bool) {
	pw, success := extractPassword(body)
	if success != expectedSuccess {
		t.Errorf("unit test failure: "+
			"input: %s, expectedSuccess: %t, result: %t",
			body, expectedSuccess, success)
	}
	if success && pw != expectedPw {
		t.Errorf("unit test failure: "+
			"input: %s, expected: %s, result: %s",
			body, expectedPw, pw)
	}
}

func testHashServer(t *testing.T) {
	go func() {
		err := HttpHashEncode(8080)
		if err != nil {
			t.Error(err)
		}
	}()
	// give server time to start up
	time.Sleep(100 * time.Millisecond)

	out, err := exec.Command("sh", "-c", "curl "+
		"--data password=angryMonkey "+
		"http://localhost:8080/hash").Output()
	if err != nil {
		t.Error(err)
	}
	if string(out) != "1" {
		t.Errorf("first hash, expected 1, got %s", string(out))
	}

	out, err = exec.Command("sh", "-c", "curl "+
		"http://localhost:8080/hash/1").Output()
	if err != nil {
		t.Error(err)
	}
	if string(out) != "ZEHhWB65gUlzdVwtDQArEyx+KVLzp/aTaRaPlBzYRIFj6vjFdqEb0Q5B8zVKCZ0vKbZPZklJz0Fd7su2A+gf7Q==" {
		t.Errorf("lookup returned %s", string(out))
	}

	// hashing a previously-hashed password should return the earlier key
	out, err = exec.Command("sh", "-c", "curl "+
		"--data password=angryMonkey "+
		"http://localhost:8080/hash").Output()
	if err != nil {
		t.Error(err)
	}
	if string(out) != "1" {
		t.Errorf("first hash, expected 1, got %s", string(out))
	}

	// shutdown
	out, err = exec.Command("sh", "-c", "curl "+
		"http://localhost:8080/shutdown").Output()
	if err != nil {
		t.Error(err)
	}
	if string(out) != "" {
		t.Errorf("shutdown, expected nothing, got %s", string(out))
	}

	// further requests should fail
	out, err = exec.Command("sh", "-c", "curl "+
		"http://localhost:8080/hash/1").Output()
	if err == nil {
		t.Error("lookup succeeded after shutdown, expected failure")
	}
}
