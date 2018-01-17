package hash

import "testing"

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
}

// Extracting the password is a bit complex, so let's have some tests!
func testExtractPassword(t *testing.T, body string, expectedPw string, expectedSuccess bool) {
	pw, success := extractPassword(body)
	if success != expectedSuccess {
		t.Errorf("unit test failure: input: %s, expectedSuccess: %t, result: %t",
			body, expectedSuccess, success)
	}
	if success && pw != expectedPw {
		t.Errorf("unit test failure: input: %s, expected: %s, result: %s",
			body, expectedPw, pw)
	}
}
