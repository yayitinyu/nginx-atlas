package server

import "testing"

func TestAdminPasswordHashRoundTrip(t *testing.T) {
	encoded, err := hashAdminPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyAdminPassword(encoded, "correct horse battery staple") {
		t.Fatal("expected password to verify")
	}
	if verifyAdminPassword(encoded, "wrong password") {
		t.Fatal("wrong password verified")
	}
}

func TestVerifyAdminPasswordRejectsMalformedHashes(t *testing.T) {
	for _, value := range []string{"", "sha256$bad", "pbkdf2-sha256$1$bad$bad"} {
		if verifyAdminPassword(value, "password") {
			t.Fatalf("malformed hash verified: %q", value)
		}
	}
}
