package securebox

import (
	"bytes"
	"strings"
	"testing"
)

func TestSealOpenAndPurposeBinding(t *testing.T) {
	box, err := New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Seal("certificate:test", []byte("private material"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "private material") {
		t.Fatal("ciphertext contains plaintext")
	}
	opened, err := box.Open("certificate:test", sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != "private material" {
		t.Fatalf("unexpected plaintext %q", opened)
	}
	if _, err := box.Open("dns-account:test", sealed); err == nil {
		t.Fatal("ciphertext should be bound to its purpose")
	}
}

func TestParseKeyRejectsWrongLength(t *testing.T) {
	if _, err := ParseKey("dG9vLXNob3J0"); err == nil {
		t.Fatal("expected short key to fail")
	}
}
