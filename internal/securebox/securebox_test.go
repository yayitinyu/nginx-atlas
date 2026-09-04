package securebox

import (
	"bytes"
	"crypto/sha256"
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

func TestKeyedDigestIsStableAndPurposeBound(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	box, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	sameKeyBox, err := New(append([]byte(nil), key...))
	if err != nil {
		t.Fatal(err)
	}
	otherKeyBox, err := New(bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		t.Fatal(err)
	}

	value := []byte("operator-selected-value")
	digest := box.KeyedDigest("security-entrance", value)
	if !bytes.Equal(digest, sameKeyBox.KeyedDigest("security-entrance", value)) {
		t.Fatal("same master key and purpose produced different digests")
	}
	if bytes.Equal(digest, box.KeyedDigest("other-purpose", value)) {
		t.Fatal("keyed digest was not purpose-bound")
	}
	if bytes.Equal(digest, otherKeyBox.KeyedDigest("security-entrance", value)) {
		t.Fatal("different master keys produced the same digest")
	}
	rawDigest := sha256.Sum256(value)
	if bytes.Equal(digest, rawDigest[:]) {
		t.Fatal("keyed digest matched raw SHA-256")
	}
}
