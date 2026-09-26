package config

import (
	"bytes"
	"errors"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

func TestEvidenceKeyPersistsAndFailsClosed(t *testing.T) {
	keyring.MockInit()
	if _, err := EvidenceKey(false); err == nil {
		t.Fatal("missing key accepted for existing evidence")
	}
	first, err := EvidenceKey(true)
	if err != nil || len(first) != 32 {
		t.Fatalf("key creation: %v", err)
	}
	second, err := EvidenceKey(false)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("persistent key read: %v", err)
	}
	if err := keyring.Set(evidenceKeyService, evidenceKeyAccount, "invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := EvidenceKey(true); err == nil {
		t.Fatal("corrupt key was replaced")
	}
	keyring.MockInitWithError(errors.New("keyring unavailable"))
	if _, err := EvidenceKey(true); err == nil {
		t.Fatal("keyring outage was ignored")
	}
}
