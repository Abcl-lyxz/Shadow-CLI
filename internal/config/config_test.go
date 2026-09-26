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

func TestRecoveredEvidenceKeyNeverReplacesExistingKey(t *testing.T) {
	keyring.MockInit()
	key := bytes.Repeat([]byte{3}, 32)
	if err := InstallEvidenceKey(key); err != nil {
		t.Fatal(err)
	}
	if err := InstallEvidenceKey(key); err != nil {
		t.Fatalf("same key was rejected: %v", err)
	}
	if err := InstallEvidenceKey(bytes.Repeat([]byte{4}, 32)); err == nil {
		t.Fatal("different key replaced the existing key")
	}
	got, err := EvidenceKey(false)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("original key was lost: %v", err)
	}
}

func TestPolicyApprovalKeyIsSeparateAndFailsClosed(t *testing.T) {
	keyring.MockInit()
	if _, err := PolicyApprovalKey(false); err == nil {
		t.Fatal("missing approval key accepted")
	}
	approvalKey, err := PolicyApprovalKey(true)
	if err != nil || len(approvalKey) != 32 {
		t.Fatalf("approval key creation: %v", err)
	}
	if _, err := EvidenceKey(false); err == nil {
		t.Fatal("approval key became an evidence key")
	}
	second, err := PolicyApprovalKey(false)
	if err != nil || !bytes.Equal(approvalKey, second) {
		t.Fatalf("approval key was not persisted: %v", err)
	}
	if err := keyring.Set(policyApprovalService, policyApprovalAccount, "invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := PolicyApprovalKey(true); err == nil {
		t.Fatal("corrupt approval key was replaced")
	}
}

func TestRetentionDaysAreBounded(t *testing.T) {
	if days, err := (Config{}).RetentionDays(); err != nil || days != DefaultAutoRetentionDays {
		t.Fatalf("default retention: %d %v", days, err)
	}
	for _, days := range []int{-1, 366} {
		if _, err := (Config{AutoRetentionDays: days}).RetentionDays(); err == nil {
			t.Fatalf("accepted %d retention days", days)
		}
	}
	if days, err := (Config{AutoRetentionDays: 7}).RetentionDays(); err != nil || days != 7 {
		t.Fatalf("configured retention: %d %v", days, err)
	}
}
