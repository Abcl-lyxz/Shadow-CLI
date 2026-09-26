package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shadow/internal/store"
)

func backupFixture(t *testing.T) (string, string, string, string, []byte, int64) {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"source", "archive", "custody", "restored"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	database := filepath.Join(root, "source", "shadow.db")
	archive := filepath.Join(root, "archive", "shadow.sbk")
	keyFile := filepath.Join(root, "custody", "recovery.key")
	anchor := filepath.Join(root, "custody", "anchor.sha256")
	evidenceKey := bytes.Repeat([]byte{0x42}, 32)
	st, err := store.OpenWithEvidenceKey(database, evidenceKey)
	if err != nil {
		t.Fatal(err)
	}
	url := "http://fixture.test/private?token=secret-value"
	body := []byte("private@example.com")
	raw, err := json.Marshal(store.RawHTTP{RequestURL: url, Method: http.MethodGet, Status: 200, Header: http.Header{"Content-Type": []string{"text/plain"}, "Set-Cookie": []string{"session=private"}}, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	u := sha256.Sum256([]byte(url))
	b := sha256.Sum256(body)
	id, err := st.RecordObservation(context.Background(), "run-1", store.EvidenceSummary{Origin: "http://fixture.test", URLSHA256: hex.EncodeToString(u[:]), Status: 200, ContentType: "text/plain", Bytes: len(body), SHA256: hex.EncodeToString(b[:])}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Create(context.Background(), st, archive, keyFile, anchor, evidenceKey); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return database, archive, keyFile, anchor, evidenceKey, id
}

func TestEncryptedBackupRestoresEvidenceAndNeverOverwrites(t *testing.T) {
	database, archive, keyFile, anchor, evidenceKey, eventID := backupFixture(t)
	assertNoPlaintextScratch(t, filepath.Dir(filepath.Dir(database)))
	archiveBytes, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private@example.com", "session=private", "secret-value"} {
		if bytes.Contains(archiveBytes, []byte(secret)) {
			t.Fatalf("archive disclosed %s", secret)
		}
	}
	target := filepath.Join(filepath.Dir(filepath.Dir(database)), "restored", "shadow.db")
	installed := 0
	err = Restore(context.Background(), archive, keyFile, anchor, target, func(key []byte) error {
		installed++
		if !bytes.Equal(key, evidenceKey) {
			t.Fatal("wrong evidence key recovered")
		}
		return nil
	})
	if err != nil || installed != 1 {
		t.Fatalf("restore failed: %v; installs=%d", err, installed)
	}
	assertNoPlaintextScratch(t, filepath.Dir(filepath.Dir(database)))
	st, err := store.OpenWithEvidenceKey(target, evidenceKey)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	raw, err := st.RawEvidence(context.Background(), "run-1", eventID)
	var response store.RawHTTP
	if err == nil {
		err = json.Unmarshal(raw, &response)
	}
	if err != nil || string(response.Body) != "private@example.com" {
		t.Fatalf("restored evidence unavailable: %v", err)
	}
	if err := Restore(context.Background(), archive, keyFile, anchor, target, func([]byte) error { t.Fatal("reinstalled key"); return nil }); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing database was not protected: %v", err)
	}
	if err := Create(context.Background(), st, archive, keyFile, anchor, evidenceKey); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing archive was not protected: %v", err)
	}
}

func TestRestoreDrillStartsNewProvenanceChain(t *testing.T) {
	database, archive, keyFile, anchor, evidenceKey, eventID := backupFixture(t)
	ctx := context.Background()
	source, err := store.OpenWithEvidenceKey(database, evidenceKey)
	if err != nil {
		t.Fatal(err)
	}
	ledger, head := store.DefaultProvenancePaths(database)
	if err := source.EnableProvenance(ctx, ledger, head); err != nil {
		t.Fatal(err)
	}
	if err := source.Append(ctx, "run-1", "later", map[string]int{"count": 1}); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(filepath.Dir(filepath.Dir(database)), "restored", "drill.db")
	if err := Restore(ctx, archive, keyFile, anchor, restored, func(key []byte) error {
		if !bytes.Equal(key, evidenceKey) {
			return errors.New("wrong evidence key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	clone, err := store.OpenWithEvidenceKey(restored, evidenceKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clone.Close()
	if raw, err := clone.RawEvidence(ctx, "run-1", eventID); err != nil || len(raw) == 0 {
		t.Fatalf("restored evidence unavailable: %v", err)
	}
	restoredLedger, restoredHead := store.DefaultProvenancePaths(restored)
	if err := clone.EnableProvenance(ctx, restoredLedger, restoredHead); err != nil {
		t.Fatalf("new recovery chain rejected: %v", err)
	}
	if err := clone.AuditProvenance(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := clone.EventInRun(ctx, "run-1", eventID+1); err == nil {
		t.Fatal("post-backup event appeared in restored snapshot")
	}
}

func TestRestoreRejectsTamperWrongKeyAndKeyInstallerFailure(t *testing.T) {
	database, archive, keyFile, anchor, _, _ := backupFixture(t)
	root := filepath.Dir(filepath.Dir(database))
	target := filepath.Join(root, "restored", "shadow.db")
	original, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	checkRefused := func(name string) {
		t.Helper()
		if err := Restore(context.Background(), archive, keyFile, anchor, target, func([]byte) error { t.Fatal("installed unverified key"); return nil }); err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left a target: %v", name, err)
		}
	}
	modified := append([]byte(nil), original...)
	modified[len(modified)-1] ^= 1
	if err := os.WriteFile(archive, modified, 0600); err != nil {
		t.Fatal(err)
	}
	checkRefused("tampered archive")
	h := sha256.Sum256(modified)
	if err := os.WriteFile(anchor, []byte("sha256:"+hex.EncodeToString(h[:])+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	checkRefused("tampered archive with matching edited anchor")
	if err := os.WriteFile(archive, original[:len(original)-1], 0600); err != nil {
		t.Fatal(err)
	}
	checkRefused("truncated archive")
	if err := os.WriteFile(archive, original, 0600); err != nil {
		t.Fatal(err)
	}
	h = sha256.Sum256(original)
	if err := os.WriteFile(anchor, []byte("sha256:"+hex.EncodeToString(h[:])+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if keyBytes[len(keyMagic)] == 'A' {
		keyBytes[len(keyMagic)] = 'B'
	} else {
		keyBytes[len(keyMagic)] = 'A'
	}
	if err := os.WriteFile(keyFile, keyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	checkRefused("wrong recovery key")
	// Restore the original key file from a fresh bundle; a failed keyring
	// installation still must not create the target database.
	_, freshArchive, freshKey, freshAnchor, _, _ := backupFixture(t)
	if err := Restore(context.Background(), freshArchive, freshKey, freshAnchor, target, func([]byte) error { return errors.New("keyring unavailable") }); err == nil || !strings.Contains(err.Error(), "keyring unavailable") {
		t.Fatalf("key installation failure not returned: %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("key installation failure left target: %v", err)
	}
	assertNoPlaintextScratch(t, root)
}

func assertNoPlaintextScratch(t *testing.T, root string) {
	t.Helper()
	for _, name := range []string{"source", "restored"} {
		entries, err := os.ReadDir(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".shadow-backup-") || strings.HasPrefix(entry.Name(), ".shadow-restore-") {
				t.Fatalf("plaintext scratch remains: %s", entry.Name())
			}
		}
	}
}

func TestBackupRejectsDamagedEvidenceBeforePublishing(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"source", "archive", "custody"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	database := filepath.Join(root, "source", "shadow.db")
	key := bytes.Repeat([]byte{7}, 32)
	st, err := store.OpenWithEvidenceKey(database, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Append(context.Background(), "run-1", "observation", map[string]any{"status": 200}); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "archive", "backup.sbk")
	keyFile := filepath.Join(root, "custody", "key")
	anchor := filepath.Join(root, "custody", "anchor")
	if err := Create(context.Background(), st, archive, keyFile, anchor, key); err == nil {
		t.Fatal("orphan observation was backed up")
	}
	for _, path := range []string{archive, keyFile, anchor} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed backup left %s: %v", path, err)
		}
	}
}
