package ui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	keyring "github.com/zalando/go-keyring"
	"shadow/internal/store"
)

func TestManagedEvidenceKeySurvivesReopenAndRejectsReplacement(t *testing.T) {
	keyring.MockInit()
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	url := "http://fixture.test/private"
	body := []byte("private response")
	raw, err := json.Marshal(store.RawHTTP{RequestURL: url, Method: http.MethodGet, Status: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	u := sha256.Sum256([]byte(url))
	b := sha256.Sum256(body)
	id, err := st.RecordObservation(context.Background(), "run-1", store.EvidenceSummary{
		Origin: "http://fixture.test", URLSHA256: hex.EncodeToString(u[:]),
		Status: 200, ContentType: "text/plain", Bytes: len(body), SHA256: hex.EncodeToString(b[:]),
	}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.RawEvidence(context.Background(), "run-1", id)
	st.Close()
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("reopened evidence: %v", err)
	}
	if err := keyring.Set("shadow-cli-evidence", "master-v1", base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))); err != nil {
		t.Fatal(err)
	}
	if st, err := openStore(path); err == nil {
		st.Close()
		t.Fatal("replacement key opened existing evidence")
	}
}
