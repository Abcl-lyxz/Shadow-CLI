package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSignedPassiveMagicRules(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "pub.key")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(pub)), 0600); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(Manifest{ID: "example.test/mobile", Version: "1.0.0", Purpose: "Detect a fixed marker", Capability: "static-magic-v1", Rules: []Rule{{Offset: 0, Hex: "504b0304", Label: "ZIP marker"}}})
	write := func(data []byte, signature []byte) string {
		t.Helper()
		body, _ := json.Marshal(signedManifest{Payload: data, Signature: hex.EncodeToString(signature)})
		path := filepath.Join(dir, "plugin.json")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := write(payload, ed25519.Sign(private, payload))
	loaded, err := Load(path, keyPath)
	if err != nil || len(loaded.MatchPrefix([]byte("PK\x03\x04data"))) != 1 || len(loaded.MatchPrefix([]byte("unknown"))) != 0 {
		t.Fatalf("loaded %+v %v", loaded, err)
	}
	modified := append([]byte(nil), payload...)
	modified[0] = ' '
	if _, err := Load(write(modified, ed25519.Sign(private, payload)), keyPath); err == nil {
		t.Fatal("changed payload accepted")
	}
	bad, _ := json.Marshal(Manifest{ID: "example.test/mobile", Version: "1.0.0", Purpose: "Bad capability", Capability: "shell", Rules: []Rule{{Hex: "50", Label: "x"}}})
	if _, err := Load(write(bad, ed25519.Sign(private, bad)), keyPath); err == nil {
		t.Fatal("executable capability accepted")
	}
	duplicate := []byte(`{"id":"example.test/mobile","id":"example.test/other","version":"1.0.0","purpose":"Duplicate key","capability":"static-magic-v1","rules":[{"offset":0,"hex":"50","label":"x"}]}`)
	if _, err := Load(write(duplicate, ed25519.Sign(private, duplicate)), keyPath); err == nil {
		t.Fatal("signed duplicate fields accepted")
	}
}
