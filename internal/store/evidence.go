package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"time"
)

const maxEvidenceBytes = 512 << 10

// EvidenceSummary is the only part of a response allowed into the event log.
// The URL, headers, and body live only in the encrypted evidence table.
type EvidenceSummary struct {
	Origin      string `json:"origin"`
	URLSHA256   string `json:"url_sha256"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256"`
	Truncated   bool   `json:"truncated"`
}

// RawHTTP is serialized only inside the encrypted evidence record.
type RawHTTP struct {
	RequestURL string      `json:"request_url"`
	Method     string      `json:"method"`
	Status     int         `json:"status"`
	Header     http.Header `json:"header"`
	Body       []byte      `json:"body"`
	Truncated  bool        `json:"truncated"`
}

// OpenWithEvidenceKey enables raw-evidence writes and reads. The caller must
// keep the 32-byte key outside this database and supply it again after restart.
func OpenWithEvidenceKey(path string, key []byte) (*Store, error) {
	s, err := Open(path)
	if err != nil {
		return nil, err
	}
	if err := s.ConfigureEvidenceKey(context.Background(), key); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// HasEvidence lets startup refuse key regeneration when encrypted records exist.
func (s *Store) HasEvidence(ctx context.Context) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM evidence)").Scan(&exists)
	return exists, err
}

// ConfigureEvidenceKey checks the key against existing evidence before the
// store accepts new records. A lost or replaced key must not orphan old data.
func (s *Store) ConfigureEvidenceKey(ctx context.Context, key []byte) error {
	if len(key) != 32 {
		return errors.New("evidence key must be 32 bytes")
	}
	var runID string
	var eventID int64
	err := s.db.QueryRowContext(ctx, "SELECT run_id,event_id FROM evidence ORDER BY event_id LIMIT 1").Scan(&runID, &eventID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	previous := s.evidenceKey
	s.evidenceKey = append([]byte(nil), key...)
	if err == nil {
		if _, err := s.observationInRun(ctx, runID, eventID); err != nil {
			s.evidenceKey = previous
			return errors.New("existing evidence cannot be authenticated with the OS keyring key")
		}
	}
	return nil
}

func (s *Store) evidenceAEAD() (cipher.AEAD, error) {
	if len(s.evidenceKey) != 32 {
		return nil, errors.New("evidence key unavailable")
	}
	block, err := aes.NewCipher(s.evidenceKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func evidenceAAD(runID string, eventID int64) []byte {
	return []byte(fmt.Sprintf("shadow-evidence-v1:%s:%d", runID, eventID))
}

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

func validateEvidence(summary EvidenceSummary, raw []byte) error {
	var response RawHTTP
	if err := json.Unmarshal(raw, &response); err != nil {
		return errors.New("invalid raw response")
	}
	u, err := url.Parse(response.RequestURL)
	if err != nil || u.Opaque != "" || u.Scheme+"://"+u.Host != summary.Origin || response.Method != http.MethodGet || response.Status != summary.Status || len(response.Body) != summary.Bytes || response.Truncated != summary.Truncated {
		return errors.New("raw response does not match observation")
	}
	urlHash := sha256.Sum256([]byte(response.RequestURL))
	bodyHash := sha256.Sum256(response.Body)
	if hex.EncodeToString(urlHash[:]) != summary.URLSHA256 || hex.EncodeToString(bodyHash[:]) != summary.SHA256 {
		return errors.New("raw response hash does not match observation")
	}
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || len(contentType) > 128 {
		contentType = ""
	}
	if contentType != summary.ContentType {
		return errors.New("raw content type does not match observation")
	}
	return nil
}

// RecordObservation commits the minimized event and encrypted raw response in
// one transaction. A failed evidence write cannot leave an observation behind.
func (s *Store) RecordObservation(ctx context.Context, runID string, summary EvidenceSummary, raw []byte) (int64, error) {
	if runID == "" || summary.Origin == "" || !validDigest(summary.URLSHA256) || !validDigest(summary.SHA256) || summary.Status < 100 || summary.Status > 599 || summary.Bytes < 0 || len(raw) == 0 || len(raw) > maxEvidenceBytes {
		return 0, errors.New("invalid observation or raw evidence")
	}
	if err := validateEvidence(summary, raw); err != nil {
		return 0, err
	}
	aead, err := s.evidenceAEAD()
	if err != nil {
		return 0, err
	}
	payload, err := json.Marshal(summary)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	at := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, "INSERT INTO events(run_id,at,kind,payload) VALUES(?,?,?,?)", runID, at, "observation", payload)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	ciphertext := aead.Seal(nil, nonce, raw, evidenceAAD(runID, id))
	digest := sha256.Sum256(raw)
	if _, err := tx.ExecContext(ctx, "INSERT INTO evidence(event_id,run_id,nonce,ciphertext,sha256,created_at) VALUES(?,?,?,?,?,?)", id, runID, nonce, ciphertext, hex.EncodeToString(digest[:]), at); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// RawEvidence requires both the encryption key and the exact run/event pair.
// The dashboard and agent context never call this method.
func (s *Store) RawEvidence(ctx context.Context, runID string, eventID int64) ([]byte, error) {
	aead, err := s.evidenceAEAD()
	if err != nil {
		return nil, err
	}
	var nonce, ciphertext []byte
	var expected string
	err = s.db.QueryRowContext(ctx, "SELECT nonce,ciphertext,sha256 FROM evidence WHERE event_id=? AND run_id=?", eventID, runID).Scan(&nonce, &ciphertext, &expected)
	if err != nil {
		return nil, err
	}
	raw, err := aead.Open(nil, nonce, ciphertext, evidenceAAD(runID, eventID))
	if err != nil {
		return nil, errors.New("evidence authentication failed")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != expected {
		return nil, errors.New("evidence digest mismatch")
	}
	return raw, nil
}

func (s *Store) observationInRun(ctx context.Context, runID string, eventID int64) (EvidenceSummary, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx, "SELECT e.payload FROM events e JOIN evidence v ON v.event_id=e.id AND v.run_id=e.run_id WHERE e.id=? AND e.run_id=? AND e.kind='observation'", eventID, runID).Scan(&payload)
	if err != nil {
		return EvidenceSummary{}, err
	}
	var summary EvidenceSummary
	if err := json.Unmarshal(payload, &summary); err != nil {
		return EvidenceSummary{}, err
	}
	raw, err := s.RawEvidence(ctx, runID, eventID)
	if err != nil {
		return EvidenceSummary{}, err
	}
	if err := validateEvidence(summary, raw); err != nil {
		return EvidenceSummary{}, err
	}
	return summary, nil
}
