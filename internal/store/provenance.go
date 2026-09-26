package store

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Provenance is an independent, append-only sequence of active event/evidence
// digests. The separately held head detects truncation of that sequence.
type Provenance struct {
	ledger string
	head   string
	key    []byte
}

type provenanceEntry struct {
	Sequence int64  `json:"sequence"`
	At       string `json:"at"`
	Reason   string `json:"reason"`
	State    string `json:"state_sha256"`
	Previous string `json:"previous_sha256"`
	Hash     string `json:"hash"`
}

// DefaultProvenancePaths keeps the ledger and its head in separate private
// sibling directories outside the active database directory. Operators must
// copy the head into independent custody against whole-profile rollback.
func DefaultProvenancePaths(database string) (string, string) {
	absolute, err := filepath.Abs(database)
	if err != nil {
		absolute = filepath.Clean(database)
	}
	identity := absolute
	if runtime.GOOS == "windows" {
		identity = strings.ToLower(identity)
	}
	sum := sha256.Sum256([]byte(identity))
	suffix := hex.EncodeToString(sum[:6])
	parent := filepath.Dir(filepath.Dir(absolute))
	return filepath.Join(parent, "shadow-provenance-"+suffix, "events.log"), filepath.Join(parent, "shadow-provenance-head-"+suffix, "head")
}

// EnableProvenance checks an existing chain before allowing more writes. A new
// chain seals the current database as a baseline; it cannot attest to history
// that predates enrollment.
func (s *Store) EnableProvenance(ctx context.Context, ledger, head string) error {
	if s.provenance != nil {
		return errors.New("provenance already enabled")
	}
	if len(s.evidenceKey) != 32 {
		return errors.New("evidence key required for authenticated provenance")
	}
	if err := s.CheckIntegrity(ctx); err != nil {
		return err
	}
	audit, err := s.AuditEvidence(ctx, s.evidenceKey)
	if err != nil {
		return err
	}
	if audit.Invalid != 0 {
		return errors.New("evidence audit failed before provenance enrollment")
	}
	paths := []string{ledger, head}
	for i, path := range paths {
		if path == "" {
			return errors.New("provenance ledger and head paths required")
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		paths[i] = filepath.Clean(absolute)
	}
	if strings.EqualFold(paths[0], paths[1]) || strings.EqualFold(filepath.Dir(paths[0]), filepath.Dir(paths[1])) {
		return errors.New("provenance head must be held in a separate directory")
	}
	p := &Provenance{ledger: paths[0], head: paths[1], key: append([]byte(nil), s.evidenceKey...)}
	_, ledgerErr := os.Lstat(p.ledger)
	_, headErr := os.Lstat(p.head)
	if errors.Is(ledgerErr, os.ErrNotExist) && errors.Is(headErr, os.ErrNotExist) {
		if err := p.append(ctx, s, "baseline"); err != nil {
			return err
		}
	} else if ledgerErr != nil || headErr != nil {
		return errors.New("provenance ledger or independent head is missing")
	}
	if err := p.verify(ctx, s); err != nil {
		return err
	}
	s.provenance = p
	return nil
}

func (s *Store) AuditProvenance(ctx context.Context) error {
	if s.provenance == nil {
		return errors.New("independent provenance is not enabled")
	}
	return s.provenance.verify(ctx, s)
}

// VerifiedSnapshotBytes refuses to back up a state that diverges from the
// independent head. It serializes trusted writers using this Store while the
// consistent SQLite image is captured.
func (s *Store) VerifiedSnapshotBytes(ctx context.Context, maxBytes int64) ([]byte, error) {
	if s.provenance == nil {
		return s.SnapshotBytes(ctx, maxBytes)
	}
	s.provenanceMu.Lock()
	defer s.provenanceMu.Unlock()
	if err := s.provenance.verify(ctx, s); err != nil {
		return nil, err
	}
	image, err := s.SnapshotBytes(ctx, maxBytes)
	if err != nil {
		return nil, err
	}
	if err := s.provenance.verify(ctx, s); err != nil {
		return nil, err
	}
	return image, nil
}

// commitWithProvenance makes the authenticated external record durable before
// SQLite commits. A failed SQLite commit leaves the ledger ahead and later
// opens fail closed; it never creates an unrecorded committed event.
func (s *Store) commitWithProvenance(ctx context.Context, tx *sql.Tx, reason string) error {
	if s.provenance != nil {
		state, err := activeStateDigestTx(ctx, tx)
		if err != nil {
			return err
		}
		if err := s.provenance.appendState(state, reason); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// beginProvenanceMutation refuses to use a database that no longer matches its
// independently held head. The lock serializes writers sharing this Store.
func (s *Store) beginProvenanceMutation(ctx context.Context) (func(), error) {
	if s.provenance == nil {
		return func() {}, nil
	}
	s.provenanceMu.Lock()
	if err := s.provenance.verify(ctx, s); err != nil {
		s.provenanceMu.Unlock()
		return nil, err
	}
	return s.provenanceMu.Unlock, nil
}

func digestPart(h hash.Hash, b []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(b)))
	h.Write(length[:])
	h.Write(b)
}

func (s *Store) activeStateDigest(ctx context.Context) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	state, err := activeStateDigestTx(ctx, tx)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return state, nil
}

func activeStateDigestTx(ctx context.Context, tx *sql.Tx) (string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT e.id,e.run_id,e.at,e.kind,e.payload,v.run_id,v.nonce,v.ciphertext,v.sha256,v.created_at
		FROM events e LEFT JOIN evidence v ON v.event_id=e.id ORDER BY e.id`)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	digestPart(h, []byte("shadow-active-provenance-v1"))
	var count uint64
	for rows.Next() {
		var id int64
		var runID, at, kind string
		var payload []byte
		var evidenceRun, evidenceSHA, evidenceAt *string
		var nonce, ciphertext []byte
		if err := rows.Scan(&id, &runID, &at, &kind, &payload, &evidenceRun, &nonce, &ciphertext, &evidenceSHA, &evidenceAt); err != nil {
			rows.Close()
			return "", err
		}
		var idBytes [8]byte
		binary.BigEndian.PutUint64(idBytes[:], uint64(id))
		digestPart(h, idBytes[:])
		for _, value := range [][]byte{[]byte(runID), []byte(at), []byte(kind), payload} {
			digestPart(h, value)
		}
		if evidenceRun != nil {
			for _, value := range [][]byte{[]byte{1}, []byte(*evidenceRun), nonce, ciphertext, []byte(*evidenceSHA), []byte(*evidenceAt)} {
				digestPart(h, value)
			}
		} else {
			digestPart(h, []byte{0})
		}
		count++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	if err := rows.Close(); err != nil {
		return "", err
	}
	// Traverse evidence independently so an orphan row introduced with foreign
	// keys disabled cannot disappear behind the LEFT JOIN above.
	evidenceRows, err := tx.QueryContext(ctx, "SELECT event_id,run_id,nonce,ciphertext,sha256,created_at FROM evidence ORDER BY event_id")
	if err != nil {
		return "", err
	}
	for evidenceRows.Next() {
		var id int64
		var runID, digest, created string
		var nonce, ciphertext []byte
		if err := evidenceRows.Scan(&id, &runID, &nonce, &ciphertext, &digest, &created); err != nil {
			evidenceRows.Close()
			return "", err
		}
		var idBytes [8]byte
		binary.BigEndian.PutUint64(idBytes[:], uint64(id))
		for _, value := range [][]byte{idBytes[:], []byte(runID), nonce, ciphertext, []byte(digest), []byte(created)} {
			digestPart(h, value)
		}
	}
	if err := evidenceRows.Err(); err != nil {
		evidenceRows.Close()
		return "", err
	}
	if err := evidenceRows.Close(); err != nil {
		return "", err
	}
	var total [8]byte
	binary.BigEndian.PutUint64(total[:], count)
	digestPart(h, total[:])
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (p *Provenance) entryHash(entry provenanceEntry) (string, error) {
	entry.Hash = ""
	b, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, p.key)
	mac.Write([]byte("shadow-provenance-entry-v1\x00"))
	mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (p *Provenance) last() (provenanceEntry, error) {
	for _, path := range []string{p.ledger, p.head} {
		info, err := os.Lstat(path)
		if err != nil {
			return provenanceEntry{}, err
		}
		if !info.Mode().IsRegular() {
			return provenanceEntry{}, errors.New("provenance file is not regular")
		}
		if path == p.head && info.Size() > 128 {
			return provenanceEntry{}, errors.New("provenance head is oversized")
		}
	}
	file, err := os.Open(p.ledger)
	if err != nil {
		return provenanceEntry{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return provenanceEntry{}, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return provenanceEntry{}, errors.New("provenance ledger is empty or irregular")
	}
	var final [1]byte
	if _, err := file.ReadAt(final[:], info.Size()-1); err != nil || final[0] != '\n' {
		return provenanceEntry{}, errors.New("provenance ledger has an incomplete final entry")
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var previous provenanceEntry
	for scanner.Scan() {
		var entry provenanceEntry
		line := scanner.Bytes()
		if err := json.Unmarshal(line, &entry); err != nil {
			return provenanceEntry{}, errors.New("invalid provenance entry")
		}
		expected, err := p.entryHash(entry)
		if err != nil || entry.Hash != expected || entry.Previous != previous.Hash || entry.Sequence != previous.Sequence+1 || entry.State == "" || entry.Reason == "" {
			return provenanceEntry{}, errors.New("provenance chain is damaged")
		}
		previous = entry
	}
	if err := scanner.Err(); err != nil {
		return provenanceEntry{}, err
	}
	if previous.Sequence == 0 {
		return provenanceEntry{}, errors.New("provenance ledger is empty")
	}
	head, err := os.ReadFile(p.head)
	if err != nil {
		return provenanceEntry{}, err
	}
	if string(head) != fmt.Sprintf("%d %s\n", previous.Sequence, previous.Hash) {
		return provenanceEntry{}, errors.New("provenance head does not match append-only ledger")
	}
	return previous, nil
}

func (p *Provenance) verify(ctx context.Context, s *Store) error {
	last, err := p.last()
	if err != nil {
		return err
	}
	state, err := s.activeStateDigest(ctx)
	if err != nil {
		return err
	}
	if state != last.State {
		return errors.New("active event/evidence state differs from independent provenance; possible deletion or rollback")
	}
	return nil
}

func (p *Provenance) append(ctx context.Context, s *Store, reason string) error {
	state, err := s.activeStateDigest(ctx)
	if err != nil {
		return err
	}
	return p.appendState(state, reason)
}

func (p *Provenance) appendState(state, reason string) error {
	var previous provenanceEntry
	var err error
	if _, err := os.Stat(p.ledger); err == nil {
		previous, err = p.last()
		if err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entry := provenanceEntry{Sequence: previous.Sequence + 1, At: time.Now().UTC().Format(time.RFC3339Nano), Reason: reason, State: state, Previous: previous.Hash}
	entry.Hash, err = p.entryHash(entry)
	if err != nil {
		return err
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.ledger), 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.head), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(p.ledger, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// The head is replaced only after the ledger entry has reached storage. A
	// crash between these writes fails closed and requires operator recovery.
	tmp, err := os.OpenFile(p.head+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(tmp, fmt.Sprintf("%d %s\n", entry.Sequence, entry.Hash)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(p.head+".tmp", p.head)
}
