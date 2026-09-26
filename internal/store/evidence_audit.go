package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// EvidenceAudit counts encrypted records and observation events without
// returning raw responses, routes, or event payloads to the caller.
type EvidenceAudit struct {
	Total   int
	Valid   int
	Invalid int
}

// AuditEvidence checks every stored evidence/observation pair in one read
// transaction. It accepts the OS-keyring key directly so an invalid first
// record cannot prevent the remaining records from being checked.
func (s *Store) AuditEvidence(ctx context.Context, key []byte) (EvidenceAudit, error) {
	var report EvidenceAudit
	if len(key) != 0 && len(key) != 32 {
		return report, errors.New("evidence key must be 32 bytes")
	}
	var aead cipher.AEAD
	if len(key) == 32 {
		block, err := aes.NewCipher(key)
		if err != nil {
			return report, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return report, err
		}
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
		WITH refs(event_id,run_id) AS (
			SELECT event_id,run_id FROM evidence
			UNION
			SELECT id,run_id FROM events WHERE kind='observation'
		)
		SELECT refs.event_id,refs.run_id,e.kind,e.payload,v.nonce,v.ciphertext,v.sha256
		FROM refs
		LEFT JOIN events e ON e.id=refs.event_id AND e.run_id=refs.run_id
		LEFT JOIN evidence v ON v.event_id=refs.event_id AND v.run_id=refs.run_id
		ORDER BY refs.event_id,refs.run_id`)
	if err != nil {
		return report, err
	}
	defer rows.Close()
	for rows.Next() {
		var eventID int64
		var runID string
		var kind, expected sql.NullString
		var payload, nonce, ciphertext []byte
		if err := rows.Scan(&eventID, &runID, &kind, &payload, &nonce, &ciphertext, &expected); err != nil {
			return report, err
		}
		valid, err := auditEvidencePair(aead, eventID, runID, kind, payload, nonce, ciphertext, expected)
		if err != nil {
			return report, err
		}
		report.Total++
		if valid {
			report.Valid++
		} else {
			report.Invalid++
		}
	}
	if err := rows.Err(); err != nil {
		return report, err
	}
	if err := rows.Close(); err != nil {
		return report, err
	}
	return report, tx.Commit()
}

func auditEvidencePair(aead cipher.AEAD, eventID int64, runID string, kind sql.NullString, payload, nonce, ciphertext []byte, expected sql.NullString) (bool, error) {
	if !kind.Valid || kind.String != "observation" || !expected.Valid {
		return false, nil
	}
	if aead == nil {
		return false, errors.New("evidence key unavailable")
	}
	var summary EvidenceSummary
	if json.Unmarshal(payload, &summary) != nil {
		return false, nil
	}
	if len(nonce) != aead.NonceSize() || len(ciphertext) < aead.Overhead() || len(ciphertext) > maxEvidenceBytes+aead.Overhead() {
		return false, nil
	}
	raw, err := aead.Open(nil, nonce, ciphertext, evidenceAAD(runID, eventID))
	if err != nil {
		return false, nil
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != expected.String || validateEvidence(summary, raw) != nil {
		return false, nil
	}
	return true, nil
}
