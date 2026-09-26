package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"modernc.org/sqlite"
)

// SnapshotBytes takes a consistent online SQLite backup without creating a
// plaintext snapshot file. The limit keeps the in-memory copy bounded.
func (s *Store) SnapshotBytes(ctx context.Context, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("snapshot memory limit required")
	}
	var pageSize int64
	if err := s.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return nil, err
	}
	if pageSize <= 0 {
		return nil, errors.New("invalid SQLite page size")
	}
	var pageCount int64
	if err := s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
		return nil, err
	}
	if pageCount > maxBytes/pageSize {
		return nil, errors.New("snapshot exceeds in-memory backup limit")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var snapshot []byte
	err = conn.Raw(func(raw any) error {
		backuper, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("SQLite online backup unavailable")
		}
		backup, err := backuper.NewBackup(":memory:")
		if err != nil {
			return err
		}
		active := true
		defer func() {
			if active {
				_ = backup.Finish()
			}
		}()
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			more, err := backup.Step(128)
			if err != nil {
				return err
			}
			if int64(backup.PageCount()) > maxBytes/pageSize {
				return errors.New("snapshot exceeds in-memory backup limit")
			}
			if !more {
				break
			}
		}
		memoryConn, err := backup.Commit()
		active = false
		if err != nil {
			return err
		}
		defer memoryConn.Close()
		serializer, ok := memoryConn.(interface{ Serialize() ([]byte, error) })
		if !ok {
			return errors.New("SQLite serialization unavailable")
		}
		snapshot, err = serializer.Serialize()
		if err != nil {
			return err
		}
		if len(snapshot) == 0 || int64(len(snapshot)) > maxBytes {
			return errors.New("snapshot exceeds in-memory backup limit")
		}
		// The online backup has copied every WAL frame into the memory image.
		// Its serialized header may still ask SQLite to open a missing -wal
		// sidecar. Mark this self-contained image as rollback-journal format.
		if len(snapshot) < 20 || string(snapshot[:16]) != "SQLite format 3\x00" {
			return errors.New("online backup produced an invalid SQLite image")
		}
		if snapshot[18] == 2 && snapshot[19] == 2 {
			snapshot[18], snapshot[19] = 1, 1
		} else if snapshot[18] != 1 || snapshot[19] != 1 {
			return errors.New("online backup produced unsupported journal header")
		}
		return nil
	})
	return snapshot, err
}

// CheckIntegrity verifies SQLite structure and foreign-key references before
// a restored database is made available as the active store.
func (s *Store) CheckIntegrity(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return errors.New("SQLite integrity check failed")
	}
	rows, err := s.db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("SQLite foreign key check failed")
	}
	return rows.Err()
}

// VerifySnapshotBytes audits a SQLite image entirely in memory. No temporary
// plaintext SQLite database is written while validating a recovery bundle.
func VerifySnapshotBytes(ctx context.Context, image, key []byte) error {
	if len(image) < 16 || string(image[:16]) != "SQLite format 3\x00" {
		return errors.New("snapshot is not a SQLite database")
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	err = conn.Raw(func(raw any) error {
		deserializer, ok := raw.(interface{ Deserialize([]byte) error })
		if !ok {
			return errors.New("SQLite deserialization unavailable")
		}
		return deserializer.Deserialize(image)
	})
	if closeErr := conn.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("deserialize snapshot: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA query_only=ON"); err != nil {
		return fmt.Errorf("set snapshot read-only: %w", err)
	}
	if err := verifySnapshotDB(ctx, db, key); err != nil {
		return fmt.Errorf("audit snapshot: %w", err)
	}
	return nil
}

func verifySnapshotDB(ctx context.Context, db *sql.DB, key []byte) error {
	st := &Store{db: db}
	if err := st.CheckIntegrity(ctx); err != nil {
		return fmt.Errorf("SQLite integrity: %w", err)
	}
	audit, err := st.AuditEvidence(ctx, key)
	if err != nil {
		return fmt.Errorf("evidence audit: %w", err)
	}
	if audit.Invalid != 0 {
		return errors.New("snapshot contains invalid evidence pairs")
	}
	return nil
}
