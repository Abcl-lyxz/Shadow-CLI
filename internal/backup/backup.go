// Package backup provides an encrypted, versioned SQLite recovery bundle.
// Recovery keys and integrity anchors are separate operator-held files.
package backup

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"shadow/internal/store"
)

const chunkSize = 1 << 20
const maxDatabaseBytes = 1 << 40
const maxMemoryDatabaseBytes = 128 << 20

var magic = []byte("SHADOWBK1\n")
var keyMagic = []byte("SHADOW-RECOVERY-KEY-1\n")

// Create takes a consistent snapshot, audits every evidence pair, then writes
// three new files. The recovery key and anchor must be held outside the backup
// directory. Existing files are never replaced.
func Create(ctx context.Context, source *store.Store, archivePath, keyPath, anchorPath string, evidenceKey []byte) error {
	if source == nil || len(evidenceKey) != 32 {
		return errors.New("store and 32-byte evidence key required")
	}
	if err := validatePaths(archivePath, keyPath, anchorPath); err != nil {
		return err
	}
	snapshot, err := source.VerifiedSnapshotBytes(ctx, maxMemoryDatabaseBytes)
	if err != nil {
		return fmt.Errorf("snapshot in memory: %w", err)
	}
	if err := store.VerifySnapshotBytes(ctx, snapshot, evidenceKey); err != nil {
		return fmt.Errorf("verify in-memory snapshot: %w", err)
	}
	var recoveryKey [32]byte
	var noncePrefix [8]byte
	if _, err := rand.Read(recoveryKey[:]); err != nil {
		return err
	}
	if _, err := rand.Read(noncePrefix[:]); err != nil {
		return err
	}
	block, err := aes.NewCipher(recoveryKey[:])
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	header := makeHeader(noncePrefix, uint64(len(snapshot)))
	archive, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	archiveCreated := true
	defer func() {
		archive.Close()
		if archiveCreated {
			os.Remove(archivePath)
		}
	}()
	digest := sha256.New()
	output := io.MultiWriter(archive, digest)
	if _, err := output.Write(header); err != nil {
		return err
	}
	if err := encryptChunks(output, io.MultiReader(bytes.NewReader(evidenceKey), bytes.NewReader(snapshot)), aead, header, uint64(len(snapshot))+32); err != nil {
		return err
	}
	if err := archive.Sync(); err != nil {
		return err
	}
	if err := archive.Close(); err != nil {
		return err
	}
	keyFile := append(append([]byte(nil), keyMagic...), []byte(base64.RawStdEncoding.EncodeToString(recoveryKey[:])+"\n")...)
	if err := writeNewFile(keyPath, keyFile); err != nil {
		return err
	}
	keyCreated := true
	defer func() {
		if keyCreated {
			os.Remove(keyPath)
		}
	}()
	anchor := []byte("sha256:" + hex.EncodeToString(digest.Sum(nil)) + "\n")
	if err := writeNewFile(anchorPath, anchor); err != nil {
		return err
	}
	archiveCreated = false
	keyCreated = false
	return nil
}

// Restore verifies the separate anchor, decrypts and audits in memory, then
// creates a previously absent target. An interrupted final write may leave a
// partial target that the operator must remove before retrying.
// installKey must refuse to replace a different key already in use.
func Restore(ctx context.Context, archivePath, keyPath, anchorPath, targetPath string, installKey func([]byte) error) error {
	if installKey == nil || targetPath == "" {
		return errors.New("restore target and key installer required")
	}
	if err := validatePaths(archivePath, keyPath, anchorPath); err != nil {
		return err
	}
	if _, err := os.Lstat(targetPath); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	keyText, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(keyText, keyMagic) || len(keyText) > 128 {
		return errors.New("invalid recovery key file")
	}
	encoded := strings.TrimSpace(string(keyText[len(keyMagic):]))
	recoveryKey, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(recoveryKey) != 32 || base64.RawStdEncoding.EncodeToString(recoveryKey) != encoded || string(keyText) != string(keyMagic)+encoded+"\n" {
		return errors.New("invalid recovery key file")
	}
	anchorText, err := os.ReadFile(anchorPath)
	if err != nil {
		return err
	}
	if len(anchorText) != len("sha256:")+64+1 || !bytes.HasPrefix(anchorText, []byte("sha256:")) || anchorText[len(anchorText)-1] != '\n' {
		return errors.New("invalid backup anchor")
	}
	expectedHash, err := hex.DecodeString(string(anchorText[len("sha256:") : len(anchorText)-1]))
	if err != nil || len(expectedHash) != sha256.Size {
		return errors.New("invalid backup anchor")
	}
	input, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
		return err
	}
	digest := sha256.New()
	reader := io.TeeReader(input, digest)
	header := make([]byte, len(magic)+8+8)
	if _, err := io.ReadFull(reader, header); err != nil || !bytes.Equal(header[:len(magic)], magic) {
		return errors.New("invalid backup header")
	}
	length := binary.BigEndian.Uint64(header[len(magic)+8:])
	if length == 0 || length > maxDatabaseBytes || length > maxMemoryDatabaseBytes {
		return errors.New("backup database exceeds in-memory restore limit")
	}
	block, err := aes.NewCipher(recoveryKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	var output bytes.Buffer
	output.Grow(int(length))
	var evidenceKey [32]byte
	if err := decryptChunks(reader, &output, aead, header, length+32, evidenceKey[:]); err != nil {
		return err
	}
	var extra [1]byte
	if n, err := reader.Read(extra[:]); n != 0 || err != io.EOF {
		return errors.New("backup has trailing or unreadable data")
	}
	if !bytes.Equal(digest.Sum(nil), expectedHash) {
		return errors.New("backup does not match the external anchor")
	}
	if err := store.VerifySnapshotBytes(ctx, output.Bytes(), evidenceKey[:]); err != nil {
		return err
	}
	if _, err := os.Lstat(targetPath); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := installKey(evidenceKey[:]); err != nil {
		return err
	}
	file, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		file.Close()
		if !complete {
			os.Remove(targetPath)
		}
	}()
	if _, err := io.Copy(file, &output); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func makeHeader(prefix [8]byte, dbSize uint64) []byte {
	header := append([]byte(nil), magic...)
	header = append(header, prefix[:]...)
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], dbSize)
	return append(header, size[:]...)
}

func encryptChunks(dst io.Writer, src io.Reader, aead cipher.AEAD, header []byte, length uint64) error {
	buffer := make([]byte, chunkSize)
	for index := uint64(0); length > 0; index++ {
		if index >= 1<<32 {
			return errors.New("backup nonce space exhausted")
		}
		n := chunkSize
		if length < uint64(n) {
			n = int(length)
		}
		if _, err := io.ReadFull(src, buffer[:n]); err != nil {
			return err
		}
		nonce, aad := chunkParameters(header, uint32(index))
		if _, err := dst.Write(aead.Seal(nil, nonce, buffer[:n], aad)); err != nil {
			return err
		}
		length -= uint64(n)
	}
	return nil
}

func decryptChunks(src io.Reader, dst io.Writer, aead cipher.AEAD, header []byte, length uint64, evidenceKey []byte) error {
	for index := uint64(0); length > 0; index++ {
		if index >= 1<<32 {
			return errors.New("backup nonce space exhausted")
		}
		n := chunkSize
		if length < uint64(n) {
			n = int(length)
		}
		ciphertext := make([]byte, n+aead.Overhead())
		if _, err := io.ReadFull(src, ciphertext); err != nil {
			return errors.New("backup is truncated")
		}
		nonce, aad := chunkParameters(header, uint32(index))
		plain, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return errors.New("backup authentication failed")
		}
		if index == 0 {
			copy(evidenceKey, plain[:32])
			plain = plain[32:]
		}
		if _, err := dst.Write(plain); err != nil {
			return err
		}
		length -= uint64(n)
	}
	return nil
}

func chunkParameters(header []byte, index uint32) ([]byte, []byte) {
	nonce := make([]byte, 12)
	copy(nonce, header[len(magic):len(magic)+8])
	binary.BigEndian.PutUint32(nonce[8:], index)
	aad := append([]byte(nil), header...)
	return nonce, binary.BigEndian.AppendUint32(aad, index)
}

func writeNewFile(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

func validatePaths(archive, key, anchor string) error {
	paths := []string{archive, key, anchor}
	resolved := make([]string, len(paths))
	dirs := make([]string, len(paths))
	for i, path := range paths {
		if path == "" {
			return errors.New("archive, recovery key, and anchor paths are required")
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
		if err != nil {
			return err
		}
		resolved[i] = filepath.Join(parent, filepath.Base(absolute))
		dirs[i] = parent
	}
	for i := range resolved {
		for j := 0; j < i; j++ {
			if strings.EqualFold(resolved[i], resolved[j]) {
				return errors.New("backup output paths must be distinct")
			}
		}
	}
	if strings.EqualFold(dirs[0], dirs[1]) || strings.EqualFold(dirs[0], dirs[2]) {
		return errors.New("recovery key and anchor must be stored outside the archive directory")
	}
	return nil
}
