package config

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	keyring "github.com/zalando/go-keyring"
)

const keyringService = "shadow-cli"
const evidenceKeyService = "shadow-cli-evidence"
const evidenceKeyAccount = "master-v1"
const fixtureCredentialService = "shadow-cli-fixture-target-v1"
const policyApprovalService = "shadow-cli-policy-approval-v1"
const policyApprovalAccount = "local-operator-v1"

// PolicyApprovalKey is separate from provider, target, and evidence keys.
// Creation is permitted only during an explicit local operator approval.
func PolicyApprovalKey(allowCreate bool) ([]byte, error) {
	encoded, err := keyring.Get(policyApprovalService, policyApprovalAccount)
	if errors.Is(err, keyring.ErrNotFound) {
		if !allowCreate {
			return nil, errors.New("local policy approval key is missing")
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := keyring.Set(policyApprovalService, policyApprovalAccount, base64.RawStdEncoding.EncodeToString(key)); err != nil {
			return nil, fmt.Errorf("store local policy approval key: %w", err)
		}
		return key, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read local policy approval key: %w", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("local policy approval key is invalid")
	}
	return key, nil
}

// FixtureCredentialRef is opaque to agents and bound to one run creation,
// origin, and authentication action. Its service is separate from provider keys.
func FixtureCredentialRef(runID, origin, actionID, startedAt string) (string, error) {
	if runID == "" || origin == "" || startedAt == "" || len(actionID) != 64 {
		return "", errors.New("invalid fixture credential binding")
	}
	if _, err := hex.DecodeString(actionID); err != nil {
		return "", errors.New("invalid fixture credential action")
	}
	sum := sha256.Sum256([]byte(runID + "\x00" + origin + "\x00" + actionID + "\x00" + startedAt))
	return hex.EncodeToString(sum[:]), nil
}

func SetFixtureCredential(runID, origin, actionID, startedAt, secret string) error {
	ref, err := FixtureCredentialRef(runID, origin, actionID, startedAt)
	if err != nil || secret == "" || len(secret) > 4096 {
		return errors.New("invalid fixture credential")
	}
	return keyring.Set(fixtureCredentialService, ref, secret)
}

func FixtureCredential(runID, origin, actionID, startedAt string) (string, error) {
	ref, err := FixtureCredentialRef(runID, origin, actionID, startedAt)
	if err != nil {
		return "", err
	}
	secret, err := keyring.Get(fixtureCredentialService, ref)
	if err != nil || secret == "" || len(secret) > 4096 {
		return "", errors.New("fixture credential unavailable")
	}
	return secret, nil
}

type Route struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	BaseURL  string `json:"base_url"`
	Protocol string `json:"protocol"`
}

type Config struct {
	Version           int   `json:"version"`
	Route             Route `json:"route"`
	AutoRetentionDays int   `json:"auto_retention_days,omitempty"`
}

const DefaultAutoRetentionDays = 90

func (c Config) RetentionDays() (int, error) {
	if c.AutoRetentionDays == 0 {
		return DefaultAutoRetentionDays, nil
	}
	if c.AutoRetentionDays < 1 || c.AutoRetentionDays > 365 {
		return 0, errors.New("automatic retention days must be between 1 and 365")
	}
	return c.AutoRetentionDays, nil
}

func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "shadow"), nil
}

func Load() (Config, error) {
	dir, err := Dir()
	if err != nil {
		return Config{}, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if errors.Is(err, os.ErrNotExist) {
		return Config{Version: 1}, nil
	}
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.Version != 1 {
		return Config{}, errors.New("unsupported config version")
	}
	if _, err := cfg.RetentionDays(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Save(cfg Config) error {
	if _, err := cfg.RetentionDays(); err != nil {
		return err
	}
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	cfg.Version = 1
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "config.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func SetKey(provider, value string) error {
	if strings.TrimSpace(provider) == "" || strings.TrimSpace(value) == "" {
		return errors.New("provider and key are required")
	}
	return keyring.Set(keyringService, provider, value)
}

func Key(provider string) (string, error) {
	if strings.TrimSpace(provider) == "" {
		return "", errors.New("no provider selected")
	}
	return keyring.Get(keyringService, provider)
}

// EvidenceKey returns the persistent raw-evidence key. Creation is allowed
// only when the caller has confirmed that no encrypted evidence exists.
func EvidenceKey(allowCreate bool) ([]byte, error) {
	encoded, err := keyring.Get(evidenceKeyService, evidenceKeyAccount)
	if errors.Is(err, keyring.ErrNotFound) {
		if !allowCreate {
			return nil, errors.New("evidence key missing from OS keyring; restore the original keyring before opening existing evidence")
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := keyring.Set(evidenceKeyService, evidenceKeyAccount, base64.RawStdEncoding.EncodeToString(key)); err != nil {
			return nil, fmt.Errorf("store evidence key in OS keyring: %w", err)
		}
		return key, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read evidence key from OS keyring: %w", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid evidence key in OS keyring")
	}
	return key, nil
}

// InstallEvidenceKey is used only after a recovery bundle has been decrypted
// and audited. A different existing key is never replaced.
func InstallEvidenceKey(key []byte) error {
	if len(key) != 32 {
		return errors.New("evidence key must be 32 bytes")
	}
	existing, err := keyring.Get(evidenceKeyService, evidenceKeyAccount)
	if err == nil {
		decoded, decodeErr := base64.RawStdEncoding.DecodeString(existing)
		if decodeErr != nil || len(decoded) != 32 || subtle.ConstantTimeCompare(decoded, key) != 1 {
			return errors.New("a different evidence key is already stored in the OS keyring")
		}
		return nil
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("read evidence key from OS keyring: %w", err)
	}
	if err := keyring.Set(evidenceKeyService, evidenceKeyAccount, base64.RawStdEncoding.EncodeToString(key)); err != nil {
		return fmt.Errorf("store restored evidence key in OS keyring: %w", err)
	}
	return nil
}
