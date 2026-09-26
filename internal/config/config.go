package config

import (
	"crypto/rand"
	"encoding/base64"
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

type Route struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	BaseURL  string `json:"base_url"`
	Protocol string `json:"protocol"`
}

type Config struct {
	Version int   `json:"version"`
	Route   Route `json:"route"`
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
	return cfg, nil
}

func Save(cfg Config) error {
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
