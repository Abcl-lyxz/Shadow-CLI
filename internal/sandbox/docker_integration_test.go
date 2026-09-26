package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerIsolation(t *testing.T) {
	image := os.Getenv("SHADOW_TEST_IMAGE")
	if image == "" {
		t.Skip("set SHADOW_TEST_IMAGE to an existing local Linux image")
	}
	r, err := New(image)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := r.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(path, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := r.Run(ctx, []string{"sh", "-c", "id -u; cat /workspace/input.txt; echo changed > /workspace/input.txt; echo changed > /etc/shadow"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Output, "65534") || !strings.Contains(result.Output, "original") {
		t.Fatalf("unexpected sandbox output: %q", result.Output)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "original" {
		t.Fatalf("host mount changed: %q, %v", content, err)
	}
	if !strings.Contains(result.Output, "Read-only file system") && !strings.Contains(result.Output, "Permission denied") {
		t.Fatalf("expected write denial: %q", result.Output)
	}
}
