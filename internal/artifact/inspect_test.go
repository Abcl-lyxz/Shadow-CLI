package artifact

import (
	"archive/zip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func archive(t *testing.T, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "package.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, body := range entries {
		member, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRecognizesMobileArchivesWithoutExposingNames(t *testing.T) {
	for _, tc := range []struct {
		kind    string
		entries map[string]string
	}{
		{"APK", map[string]string{"AndroidManifest.xml": "manifest", "classes.dex": "dex", "secret-token.txt": "hidden"}},
		{"IPA", map[string]string{"Payload/Test.app/Info.plist": "plist", "secret-token.txt": "hidden"}},
	} {
		r, err := Inspect(archive(t, tc.entries))
		if err != nil || r.Kind != tc.kind || r.Entries != len(tc.entries) || len(r.SHA256) != 64 {
			t.Fatalf("%s: %+v %v", tc.kind, r, err)
		}
		if strings.Contains(strings.Join(r.Warnings, " "), "secret-token") {
			t.Fatal("member name leaked")
		}
	}
}

func TestRejectsUnsafeArchiveAndNonRegularInput(t *testing.T) {
	if _, err := Inspect(archive(t, map[string]string{"../escape": "x", "AndroidManifest.xml": "x", "classes.dex": "x"})); err == nil {
		t.Fatal("traversal accepted")
	}
	if _, err := Inspect(t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	path := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(archive(t, map[string]string{"AndroidManifest.xml": "x", "classes.dex": "x"}), path); err == nil {
		if _, err := Inspect(path); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}

func TestInspectsNativeTestExecutable(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"windows": "PE", "linux": "ELF", "darwin": "Mach-O"}[runtime.GOOS]
	if want == "" {
		t.Skip("native format not in supported set")
	}
	if r.Kind != want || r.Architecture == "" || len(r.Properties) == 0 {
		t.Fatalf("native result %+v", r)
	}
}
