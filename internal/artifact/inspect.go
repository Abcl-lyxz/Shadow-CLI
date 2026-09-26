// Package artifact performs bounded, read-only identification of local binaries.
// It never extracts archive members or executes content from an attachment.
package artifact

import (
	"archive/zip"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const MaxFileBytes int64 = 512 << 20

type Result struct {
	Kind         string     `json:"kind"`
	SHA256       string     `json:"sha256"`
	Bytes        int64      `json:"bytes"`
	Architecture string     `json:"architecture,omitempty"`
	Entries      int        `json:"entries,omitempty"`
	Properties   []Property `json:"properties,omitempty"`
	Warnings     []string   `json:"warnings,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Inspect accepts one regular file. Archive paths are counted but never
// extracted or returned, because package member names may be sensitive.
func Inspect(path string) (Result, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return Result{}, err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxFileBytes {
		return Result{}, errors.New("artifact must be a regular file no larger than 512 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() > MaxFileBytes || !os.SameFile(st, opened) {
		return Result{}, errors.New("artifact changed while opening or is not a bounded regular file")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return Result{}, err
	}
	if n > MaxFileBytes || n != st.Size() {
		return Result{}, errors.New("artifact changed during inspection or exceeds size limit")
	}
	r := Result{SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: n}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Result{}, err
	}
	var magic [8]byte
	_, _ = io.ReadFull(f, magic[:])
	switch {
	case string(magic[:4]) == "PK\x03\x04":
		return inspectZip(f, n, r)
	case string(magic[:4]) == "\x7fELF":
		e, err := elf.NewFile(f)
		if err != nil {
			return Result{}, fmt.Errorf("invalid ELF: %w", err)
		}
		defer e.Close()
		r.Kind, r.Architecture = "ELF", e.Machine.String()
		r.Properties = append(r.Properties, Property{"elf_type", e.Type.String()})
		stack, relro := "unknown", "absent"
		for _, prog := range e.Progs {
			if prog.Type == elf.PT_GNU_STACK {
				if prog.Flags&elf.PF_X != 0 {
					stack = "executable"
				} else {
					stack = "non-executable"
				}
			}
			if prog.Type == elf.PT_GNU_RELRO {
				relro = "present"
			}
		}
		r.Properties = append(r.Properties, Property{"gnu_stack", stack}, Property{"gnu_relro_segment", relro})
	case string(magic[:2]) == "MZ":
		p, err := pe.NewFile(f)
		if err != nil {
			return Result{}, fmt.Errorf("invalid PE: %w", err)
		}
		defer p.Close()
		r.Kind, r.Architecture = "PE", fmt.Sprintf("0x%04x", p.Machine)
		var flags uint16
		switch o := p.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			flags = o.DllCharacteristics
		case *pe.OptionalHeader64:
			flags = o.DllCharacteristics
		}
		r.Properties = append(r.Properties, Property{"dynamic_base_flag", presence(flags&0x0040 != 0)}, Property{"nx_compatible_flag", presence(flags&0x0100 != 0)})
	default:
		if fat, err := macho.NewFatFile(f); err == nil {
			r.Kind = "Mach-O universal"
			for _, a := range fat.Arches {
				if r.Architecture != "" {
					r.Architecture += ","
				}
				r.Architecture += a.Cpu.String()
			}
			fat.Close()
		} else if m, err := macho.NewFile(f); err == nil {
			r.Kind, r.Architecture = "Mach-O", m.Cpu.String()
			m.Close()
			r.Properties = append(r.Properties, Property{"mh_pie_flag", presence(m.Flags&0x200000 != 0)})
		} else {
			return Result{}, errors.New("unsupported or malformed artifact")
		}
	}
	r.Warnings = []string{"static metadata only; properties are not vulnerability or runtime mitigation proof"}
	return r, nil
}

func presence(ok bool) string {
	if ok {
		return "present"
	}
	return "absent"
}

func inspectZip(f *os.File, n int64, r Result) (Result, error) {
	z, err := zip.NewReader(f, n)
	if err != nil {
		return Result{}, fmt.Errorf("invalid ZIP: %w", err)
	}
	if len(z.File) > 10000 {
		return Result{}, errors.New("archive has too many entries")
	}
	var total uint64
	var manifest, dex, appInfo bool
	for _, member := range z.File {
		name := strings.ReplaceAll(member.Name, "\\", "/")
		if strings.HasPrefix(name, "/") || strings.Contains("/"+name+"/", "/../") || filepath.IsAbs(name) || member.Mode()&os.ModeSymlink != 0 {
			return Result{}, errors.New("archive has unsafe member path or symlink")
		}
		if member.UncompressedSize64 > 1<<30 {
			return Result{}, errors.New("archive member exceeds size limit")
		}
		total += member.UncompressedSize64
		if total > 2<<30 {
			return Result{}, errors.New("archive expands beyond size limit")
		}
		if member.CompressedSize64 > 0 && member.UncompressedSize64/member.CompressedSize64 > 1000 {
			return Result{}, errors.New("archive expansion ratio exceeds limit")
		}
		if name == "AndroidManifest.xml" {
			manifest = true
		}
		if name == "classes.dex" {
			dex = true
		}
		if strings.HasPrefix(name, "Payload/") && strings.HasSuffix(name, ".app/Info.plist") {
			appInfo = true
		}
	}
	r.Entries = len(z.File)
	switch {
	case manifest && dex:
		r.Kind = "APK"
	case appInfo:
		r.Kind = "IPA"
	default:
		return Result{}, errors.New("ZIP lacks APK or IPA structure")
	}
	r.Warnings = []string{"format and structure only; no code execution or vulnerability claim"}
	return r, nil
}
