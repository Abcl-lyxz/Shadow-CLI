package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		return
	}
	for {
		path := filepath.Join(dir, "docs", "CURRENT_STATUS.md")
		if _, err := os.Stat(filepath.Join(dir, "AGENTS.md")); err == nil {
			if body, err := os.ReadFile(path); err == nil {
				s := strings.TrimSpace(string(body))
				if len([]rune(s)) > 3500 {
					head := []rune(s)
					s = string(head[:2200])
					if end := strings.LastIndex(s, "\n"); end > 0 {
						s = s[:end]
					}
					if start := strings.Index(string(body), "## Next concrete task"); start >= 0 {
						next := string(body[start:])
						if end := strings.Index(next, "## Resume commands"); end >= 0 {
							next = next[:end]
						}
						s += "\n\n" + strings.TrimSpace(next)
					}
					s += "\n[Read docs/CURRENT_STATUS.md for verification and remaining gates.]"
				}
				fmt.Print(s)
				return
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return
		}
		dir = parent
	}
}
