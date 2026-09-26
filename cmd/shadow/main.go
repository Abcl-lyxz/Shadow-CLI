package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"shadow/internal/config"
	"shadow/internal/sandbox"
	"shadow/internal/store"
	"shadow/internal/ui"
	toolinventory "shadow/sandbox"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "shadow:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return ui.Run()
	}
	switch args[0] {
	case "doctor":
		return doctor()
	case "sandbox":
		if len(args) < 3 || args[1] != "run" {
			return fmt.Errorf("usage: shadow sandbox run <command> [arguments]")
		}
		sb, err := sandbox.New("")
		if err != nil {
			return err
		}
		defer sb.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		result, err := sb.Run(ctx, args[2:], "")
		if err != nil {
			return err
		}
		fmt.Print(result.Output)
		if result.ExitCode != 0 {
			return fmt.Errorf("sandbox command exited %d", result.ExitCode)
		}
		return nil
	case "tools":
		if len(args) == 2 && args[1] == "audit" {
			return auditTools()
		}
		return fmt.Errorf("usage: shadow tools audit")
	case "data":
		return dataCommand(args[1:])
	case "help", "--help", "-h":
		fmt.Println("Shadow CLI\n\n  shadow                             Open TUI\n  shadow doctor                      Check local runtime\n  shadow sandbox run CMD             Run a command in network-disabled Docker\n  shadow tools audit                 Verify tool inventory\n  shadow data runs                   List stored runs\n  shadow data scope ID               Show the immutable run scope/action snapshot\n  shadow data test-actions ID        List test-write cleanup obligations\n  shadow data review-test-action RUN ACTION --state EVENT  Acknowledge one observed journal state\n  shadow data purge-run ID --confirm ID  Delete one run from the active database")
		return nil
	default:
		return fmt.Errorf("unknown command %q; use shadow help", args[0])
	}
}

func dataCommand(args []string) error {
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	return dataCommandAt(filepath.Join(dir, "shadow.db"), args)
}

func dataCommandAt(path string, args []string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("data store unavailable: %w", err)
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	if len(args) == 1 && args[0] == "runs" {
		runs, err := st.Runs(ctx, 100)
		if err != nil {
			return err
		}
		for _, run := range runs {
			fmt.Printf("%s  %s  %d events\n", run.ID, run.LastAt.Format(time.RFC3339), run.Events)
		}
		return nil
	}
	if len(args) == 2 && args[0] == "test-actions" && args[1] != "" {
		actions, err := st.TestActions(ctx, args[1])
		if err != nil {
			return err
		}
		for _, action := range actions {
			review := "required"
			if action.Status == store.TestActionPlanned {
				review = "not-needed"
			} else if action.ReviewedStateID == action.StateEventID && action.ReviewEventID != 0 {
				review = "acknowledged"
			}
			fmt.Printf("%d  %s  %s  %s  method=%s url-sha256=%s cleanup=%s cleanup-url-sha256=%s state-event=%d review=%s review-event=%d plan-event=%d write-event=%d cleanup-event=%d observation-event=%d\n",
				action.ID, action.Status, action.Origin, action.Resource, action.Method, action.URLSHA256, action.CleanupMethod, action.CleanupURLSHA256, action.StateEventID, review, action.ReviewEventID, action.PlannedEventID, action.WriteEventID, action.CleanupEventID, action.ObservationEventID)
		}
		fmt.Println("Review acknowledges the current journal state only; cleanup and resource removal remain unverified.")
		return nil
	}
	if len(args) == 2 && args[0] == "scope" && args[1] != "" {
		snap, err := st.RunSnapshot(ctx, args[1])
		if err != nil {
			return err
		}
		fmt.Printf("Run %s  origin=%s  actions=%d  created=%s\n", snap.RunID, snap.Origin, len(snap.Actions), snap.CreatedAt.Format(time.RFC3339))
		for _, action := range snap.Actions {
			fmt.Printf("%s  %s  url-sha256=%s  resource=%s  cleanup=%s  cleanup-url-sha256=%s\n", action.Effect, action.Method, action.URLSHA256, action.Resource, action.CleanupMethod, action.CleanupURLSHA256)
		}
		return nil
	}
	if len(args) == 5 && args[0] == "review-test-action" && args[1] != "" && args[3] == "--state" {
		actionID, idErr := strconv.ParseInt(args[2], 10, 64)
		stateID, stateErr := strconv.ParseInt(args[4], 10, 64)
		if idErr != nil || stateErr != nil || actionID <= 0 || stateID <= 0 {
			return errors.New("positive action and state event IDs required")
		}
		if err := st.ReviewTestAction(ctx, args[1], actionID, stateID); err != nil {
			return err
		}
		fmt.Printf("Reviewed action %d in run %s at state event %d. Cleanup remains unresolved.\n", actionID, args[1], stateID)
		return nil
	}
	if len(args) == 4 && args[0] == "purge-run" && args[2] == "--confirm" && args[1] != "" && args[1] == args[3] {
		if err := st.PurgeRun(ctx, args[1]); err != nil {
			return err
		}
		fmt.Printf("Run %s removed from the active database.\n", args[1])
		return nil
	}
	return errors.New("usage: shadow data runs | shadow data scope ID | shadow data test-actions ID | shadow data review-test-action RUN ACTION --state EVENT | shadow data purge-run ID --confirm ID")
}

func doctor() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	fmt.Println("Shadow CLI development build")
	fmt.Printf("Route: provider=%s model=%s protocol=%s\n", valueOr(cfg.Route.Provider, "none"), valueOr(cfg.Route.Model, "none"), valueOr(cfg.Route.Protocol, "none"))
	if cfg.Route.Provider != "" {
		if _, err := config.Key(cfg.Route.Provider); err != nil {
			fmt.Println("Credential: unavailable from OS keyring")
		} else {
			fmt.Println("Credential: present in OS keyring")
		}
	}
	sb, err := sandbox.New("")
	if err != nil {
		return err
	}
	defer sb.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := sb.Ping(ctx); err != nil {
		return fmt.Errorf("Docker Engine unavailable: %w", err)
	}
	fmt.Println("Docker Engine: available")
	if err := sb.CheckImage(ctx); err != nil {
		fmt.Println("Sandbox image: missing (build sandbox/Dockerfile)")
		return fmt.Errorf("required sandbox image %s is unavailable: %w", sandbox.DefaultImage, err)
	} else {
		fmt.Printf("Sandbox image: available (%s)\n", sandbox.DefaultImage)
	}
	fmt.Println("Release status: incomplete; see docs/CURRENT_STATUS.md")
	return nil
}

func auditTools() error {
	var tools []string
	scanner := bufio.NewScanner(strings.NewReader(toolinventory.Manifest))
	seen := map[string]bool{}
	valid := regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		if !valid.MatchString(name) {
			return fmt.Errorf("invalid tool name: %q", name)
		}
		if seen[name] {
			return fmt.Errorf("duplicate tool in manifest: %s", name)
		}
		seen[name] = true
		tools = append(tools, name)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	fmt.Printf("Tool manifest: %d distinct command names\n", len(tools))
	sb, err := sandbox.New("")
	if err != nil {
		return err
	}
	defer sb.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	script := "for name in " + strings.Join(tools, " ") + "; do path=$(command -v \"$name\" 2>/dev/null) || true; case \"$path\" in /*) resolved=$(readlink -f \"$path\"); if [ -f \"$resolved\" ] && [ -x \"$resolved\" ]; then printf 'OK %s %s\\n' \"$name\" \"$resolved\"; else printf 'MISS %s\\n' \"$name\"; fi ;; *) printf 'MISS %s\\n' \"$name\" ;; esac; done"
	result, err := sb.Run(ctx, []string{"sh", "-c", script}, "")
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("tool verification exited %d", result.ExitCode)
	}
	paths := map[string]bool{}
	missing := 0
	verified := map[string]bool{}
	for _, line := range strings.Split(result.Output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 2 && fields[0] == "MISS" {
			if !seen[fields[1]] || verified[fields[1]] {
				return fmt.Errorf("invalid tool audit result: %q", line)
			}
			verified[fields[1]] = true
			missing++
		} else if len(fields) == 3 && fields[0] == "OK" {
			if !seen[fields[1]] || verified[fields[1]] || !strings.HasPrefix(fields[2], "/") {
				return fmt.Errorf("invalid tool audit result: %q", line)
			}
			verified[fields[1]] = true
			paths[fields[2]] = true
		} else {
			return fmt.Errorf("invalid tool audit result: %q", line)
		}
	}
	fmt.Printf("Verified distinct executable paths: %d; missing: %d\n", len(paths), missing)
	if len(verified) != len(tools) || missing > 0 || len(paths) < 300 {
		return fmt.Errorf("release gate unmet: 300 distinct available tools required")
	}
	return nil
}

func valueOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
