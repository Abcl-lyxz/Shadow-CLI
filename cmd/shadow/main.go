package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"shadow/internal/artifact"
	"shadow/internal/backup"
	"shadow/internal/broker"
	"shadow/internal/config"
	"shadow/internal/plugin"
	"shadow/internal/policy"
	"shadow/internal/report"
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
		if len(args) >= 4 && args[len(args)-2] == "--data-dir" {
			sub := args[1]
			if sub != "create-observation" && sub != "findings" && sub != "review-finding" {
				return errors.New("--data-dir is supported only for finding creation, listing, and review")
			}
			return dataCommandAtProtected(filepath.Join(args[len(args)-1], "shadow.db"), args[1:len(args)-2], true)
		}
		if len(args) == 4 && args[1] == "retention-set" && args[2] == "--days" {
			days, err := strconv.Atoi(args[3])
			if err != nil {
				return errors.New("automatic retention days must be a whole number")
			}
			if days < 1 || days > 365 {
				return errors.New("automatic retention days must be between 1 and 365")
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			cfg.AutoRetentionDays = days
			if _, err := cfg.RetentionDays(); err != nil {
				return err
			}
			if err := config.Save(cfg); err != nil {
				return err
			}
			fmt.Printf("Automatic retention set to %d days; applied at the next TUI start.\n", days)
			return nil
		}
		return dataCommand(args[1:])
	case "policy":
		return policyCommand(args[1:])
	case "target":
		return targetCommand(args[1:])
	case "report":
		return reportCommand(args[1:])
	case "artifact":
		return artifactCommand(args[1:])
	case "plugin":
		return pluginCommand(args[1:])
	case "help", "--help", "-h":
		fmt.Println("Shadow CLI\n\n  shadow                             Open TUI\n  shadow doctor                      Check local runtime\n  shadow sandbox run CMD             Run a command in network-disabled Docker\n  shadow tools audit                 Verify tool inventory\n  shadow policy validate FILE --target ORIGIN  Check rules and print digest\n  shadow policy approve FILE --target ORIGIN --confirm DIGEST --out FILE  Sign a local rule approval\n  shadow policy verify FILE --target ORIGIN --approval FILE  Verify a local rule approval\n  shadow target read RULES --target ORIGIN --approval FILE --action ID --data-dir DIR  Read one approved action\n  shadow target audit --data-dir DIR  Audit isolated target evidence and provenance\n  shadow data runs                   List stored runs\n  shadow data audit-evidence         Check all local evidence/observation pairs\n  shadow data audit-provenance       Check independent event/evidence chain\n  shadow data backup FILE --key-file KEY --anchor ANCHOR  Create encrypted recovery bundle\n  shadow data restore FILE --key-file KEY --anchor ANCHOR  Restore into an empty data location\n  shadow data retention-set --days N  Set TUI-start automatic retention (1-365 days)\n  shadow data retention-plan --days N  Count old runs and cleanup blockers\n  shadow data prune-expired --days N --confirm  Purge eligible old runs\n  shadow data scope ID               Show the immutable run scope/action snapshot\n  shadow data test-actions ID        List test-write cleanup obligations\n  shadow data review-test-action RUN ACTION --state EVENT  Acknowledge one observed journal state\n  shadow data purge-run ID --confirm ID  Delete a run after cleanup is resolved")
		fmt.Println("  shadow data review-finding RUN ID --poc STATUS --confidence LEVEL [--duplicate ID] [--cvss VECTOR]  Record metadata-only review")
		fmt.Println("  shadow data create-observation RUN EVENT [--data-dir DIR]  Create an evidence-backed response observation")
		fmt.Println("  shadow data findings RUN [--data-dir DIR]  List finding metadata")
		fmt.Println("  shadow report preview RUN [--details FILE] [--data-dir DIR]  Show reviewed report and digest")
		fmt.Println("  shadow report export RUN --format html|pdf|json|sarif --confirm DIGEST --out FILE [--details FILE] [--data-dir DIR]  Export reviewed report")
		fmt.Println("  shadow artifact inspect FILE [--plugin MANIFEST --trust-key PUBKEY]  Read-only APK/IPA/PE/Mach-O/ELF inspection")
		fmt.Println("  shadow plugin verify MANIFEST --trust-key PUBKEY  Verify a passive static magic plugin")
		return nil
	default:
		return fmt.Errorf("unknown command %q; use shadow help", args[0])
	}
}

func pluginCommand(args []string) error {
	if len(args) != 4 || args[0] != "verify" || args[2] != "--trust-key" {
		return errors.New("usage: shadow plugin verify MANIFEST --trust-key PUBKEY")
	}
	p, err := plugin.Load(args[1], args[3])
	if err != nil {
		return err
	}
	fmt.Printf("Verified %s v%s (%s); payload SHA-256 %s; capability %s\n", p.Manifest.ID, p.Manifest.Version, p.Manifest.Purpose, p.SHA256, p.Manifest.Capability)
	return nil
}

func artifactCommand(args []string) error {
	if len(args) != 2 && !(len(args) == 6 && args[2] == "--plugin" && args[4] == "--trust-key") || len(args) < 2 || args[0] != "inspect" {
		return errors.New("usage: shadow artifact inspect FILE [--plugin MANIFEST --trust-key PUBKEY]")
	}
	result, err := artifact.Inspect(args[1])
	if err != nil {
		return err
	}
	output := struct {
		artifact.Result
		PluginID      string   `json:"plugin_id,omitempty"`
		PluginSHA256  string   `json:"plugin_sha256,omitempty"`
		PluginMatches []string `json:"plugin_matches,omitempty"`
	}{Result: result}
	if len(args) == 6 {
		p, err := plugin.Load(args[3], args[5])
		if err != nil {
			return err
		}
		f, err := os.Open(args[1])
		if err != nil {
			return err
		}
		prefix, err := io.ReadAll(io.LimitReader(f, plugin.PrefixBytes))
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		output.PluginID, output.PluginSHA256, output.PluginMatches = p.Manifest.ID, p.SHA256, p.MatchPrefix(prefix)
	}
	return json.NewEncoder(os.Stdout).Encode(output)
}

func policyCommand(args []string) error {
	if len(args) < 4 || args[2] != "--target" {
		return errors.New("usage: shadow policy validate FILE --target ORIGIN | approve FILE --target ORIGIN --confirm DIGEST --out FILE | verify FILE --target ORIGIN --approval FILE")
	}
	file, err := os.Open(args[1])
	if err != nil {
		return err
	}
	defer file.Close()
	plan, err := policy.ParseTrustedRules(file, args[3])
	if err != nil {
		return err
	}
	digest, err := policy.TrustedRulesDigest(plan)
	if err != nil {
		return err
	}
	switch args[0] {
	case "validate":
		if len(args) != 4 {
			return errors.New("usage: shadow policy validate FILE --target ORIGIN")
		}
		fmt.Printf("Trusted rules valid for %s: %d exact actions; SHA-256 %s. No network access granted.\n", plan.Origin, len(plan.Actions), digest)
		for _, rule := range plan.Actions {
			if rule.Method == "GET" && rule.Effect == policy.EffectRead {
				fmt.Printf("GET/read action ID: %s\n", broker.ReadActionID(rule))
			}
		}
		return nil
	case "approve":
		if len(args) != 8 || args[4] != "--confirm" || args[6] != "--out" || subtle.ConstantTimeCompare([]byte(args[5]), []byte(digest)) != 1 {
			return errors.New("approval requires the exact validated digest and --out FILE")
		}
		key, err := config.PolicyApprovalKey(true)
		if err != nil {
			return err
		}
		approval, err := policy.SignRuleApproval(plan, key, time.Now())
		if err != nil {
			return err
		}
		encoded, err := json.MarshalIndent(approval, "", "  ")
		if err != nil {
			return err
		}
		out, err := os.OpenFile(args[7], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if _, err := out.Write(append(encoded, '\n')); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		fmt.Printf("Local rule approval written to %s; expires %s. Agent and TUI target access remain disabled.\n", args[7], approval.ExpiresAt)
		return nil
	case "verify":
		if len(args) != 6 || args[4] != "--approval" {
			return errors.New("usage: shadow policy verify FILE --target ORIGIN --approval FILE")
		}
		approvalFile, err := os.Open(args[5])
		if err != nil {
			return err
		}
		defer approvalFile.Close()
		approval, err := policy.ParseRuleApproval(approvalFile)
		if err != nil {
			return err
		}
		key, err := config.PolicyApprovalKey(false)
		if err != nil {
			return err
		}
		if err := policy.VerifyRuleApproval(plan, approval, key, time.Now()); err != nil {
			return err
		}
		fmt.Printf("Local rule approval valid for %s; expires %s. Agent and TUI target access remain disabled.\n", plan.Origin, approval.ExpiresAt)
		return nil
	default:
		return errors.New("unknown policy command")
	}
}

func targetCommand(args []string) error {
	if len(args) == 3 && args[0] == "audit" && args[1] == "--data-dir" {
		path := filepath.Join(args[2], "shadow.db")
		if err := dataCommandAtProtected(path, []string{"audit-evidence"}, true); err != nil {
			return err
		}
		return dataCommandAtProtected(path, []string{"audit-provenance"}, true)
	}
	if len(args) != 10 || args[0] != "read" || args[2] != "--target" || args[4] != "--approval" || args[6] != "--action" || args[8] != "--data-dir" {
		return errors.New("usage: shadow target read RULES --target ORIGIN --approval FILE --action ID --data-dir DIR | target audit --data-dir DIR")
	}
	rulesFile, err := os.Open(args[1])
	if err != nil {
		return err
	}
	defer rulesFile.Close()
	rules, err := policy.ParseTrustedRules(rulesFile, args[3])
	if err != nil {
		return err
	}
	for _, action := range rules.Actions {
		if action.Method != "GET" || action.Effect != policy.EffectRead {
			return errors.New("target read accepts only exact GET/read rules")
		}
	}
	approvalFile, err := os.Open(args[5])
	if err != nil {
		return err
	}
	defer approvalFile.Close()
	approval, err := policy.ParseRuleApproval(approvalFile)
	if err != nil {
		return err
	}
	key, err := config.PolicyApprovalKey(false)
	if err != nil {
		return err
	}
	verified, err := policy.VerifyApprovedRules(rules, approval, key, time.Now())
	if err != nil {
		return err
	}
	granted := false
	for _, action := range verified.Actions() {
		if broker.ReadActionID(action) == args[7] {
			granted = true
			break
		}
	}
	if !granted {
		return errors.New("read action ID is not in the approved document")
	}
	if err := os.MkdirAll(args[9], 0700); err != nil {
		return err
	}
	path := filepath.Join(args[9], "shadow.db")
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hasEvidence, err := st.HasEvidence(ctx)
	if err != nil {
		return err
	}
	evidenceKey, err := config.EvidenceKey(!hasEvidence)
	if err != nil {
		return err
	}
	if err := st.ConfigureEvidenceKey(ctx, evidenceKey); err != nil {
		return err
	}
	ledger, head := store.DefaultProvenancePaths(path)
	if err := st.EnableProvenance(ctx, ledger, head); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	days, err := cfg.RetentionDays()
	if err != nil {
		return err
	}
	if _, err := st.PruneExpired(ctx, time.Now(), days); err != nil {
		return err
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	runID := hex.EncodeToString(random[:])
	if err := st.StartApprovedRun(ctx, runID, verified); err != nil {
		return err
	}
	network, err := broker.NewApprovedReadNetwork(ctx, st, runID, verified)
	if err != nil {
		return err
	}
	observation, eventID, err := network.ReadRecorded(ctx, args[7])
	if err != nil {
		return fmt.Errorf("run %s: %w", runID, err)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		RunID       string             `json:"run_id"`
		EventID     int64              `json:"event_id"`
		Observation broker.Observation `json:"observation"`
	}{runID, eventID, observation})
}

func dataCommand(args []string) error {
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	return dataCommandAtProtected(filepath.Join(dir, "shadow.db"), args, true)
}

func dataCommandAt(path string, args []string) error {
	return dataCommandAtProtected(path, args, false)
}

func dataCommandAtProtected(path string, args []string, provenance bool) error {
	if len(args) == 6 && args[0] == "restore" && args[2] == "--key-file" && args[4] == "--anchor" {
		if err := backup.Restore(context.Background(), args[1], args[3], args[5], path, config.InstallEvidenceKey); err != nil {
			return err
		}
		fmt.Println("Recovery bundle restored. Verify with: shadow data audit-evidence")
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("data store unavailable: %w", err)
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	if provenance {
		hasEvidence, err := st.HasEvidence(ctx)
		if err != nil {
			return err
		}
		key, err := config.EvidenceKey(!hasEvidence)
		if err != nil {
			return err
		}
		if err := st.ConfigureEvidenceKey(ctx, key); err != nil {
			return err
		}
		ledger, head := store.DefaultProvenancePaths(path)
		if err := st.EnableProvenance(ctx, ledger, head); err != nil {
			return err
		}
	}
	if (len(args) == 3 && args[0] == "retention-plan" && args[1] == "--days") || (len(args) == 4 && args[0] == "prune-expired" && args[1] == "--days" && args[3] == "--confirm") {
		days, err := strconv.Atoi(args[2])
		if err != nil {
			return errors.New("retention days must be a whole number")
		}
		if args[0] == "retention-plan" {
			result, err := st.RetentionPlan(ctx, time.Now(), days)
			if err != nil {
				return err
			}
			fmt.Printf("Retention plan: %d eligible, %d blocked by unresolved cleanup. No data removed.\n", result.Eligible, result.Blocked)
			return nil
		}
		result, err := st.PruneExpired(ctx, time.Now(), days)
		if err != nil {
			return err
		}
		fmt.Printf("Retention prune: %d runs removed, %d blocked by unresolved cleanup. Backups are unchanged.\n", result.Purged, result.Blocked)
		return nil
	}
	if len(args) == 6 && args[0] == "backup" && args[2] == "--key-file" && args[4] == "--anchor" {
		hasEvidence, err := st.HasEvidence(ctx)
		if err != nil {
			return err
		}
		key, err := config.EvidenceKey(!hasEvidence)
		if err != nil {
			return err
		}
		if err := backup.Create(ctx, st, args[1], args[3], args[5], key); err != nil {
			return err
		}
		fmt.Println("Encrypted recovery bundle created. Store its recovery key and anchor separately from the archive.")
		return nil
	}
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
	if len(args) == 3 && args[0] == "create-observation" {
		eventID, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil || eventID <= 0 {
			return errors.New("positive evidence event ID required")
		}
		findingID, err := createObservationFinding(ctx, st, args[1], eventID)
		if err != nil {
			return err
		}
		fmt.Printf("Response observation finding %d in run %s. This does not verify a vulnerability.\n", findingID, args[1])
		return nil
	}
	if len(args) == 2 && args[0] == "findings" {
		findings, err := st.Findings(ctx, args[1])
		if err != nil {
			return err
		}
		reviews, err := st.FindingReviews(ctx, args[1])
		if err != nil {
			return err
		}
		for _, f := range findings {
			poc := "unreviewed"
			reviewID := int64(0)
			if r, ok := reviews[f.ID]; ok {
				poc = r.PoCStatus
				reviewID = r.ReviewEventID
			}
			fmt.Printf("finding=%d claim=%s status=%s source=%d repeat=%d review=%d poc=%s\n", f.ID, f.ClaimType, f.Status, f.SourceEventID, f.ReproductionEventID, reviewID, poc)
		}
		return nil
	}
	if len(args) == 1 && args[0] == "audit-evidence" {
		hasEvidence, err := st.HasEvidence(ctx)
		if err != nil {
			return err
		}
		var key []byte
		if hasEvidence {
			key, err = config.EvidenceKey(false)
			if err != nil {
				return err
			}
		}
		report, err := st.AuditEvidence(ctx, key)
		if err != nil {
			return err
		}
		fmt.Printf("Evidence audit: %d pairs, %d valid, %d invalid.\n", report.Total, report.Valid, report.Invalid)
		if report.Invalid != 0 {
			return errors.New("evidence integrity check failed; check the original key and database")
		}
		return nil
	}
	if len(args) == 1 && args[0] == "audit-provenance" {
		if !provenance {
			return errors.New("independent provenance is unavailable in this data context")
		}
		if err := st.AuditProvenance(ctx); err != nil {
			return err
		}
		fmt.Println("Provenance audit: active events and evidence match the authenticated append-only chain and independent head. Initial enrollment cannot attest earlier history.")
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
	if len(args) >= 7 && args[0] == "review-finding" && args[2] != "" && args[3] == "--poc" && args[5] == "--confidence" {
		id, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil || id <= 0 {
			return errors.New("positive finding ID required")
		}
		var duplicate int64
		var vector string
		seen := map[string]bool{}
		for i := 7; i < len(args); i += 2 {
			if i+1 >= len(args) || seen[args[i]] {
				return errors.New("invalid or repeated review option")
			}
			seen[args[i]] = true
			switch args[i] {
			case "--duplicate":
				duplicate, err = strconv.ParseInt(args[i+1], 10, 64)
				if err != nil {
					return err
				}
			case "--cvss":
				vector = args[i+1]
			default:
				return errors.New("unknown finding review option")
			}
		}
		r, err := st.ReviewFinding(ctx, args[1], id, args[4], args[6], duplicate, vector)
		if err != nil {
			return err
		}
		fmt.Printf("Finding %d review event %d recorded; security impact remains unverified.\n", id, r.ReviewEventID)
		return nil
	}
	if len(args) == 4 && args[0] == "purge-run" && args[2] == "--confirm" && args[1] != "" && args[1] == args[3] {
		if err := st.PurgeRun(ctx, args[1]); err != nil {
			return err
		}
		fmt.Printf("Run %s removed from the active database.\n", args[1])
		return nil
	}
	return errors.New("usage: shadow data runs | shadow data audit-evidence | shadow data audit-provenance | shadow data backup FILE --key-file KEY --anchor ANCHOR | shadow data restore FILE --key-file KEY --anchor ANCHOR | shadow data retention-plan --days N | shadow data prune-expired --days N --confirm | shadow data scope ID | shadow data test-actions ID | shadow data review-test-action RUN ACTION --state EVENT | shadow data review-finding RUN ID --poc STATUS --confidence LEVEL [--duplicate ID] [--cvss VECTOR] | shadow data purge-run ID --confirm ID")
}

func createObservationFinding(ctx context.Context, st *store.Store, runID string, eventID int64) (int64, error) {
	if runID == "" || eventID <= 0 {
		return 0, errors.New("run and evidence event required")
	}
	summary, raw, err := st.ValidatedObservation(ctx, runID, eventID)
	if err != nil {
		return 0, err
	}
	if raw.Method != "GET" {
		return 0, errors.New("response observation requires a recorded GET")
	}
	findings, err := st.Findings(ctx, runID)
	if err != nil {
		return 0, err
	}
	for _, f := range findings {
		if f.ClaimType == store.ClaimResponseObservation && f.SourceEventID == eventID {
			return f.ID, nil
		}
	}
	return st.CreateFinding(ctx, runID, "Recorded HTTP response", summary.Origin, store.ClaimResponseObservation, eventID)
}

func reportCommand(args []string) error {
	var dir string
	if len(args) >= 4 && args[len(args)-2] == "--data-dir" {
		dir = args[len(args)-1]
		args = args[:len(args)-2]
	} else {
		var err error
		dir, err = config.Dir()
		if err != nil {
			return err
		}
	}
	path := filepath.Join(dir, "shadow.db")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("data store unavailable: %w", err)
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	has, err := st.HasEvidence(ctx)
	if err != nil {
		return err
	}
	if !has {
		return errors.New("report requires encrypted source evidence")
	}
	key, err := config.EvidenceKey(false)
	if err != nil {
		return err
	}
	if err := st.ConfigureEvidenceKey(ctx, key); err != nil {
		return err
	}
	ledger, head := store.DefaultProvenancePaths(path)
	if err := st.EnableProvenance(ctx, ledger, head); err != nil {
		return err
	}
	if len(args) < 2 {
		return errors.New("usage: shadow report preview RUN [--details FILE] | export RUN --format html|pdf|json|sarif --confirm DIGEST --out FILE [--details FILE]")
	}
	preview := args[0] == "preview" && (len(args) == 2 || len(args) == 4 && args[2] == "--details")
	export := args[0] == "export" && (len(args) == 8 || len(args) == 10 && args[8] == "--details") && args[2] == "--format" && args[4] == "--confirm" && args[6] == "--out"
	if !preview && !export {
		return errors.New("usage: shadow report preview RUN [--details FILE] | export RUN --format html|pdf|json|sarif --confirm DIGEST --out FILE [--details FILE]")
	}
	doc, digest, err := report.Prepare(ctx, st, args[1])
	if err != nil {
		return err
	}
	detailFile := ""
	if preview && len(args) == 4 {
		detailFile = args[3]
	}
	if export && len(args) == 10 {
		detailFile = args[9]
	}
	if detailFile != "" {
		f, err := os.Open(detailFile)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, (64<<10)+1))
		closeErr := f.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		details, err := report.ParseDetails(data)
		if err != nil {
			return err
		}
		doc, digest, err = report.AttachDetails(doc, details)
		if err != nil {
			return err
		}
	}
	if preview {
		fmt.Printf("Reviewed report: run=%s findings=%d digest=%s\n", doc.RunID, len(doc.Findings), digest)
		if detailFile != "" {
			b, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(b))
			return nil
		}
		for _, f := range doc.Findings {
			fmt.Printf("finding=%d claim=%s status=%s poc=%s confidence=%s source=%d repeat=%d duplicate=%d cvss=%s\n", f.ID, f.ClaimType, f.Status, f.PoCStatus, f.Confidence, f.SourceEventID, f.ReproductionEventID, f.DuplicateOf, f.CVSSVector)
		}
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(digest), []byte(args[5])) != 1 {
		return errors.New("report changed since preview; review the new digest")
	}
	b, err := report.Render(doc, args[3])
	if err != nil {
		return err
	}
	f, err := os.OpenFile(args[7], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	fmt.Printf("Reviewed %s report written: %s\n", args[3], args[7])
	return nil
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
