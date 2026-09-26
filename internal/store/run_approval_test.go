package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"shadow/internal/policy"
)

func TestApprovedRunBindsRuleDigestAndCannotBeAddedLater(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC().Truncate(time.Second)
	rules := policy.TrustedRules{Version: 1, Origin: "http://127.0.0.1:47123", Actions: []policy.ActionRule{{URL: "http://127.0.0.1:47123/safe", Method: "GET", Effect: policy.EffectRead}}}
	key := bytes.Repeat([]byte{0x72}, 32)
	approval, err := policy.SignRuleApproval(rules, key, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := policy.VerifyApprovedRules(rules, approval, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.StartApprovedRun(ctx, "approved", verified); err != nil {
		t.Fatal(err)
	}
	id, digest, expiry, err := st.RunRuleApproval(ctx, "approved")
	if err != nil || id != verified.ApprovalID() || digest != verified.RulesSHA256() || !expiry.Equal(verified.ExpiresAt()) {
		t.Fatalf("run approval binding: %s %s %v %v", id, digest, expiry, err)
	}
	snapshot, err := st.RunSnapshot(ctx, "approved")
	if err != nil || !snapshot.AllowsAction(rules.Actions[0]) {
		t.Fatalf("approved grant missing: %#v %v", snapshot, err)
	}
	if err := st.RecordApprovedReadDecision(ctx, snapshot, rules.Actions[0].URL, true, "wrong", verified.RulesSHA256()); err == nil {
		t.Fatal("wrong approval signed a network decision")
	}
	if err := st.RecordApprovedReadDecision(ctx, snapshot, rules.Actions[0].URL, true, verified.ApprovalID(), verified.RulesSHA256()); err != nil {
		t.Fatalf("valid approved read decision: %v", err)
	}
	if err := st.StartApprovedRun(ctx, "approved", verified); err == nil {
		t.Fatal("existing run received another approval")
	}
	if err := st.StartApprovedRun(ctx, "zero", policy.VerifiedRules{}); err == nil {
		t.Fatal("zero verified rules started a run")
	}
	scope, _ := policy.FromTarget(rules.Origin)
	if err := st.StartRun(ctx, "ordinary", scope, rules.Actions); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := st.RunRuleApproval(ctx, "ordinary"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("ordinary run gained an approval: %v", err)
	}
	ordinary, err := st.RunSnapshot(ctx, "ordinary")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordApprovedReadDecision(ctx, ordinary, rules.Actions[0].URL, true, verified.ApprovalID(), verified.RulesSHA256()); err == nil {
		t.Fatal("ordinary run gained an approved read decision")
	}
	if _, err := st.db.ExecContext(ctx, "DELETE FROM run_rule_approvals WHERE run_id=?", "approved"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "INSERT INTO run_rule_approvals(run_id,approval_id,rules_sha256,expires_at) VALUES(?,?,?,?)", "approved", "forged", digest, expiry.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := st.RunRuleApproval(ctx, "approved"); err == nil {
		t.Fatal("forged approval row disagreed with the start event but was accepted")
	}
	if _, err := st.db.ExecContext(ctx, "DELETE FROM run_rule_approvals WHERE run_id=?", "approved"); err != nil {
		t.Fatal(err)
	}
	if err := st.PurgeRun(ctx, "approved"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := st.RunRuleApproval(ctx, "approved"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("purged run retained approval: %v", err)
	}
}
