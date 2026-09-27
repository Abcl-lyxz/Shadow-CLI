// Package report exports reviewed, evidence-linked findings. It never copies
// response bodies or unreviewed finding titles from the data store.
package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"regexp"
	"strings"

	"shadow/internal/redact"
	"shadow/internal/store"
)

// Detail is explicitly authored and reviewed by the local operator. It is
// never populated from model prose or decrypted target response content.
type Detail struct {
	FindingID        int64             `json:"finding_id"`
	Title            string            `json:"title"`
	AssetLabel       string            `json:"asset_label"`
	CWE              string            `json:"cwe,omitempty"`
	Observed         string            `json:"observed"`
	Expected         string            `json:"expected"`
	Preconditions    string            `json:"preconditions"`
	Impact           string            `json:"impact"`
	EvidenceExcerpt  string            `json:"evidence_excerpt,omitempty"`
	PoCExplanation   string            `json:"poc_explanation,omitempty"`
	ValidationPlan   string            `json:"validation_plan"`
	Remediation      string            `json:"remediation"`
	CVSSRationale    map[string]string `json:"cvss_rationale,omitempty"`
	BusinessPriority string            `json:"business_priority"`
}

type Entry struct {
	ID                  int64    `json:"id"`
	ClaimType           string   `json:"claim_type"`
	Status              string   `json:"status"`
	SourceEventID       int64    `json:"source_event_id"`
	ReproductionEventID int64    `json:"reproduction_event_id,omitempty"`
	ReviewEventID       int64    `json:"review_event_id"`
	PoCStatus           string   `json:"poc_status"`
	Confidence          string   `json:"confidence"`
	DuplicateOf         int64    `json:"duplicate_of,omitempty"`
	CVSSVector          string   `json:"cvss_vector,omitempty"`
	CVSSScore           *float64 `json:"cvss_score,omitempty"`
	Detail              *Detail  `json:"detail,omitempty"`
}

const maxDetailFile = 64 << 10

// ParseDetails accepts a bounded operator-authored JSON array. The export
// preview shows these fields before the operator confirms their digest.
func ParseDetails(data []byte) ([]Detail, error) {
	if len(data) == 0 || len(data) > maxDetailFile {
		return nil, errors.New("review details file must be 1-65536 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var details []Detail
	if err := decoder.Decode(&details); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("review details must contain one JSON array")
	}
	if len(details) == 0 || len(details) > 50 {
		return nil, errors.New("review details must contain 1-50 findings")
	}
	return details, nil
}

var cwePattern = regexp.MustCompile(`^CWE-[1-9][0-9]{0,4}$`)
var rationaleKeyPattern = regexp.MustCompile(`^[A-Z]{1,3}$`)

// AttachDetails binds a complete, reviewed narrative to each selected finding.
// It rejects obvious secrets/PII; the human digest review remains required.
func AttachDetails(doc Document, details []Detail) (Document, string, error) {
	if len(details) != len(doc.Findings) || len(details) > 50 {
		return doc, "", errors.New("one reviewed detail is required per exported finding")
	}
	doc.Findings = append([]Entry(nil), doc.Findings...)
	byID := map[int64]Detail{}
	for _, d := range details {
		if d.FindingID <= 0 || byID[d.FindingID].FindingID != 0 {
			return doc, "", errors.New("invalid or repeated finding detail ID")
		}
		fields := []string{d.Title, d.AssetLabel, d.Observed, d.Expected, d.Preconditions, d.Impact, d.ValidationPlan, d.Remediation}
		for _, field := range fields {
			if !safeReviewText(field, 1200) {
				return doc, "", errors.New("review detail is empty, too long, or contains sensitive text")
			}
		}
		for _, field := range []string{d.EvidenceExcerpt, d.PoCExplanation} {
			if field != "" && !safeReviewText(field, 1200) {
				return doc, "", errors.New("review excerpt or PoC explanation contains sensitive text")
			}
		}
		if len(d.Title) > 160 || len(d.AssetLabel) > 160 {
			return doc, "", errors.New("review title or asset label is too long")
		}
		if d.CWE != "" && !cwePattern.MatchString(d.CWE) {
			return doc, "", errors.New("invalid CWE identifier")
		}
		switch d.BusinessPriority {
		case "low", "medium", "high", "critical", "unassigned":
		default:
			return doc, "", errors.New("invalid business priority")
		}
		if len(d.CVSSRationale) > 30 {
			return doc, "", errors.New("too many CVSS rationale entries")
		}
		for key, value := range d.CVSSRationale {
			if !rationaleKeyPattern.MatchString(key) || !safeReviewText(value, 400) {
				return doc, "", errors.New("invalid CVSS metric rationale")
			}
		}
		byID[d.FindingID] = d
	}
	for i := range doc.Findings {
		d, ok := byID[doc.Findings[i].ID]
		if !ok {
			return doc, "", errors.New("detail does not match exported findings")
		}
		if doc.Findings[i].CVSSVector != "" {
			allowed := map[string]bool{}
			for _, part := range strings.Split(strings.TrimPrefix(doc.Findings[i].CVSSVector, "CVSS:4.0/"), "/") {
				metric, _, ok := strings.Cut(part, ":")
				allowed[metric] = true
				if !ok || d.CVSSRationale[metric] == "" {
					return doc, "", fmt.Errorf("CVSS metric %s lacks rationale", metric)
				}
			}
			for metric := range d.CVSSRationale {
				if !allowed[metric] {
					return doc, "", errors.New("CVSS rationale contains a metric absent from the vector")
				}
			}
		} else if len(d.CVSSRationale) > 0 {
			return doc, "", errors.New("CVSS rationale requires a scored vector")
		}
		doc.Findings[i].Detail = &d
	}
	doc.Notice = "Operator-reviewed narrative with evidence references. Response reproduction does not verify vulnerability or impact."
	digest, err := Digest(doc)
	return doc, digest, err
}

func safeReviewText(s string, max int) bool {
	if s == "" || len(s) > max || strings.TrimSpace(s) != s || redact.Text(s) != s {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func Digest(doc Document) (string, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

type Document struct {
	Schema   string  `json:"schema"`
	RunID    string  `json:"run_id"`
	Notice   string  `json:"notice"`
	Findings []Entry `json:"findings"`
}

// Prepare fails closed if a reviewed finding's source or reproduction evidence
// can no longer be authenticated. It does not validate vulnerability impact.
func Prepare(ctx context.Context, st *store.Store, runID string) (Document, string, error) {
	doc := Document{Schema: "shadow-report-v1", RunID: runID, Notice: "Development evidence metadata. A reproduced response does not verify a vulnerability or impact.", Findings: []Entry{}}
	if runID == "" {
		return doc, "", errors.New("run id required")
	}
	findings, err := st.Findings(ctx, runID)
	if err != nil {
		return doc, "", err
	}
	reviews, err := st.FindingReviews(ctx, runID)
	if err != nil {
		return doc, "", err
	}
	for _, f := range findings {
		r, ok := reviews[f.ID]
		if !ok {
			continue
		}
		if f.Status == "verified" {
			reproductionID, err := st.LatestResponseReproductionEventID(ctx, runID, f.ID)
			if err != nil {
				return doc, "", err
			}
			if reproductionID == 0 || r.ReviewEventID <= reproductionID {
				return doc, "", fmt.Errorf("finding %d requires review after response reproduction", f.ID)
			}
		}
		if _, _, err := st.ValidatedObservation(ctx, runID, f.SourceEventID); err != nil {
			return doc, "", fmt.Errorf("finding %d source evidence: %w", f.ID, err)
		}
		if f.ReproductionEventID != 0 {
			if _, _, err := st.ValidatedObservation(ctx, runID, f.ReproductionEventID); err != nil {
				return doc, "", fmt.Errorf("finding %d reproduction evidence: %w", f.ID, err)
			}
		}
		doc.Findings = append(doc.Findings, Entry{ID: f.ID, ClaimType: f.ClaimType, Status: f.Status, SourceEventID: f.SourceEventID, ReproductionEventID: f.ReproductionEventID, ReviewEventID: r.ReviewEventID, PoCStatus: r.PoCStatus, Confidence: r.Confidence, DuplicateOf: r.DuplicateOf, CVSSVector: r.CVSSVector, CVSSScore: r.CVSSScore})
	}
	if len(doc.Findings) == 0 {
		return doc, "", errors.New("no reviewed findings in run")
	}
	digest, err := Digest(doc)
	return doc, digest, err
}

func Render(doc Document, format string) ([]byte, error) {
	for _, entry := range doc.Findings {
		if entry.CVSSVector != "" && entry.CVSSScore == nil {
			return nil, errors.New("CVSS vector lacks a calculated score")
		}
	}
	switch format {
	case "json":
		// The exported bytes match Digest(doc), so a dashboard can verify the
		// operator-confirmed preview digest before showing local narrative.
		return json.Marshal(doc)
	case "sarif":
		type result struct {
			RuleID     string            `json:"ruleId"`
			Kind       string            `json:"kind"`
			Level      string            `json:"level"`
			Message    map[string]string `json:"message"`
			Properties Entry             `json:"properties"`
		}
		results := make([]result, 0, len(doc.Findings))
		for _, e := range doc.Findings {
			results = append(results, result{RuleID: "shadow/" + e.ClaimType, Kind: "review", Level: "note", Message: map[string]string{"text": fmt.Sprintf("Reviewed %s %d; %s. Vulnerability impact is not verified.", e.ClaimType, e.ID, e.PoCStatus)}, Properties: e})
		}
		return json.MarshalIndent(map[string]any{"version": "2.1.0", "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "Shadow", "rules": []any{map[string]string{"id": "shadow/security_hypothesis"}, map[string]string{"id": "shadow/response_observation"}}}}, "results": results}}}, "", "  ")
	case "html":
		var b bytes.Buffer
		t := template.Must(template.New("report").Parse(htmlReportTemplate))
		if err := t.Execute(&b, doc); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	case "pdf":
		return renderPDF(doc)
	default:
		return nil, errors.New("format must be html, pdf, json, or sarif")
	}
}

const htmlReportTemplate = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>Shadow reviewed findings</title><style>body{font:16px system-ui;max-width:760px;margin:3rem auto;padding:0 1rem;color:#17202a}article{border-top:1px solid #bbb;padding:1rem 0}small{color:#555}dt{font-weight:600;margin-top:.7rem}dd{margin:0;white-space:pre-wrap}</style><h1>Reviewed findings</h1><p>Run {{.RunID}}</p><p>{{.Notice}}</p>{{range .Findings}}<article><h2>{{if .Detail}}{{.Detail.Title}}{{else}}Finding {{.ID}}{{end}}</h2><p>{{.ClaimType}} · {{.Status}} · PoC: {{.PoCStatus}} · confidence: {{.Confidence}}</p><small>Source event {{.SourceEventID}} · repeat event {{.ReproductionEventID}} · review event {{.ReviewEventID}} · duplicate of {{.DuplicateOf}}</small>{{if .CVSSVector}}<p>Provisional CVSS v4: {{.CVSSVector}} ({{.CVSSScore}})</p>{{end}}{{with .Detail}}<dl><dt>Asset</dt><dd>{{.AssetLabel}}</dd><dt>CWE</dt><dd>{{.CWE}}</dd><dt>Observed</dt><dd>{{.Observed}}</dd><dt>Expected</dt><dd>{{.Expected}}</dd><dt>Preconditions</dt><dd>{{.Preconditions}}</dd><dt>Impact assessment</dt><dd>{{.Impact}}</dd>{{if .EvidenceExcerpt}}<dt>Operator-reviewed evidence excerpt</dt><dd>{{.EvidenceExcerpt}}</dd>{{end}}{{if .PoCExplanation}}<dt>PoC explanation</dt><dd>{{.PoCExplanation}}</dd>{{end}}<dt>Operator validation plan</dt><dd>{{.ValidationPlan}}</dd><dt>Remediation</dt><dd>{{.Remediation}}</dd><dt>Business priority</dt><dd>{{.BusinessPriority}}</dd>{{if .CVSSRationale}}<dt>CVSS metric rationale</dt>{{range $metric,$why := .CVSSRationale}}<dd>{{$metric}}: {{$why}}</dd>{{end}}{{end}}</dl>{{end}}</article>{{end}}</html>`
