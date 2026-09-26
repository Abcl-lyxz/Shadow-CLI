package dashboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"shadow/internal/store"
)

func TestDashboardRequiresSessionAndServesEvents(t *testing.T) {
	st, err := store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "db.sqlite"), bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Append(context.Background(), "0123456789abcdef", "started", map[string]string{"text": "fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Append(context.Background(), "0123456789abcdef", "legacy_tool", map[string]string{"text": "customer-code-48217"}); err != nil {
		t.Fatal(err)
	}
	urlText := "http://fixture.test/safe?token=private"
	uHash := sha256.Sum256([]byte(urlText))
	bHash := sha256.Sum256([]byte("private@example.com"))
	summary := store.EvidenceSummary{Origin: "http://fixture.test", URLSHA256: hex.EncodeToString(uHash[:]), Status: 200, Bytes: len("private@example.com"), SHA256: hex.EncodeToString(bHash[:])}
	raw, _ := json.Marshal(store.RawHTTP{RequestURL: urlText, Method: "GET", Status: 200, Body: []byte("private@example.com")})
	eventID, err := st.RecordObservation(context.Background(), "0123456789abcdef", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	findingID, err := st.CreateFinding(context.Background(), "0123456789abcdef", "customer-code-48217", summary.Origin, store.ClaimResponseObservation, eventID)
	if err != nil {
		t.Fatal(err)
	}
	repeatID, err := st.RecordObservation(context.Background(), "0123456789abcdef", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyResponseFinding(context.Background(), "0123456789abcdef", findingID, repeatID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReviewFinding(context.Background(), "0123456789abcdef", findingID, "response_reproduced", "high", 0, ""); err != nil {
		t.Fatal(err)
	}
	srv, link, err := Start(st)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if !IsLoopbackAddress(srv.ln.Addr().String()) {
		t.Fatalf("not loopback: %s", srv.ln.Addr())
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	unauthorized, err := http.Get(u.Scheme + "://" + u.Host + "/api/v1/runs")
	if err != nil {
		t.Fatal(err)
	}
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status %d", unauthorized.StatusCode)
	}
	unauthorizedFinding, err := http.Get(u.Scheme + "://" + u.Host + "/api/v1/runs/0123456789abcdef/findings")
	if err != nil {
		t.Fatal(err)
	}
	unauthorizedFinding.Body.Close()
	if unauthorizedFinding.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized finding status %d", unauthorizedFinding.StatusCode)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	if resp, err := client.Get(link); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("page status %d", resp.StatusCode)
		}
	}
	resp, err := client.Get(u.Scheme + "://" + u.Host + "/api/v1/runs/0123456789abcdef/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("events status %d, type %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	eventBody, err := io.ReadAll(resp.Body)
	if err != nil || strings.Contains(string(eventBody), "customer-code-48217") {
		t.Fatalf("dashboard leaked legacy free-form event: %v %s", err, eventBody)
	}
	findingResponse, err := client.Get(u.Scheme + "://" + u.Host + "/api/v1/runs/0123456789abcdef/findings")
	if err != nil {
		t.Fatal(err)
	}
	defer findingResponse.Body.Close()
	var findings []store.Finding
	if err := json.NewDecoder(findingResponse.Body).Decode(&findings); err != nil || findingResponse.StatusCode != http.StatusOK || len(findings) != 1 || findings[0].Status != "verified" || findings[0].ReproductionEventID != repeatID || findings[0].Title != "[WITHHELD]" || findings[0].Asset != "[WITHHELD]" || findings[0].Review == nil || findings[0].Review.PoCStatus != "response_reproduced" {
		t.Fatalf("finding API: status=%d findings=%#v error=%v", findingResponse.StatusCode, findings, err)
	}
}
