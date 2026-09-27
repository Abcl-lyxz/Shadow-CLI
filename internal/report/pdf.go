package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"
	"unicode"

	"github.com/signintech/gopdf"
)

//go:embed fonts/NotoSansThai-Regular.ttf
var reportFont []byte

// renderPDF embeds a Latin/Thai Unicode font. Unsupported glyphs fail closed
// instead of being silently replaced in a reviewed report.
func renderPDF(doc Document) ([]byte, error) {
	var pdf gopdf.GoPdf
	pdf.Start(gopdf.Config{PageSize: *gopdf.PageSizeLetter, Unit: gopdf.UnitPT})
	if err := pdf.AddTTFFontData("NotoSansThai", reportFont); err != nil {
		return nil, fmt.Errorf("load report font: %w", err)
	}
	if err := pdf.SetFont("NotoSansThai", "", 10); err != nil {
		return nil, err
	}
	const left, top, right, bottom, leading = 42.0, 42.0, 570.0, 750.0, 16.0
	y := top
	newPage := func() {
		pdf.AddPage()
		y = top
	}
	write := func(value string) error {
		for _, r := range value {
			if unicode.IsControl(r) {
				return fmt.Errorf("PDF text contains a control character")
			}
			ok, err := pdf.IsCurrFontContainGlyph(r)
			if err != nil || !ok {
				return fmt.Errorf("PDF font cannot render U+%04X", r)
			}
		}
		remaining := strings.TrimSpace(value)
		for remaining != "" {
			if y+leading > bottom {
				newPage()
			}
			line := remaining
			for {
				width, err := pdf.MeasureTextWidth(line)
				if err != nil {
					return err
				}
				if width <= right-left {
					break
				}
				runes := []rune(line)
				if len(runes) < 2 {
					return fmt.Errorf("PDF glyph exceeds page width")
				}
				line = string(runes[:len(runes)-1])
			}
			if len(line) < len(remaining) {
				if space := strings.LastIndexByte(line, ' '); space > 20 {
					line = line[:space]
				}
			}
			pdf.SetXY(left, y)
			if err := pdf.Cell(&gopdf.Rect{W: right - left, H: leading}, line); err != nil {
				return err
			}
			y += leading
			remaining = strings.TrimSpace(strings.TrimPrefix(remaining, line))
		}
		if value == "" {
			y += leading
		}
		return nil
	}
	newPage()
	lines := []string{"Shadow reviewed findings", "Run: " + doc.RunID, doc.Notice, ""}
	for _, e := range doc.Findings {
		lines = append(lines, fmt.Sprintf("Finding %d: %s / %s", e.ID, e.ClaimType, e.Status), fmt.Sprintf("PoC %s; confidence %s; duplicate %d", e.PoCStatus, e.Confidence, e.DuplicateOf), fmt.Sprintf("Evidence %d / %d; review %d", e.SourceEventID, e.ReproductionEventID, e.ReviewEventID))
		if e.CVSSVector != "" {
			lines = append(lines, fmt.Sprintf("Provisional CVSS v4 %.1f: %s", *e.CVSSScore, e.CVSSVector))
		}
		if d := e.Detail; d != nil {
			for _, field := range []struct{ label, value string }{{"Title", d.Title}, {"Asset", d.AssetLabel}, {"CWE", d.CWE}, {"Observed", d.Observed}, {"Expected", d.Expected}, {"Preconditions", d.Preconditions}, {"Impact", d.Impact}, {"Operator-reviewed evidence excerpt", d.EvidenceExcerpt}, {"PoC explanation", d.PoCExplanation}, {"Operator validation plan", d.ValidationPlan}, {"Remediation", d.Remediation}, {"Business priority", d.BusinessPriority}} {
				if field.value != "" {
					lines = append(lines, field.label+": "+field.value)
				}
			}
			for _, part := range strings.Split(strings.TrimPrefix(e.CVSSVector, "CVSS:4.0/"), "/") {
				metric, _, _ := strings.Cut(part, ":")
				if rationale := d.CVSSRationale[metric]; rationale != "" {
					lines = append(lines, "CVSS "+metric+": "+rationale)
				}
			}
		}
		lines = append(lines, "")
	}
	for _, line := range lines {
		if err := write(line); err != nil {
			return nil, err
		}
	}
	var out bytes.Buffer
	if _, err := pdf.WriteTo(&out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
