# Local finding review and report export

This development workflow uses the default local `shadow.db` or an isolated
approved-read `--data-dir`. It can create a response-only observation from an
already saved GET. It does not verify a vulnerability or authorize another
target request. A response match verifies only that the same response was
recorded again.

## Record a review

Use `go run ./cmd/shadow data runs` to find a run. Finding IDs and their source
event IDs are available from the local dashboard. Record an operator review:

```text
go run ./cmd/shadow data review-finding RUN ID --poc not_attempted --confidence low
```

For an isolated approved-read directory, use the run and observation event ID
printed by the earlier `target read` command. These local commands do not send
HTTP requests:

```text
go run ./cmd/shadow data create-observation RUN EVENT --data-dir DIR
go run ./cmd/shadow data findings RUN --data-dir DIR
go run ./cmd/shadow data review-finding RUN ID --poc not_attempted --confidence low --data-dir DIR
go run ./cmd/shadow report preview RUN --data-dir DIR
```

`create-observation` is idempotent for the same run and source event. It makes
only a `response_observation` finding and never a security hypothesis. A human
must inspect the saved evidence and review status before producing a report.

PoC status is `not_attempted`, `blocked`, or `response_reproduced`. The last is
accepted only for a response observation verified by a later independent GET;
it never upgrades a security hypothesis. Confidence is `low`, `medium`, or
`high`. Add `--duplicate EARLIER_ID` for an earlier canonical finding of the
same claim type in the same run. Add `--cvss 'CVSS:4.0/...'` only to a security
hypothesis; the calculated score is provisional. CVSS metric definitions and
scoring follow [FIRST's CVSS v4 specification](https://www.first.org/cvss/v4.0/specification-document).

## Preview and export metadata

```text
go run ./cmd/shadow report preview RUN
go run ./cmd/shadow report export RUN --format json --confirm DIGEST --out new-report.json
```

Add `--data-dir DIR` at the end of `report preview` and `report export` when
working with isolated saved evidence. With a narrative, place `--details FILE`
before `--data-dir DIR`.

Use the digest printed by the immediately preceding preview. Export supports
`html`, `pdf`, `json`, and `sarif`, refuses an existing file, and writes a
private local file. A changed review or finding changes the digest. Only
reviewed findings with authenticated source evidence appear. Metadata reports
omit stored finding titles, URLs, raw responses, and free-form text.

## Add operator-authored narrative

For a full narrative, write a local UTF-8 JSON array with one object per
reviewed finding. Replace `finding_id` and each sentence below with reviewed,
non-sensitive text. The sample describes an observation, not a verified
vulnerability:

```json
[
  {
    "finding_id": 1,
    "title": "Response observation for local fixture",
    "asset_label": "local fixture",
    "cwe": "",
    "observed": "A response was saved under an evidence event.",
    "expected": "The fixture returns the documented response.",
    "preconditions": "The disposable fixture is running.",
    "impact": "No security impact has been demonstrated.",
    "evidence_excerpt": "Operator-reviewed response summary; no raw identifier or token included.",
    "poc_explanation": "No PoC was attempted under this review.",
    "validation_plan": "Review the saved observation and request approval before any further test.",
    "remediation": "No remediation is proposed from this observation alone.",
    "business_priority": "unassigned"
  }
]
```

If the finding has a CVSS vector, add `cvss_rationale` as an object explaining
**every** metric present in that vector by its abbreviation (`AV`, `AC`, `AT`,
and so on). Unknown, missing, or extra metrics are refused. `business_priority`
is separate from CVSS and must be `unassigned`, `low`, `medium`, `high`, or
`critical`.

```text
go run ./cmd/shadow report preview RUN --details details.json
go run ./cmd/shadow report export RUN --format html --confirm DIGEST --out new-report.html --details details.json
```

The preview prints the complete reviewed document and its digest. The detail
file is capped at 64 KiB and 50 findings. Known secret and email patterns,
control characters, unknown fields, incomplete details, and missing CVSS
rationale are refused. Optional evidence excerpts and PoC explanations are
operator-authored, pass the same text filter, and join the digest review; raw
response text is never inserted automatically. This cannot recognize every
secret or personal datum; the operator must inspect the preview before export.
HTML escapes narrative text and applies a restrictive content policy. PDF
embeds an OFL-licensed Noto Sans Thai font for Latin and Thai text and refuses
unsupported glyphs instead of replacing them. The file remains on the
operator's machine and is not placed in the active database. The dashboard
can open a digest-approved JSON export locally to show matching reviewed detail;
the file stays in the browser tab and is matched against run, finding, source,
and review event IDs. No report format claims a verified vulnerability from a
response observation or an operator's prose alone.
