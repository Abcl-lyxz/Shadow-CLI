# Shadow CLI

Shadow is a local-first AI security testing CLI. The Go application coordinates work; agent commands run in Linux Docker containers. The current implementation status is in [docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md). Do not treat this repository as production-ready until the release gates there pass.

## Development

Requires Go 1.27 and a Docker Engine running Linux containers.

```text
go test ./...
docker build -t shadow-tools:dev -f sandbox/Dockerfile .
go run ./cmd/shadow doctor
go run ./cmd/shadow tools audit
go run ./cmd/shadow
```

The TUI opens without a provider. Use `/connect` to inspect the provider catalog and configure a route. Runtime files live under the user config directory, outside this repository. Docker workloads have no network by default.

## Use the development build

Start the TUI with `go run ./cmd/shadow`. Enter `/connect` to list providers, use `/connect search TEXT` to filter them, then `/connect <provider>` (or `/connect <id> <https-base-url>` for a compatible custom endpoint). Enter the API key at the hidden prompt. To replace the active provider's key later without changing its route or selected model, use `/key rotate` and enter the replacement at the hidden prompt; then run `/models refresh` and `/models probe` again. Run `/models refresh`, use `/models search TEXT` to filter models, then `/models <model-id>`. A stale catalog or custom endpoint requires `/models probe` to confirm tool calls and usage for the selected route. If the catalog price is missing or stale, enter `/price <input-USD-per-million> <output-USD-per-million>` using prices you verified with the provider. For an operator-confirmed free allowance, `/price 0 0` records zero marginal price for the current TUI session while input and output token caps stay finite. Set `/target https://your-authorized-origin.example`, optionally attach a source directory with `/attach <directory>`, and type an analysis request. The TUI runs four bounded roles (`surface`, `source`, `verify`, `report`) and prints the plan ID. `/board`, `/trace`, `/memory`, `/findings`, and `/budget` show metadata-only views, including allowed/denied policy decisions in the trace; Tab changes view, Ctrl+R refreshes it, Esc returns to the log, and Ctrl+P pauses by cancelling the active run. `/recover`, `/review`, and `/resume <run-id> <original task>` handle interrupted jobs without automatic replay. `/scope` shows the exact origin, `/dashboard` prints the local evidence dashboard link, and `/quit` exits. `/help` lists TUI commands.

The default agent run has no target network grant. For an owner-authorized exact GET/read plan, validate and sign the rule file using the [trusted rule workflow](docs/TRUSTED_RULES.md), set `/target ORIGIN`, then load `/rules RULES.json APPROVAL.json` before the task. The surface role may choose only the granted action IDs; the host gateway enforces the exact route and stores encrypted evidence. `/rules clear` removes the plan after the active run ends. A local signature does not establish target-owner permission. Authentication, writes, and vulnerability verification still require the open Phase 4 and 6 gates.

For a local static file, use `/attach <directory>` then `/artifact <relative-file>` in the TUI, or `go run ./cmd/shadow artifact inspect FILE` in a terminal. Supported formats are APK, IPA, PE, Mach-O, and ELF. Optional signed passive magic rules and their trust-key contract are in [static artifact workflow](docs/STATIC_ARTIFACTS.md).

After a crash, use `/agents <plan-id>` to inspect checkpoints and `/recover <plan-id>` to mark any in-progress job as `outcome_unknown`. Review any possible tool effect before using `/review <plan-id> <role> no_side_effect` or `side_effect_resolved`. Then enter `/resume <plan-id> <original task text>` with the same provider route. Recovery never replays an interrupted job automatically. Pending jobs can continue after the task text and route match the stored plan. Prompt text and provider keys are not stored in the plan; route and budget metadata are.

This build can run commands against attached files in network-disabled Docker, but untrusted command output is withheld from the model until a trusted typed extraction path is added. This limits useful source analysis. Approved exact GET reads are available through the host gateway; the build cannot verify a vulnerability from a response alone. Do not enter sensitive source or production responses into this development build; older ordinary event payloads are not encrypted.

The agent receives only a command's exit code and output byte count. Model-written memory text and stored answer text are withheld. The local TUI still shows an answer, while the dashboard withholds event payloads and finding title/asset text. Fixture HTTP observations remain typed metadata with encrypted raw evidence.

For a finding already recorded in the default local database, an operator can record a metadata-only review, inspect the exact report digest, then export the reviewed metadata. Valid PoC values are `not_attempted`, `blocked`, and `response_reproduced`; the last applies only to a separately reproduced response observation. Confidence is `low`, `medium`, or `high`. A CVSS v4 vector is accepted only for a security hypothesis and its score remains provisional. The optional `--duplicate` ID must identify an earlier canonical finding in the same run.

```text
go run ./cmd/shadow data review-finding <run-id> <finding-id> --poc not_attempted --confidence low
go run ./cmd/shadow report preview <run-id>
go run ./cmd/shadow report export <run-id> --format json --confirm <preview-digest> --out <new-report.json>
```

The report exporter also supports `html`, `pdf`, and `sarif`. It checks encrypted source evidence and the current review, refuses an existing output file, and omits URLs, stored titles, raw responses, and unreviewed prose. An optional operator-authored `--details FILE` adds reviewed finding narrative, bounded evidence excerpts, PoC explanations, and CVSS metric rationale to the preview and export. The dashboard requires the `report preview` digest before opening a local JSON export and verifies the file's SHA-256 before showing reviewed details; re-export JSON made by older builds. The isolated manual target-read directory can create only a response observation from its saved GET evidence with `data create-observation RUN EVENT --data-dir DIR`; the same directory can be used for `data findings`, `data review-finding`, and `report preview/export`. These local commands send no new HTTP request. See [report review workflow](docs/REPORT_REVIEW.md) for exact commands, the JSON format, safety checks, and PDF's embedded Thai/Latin font. Verified vulnerability reports remain open Phase 6 work.

Run data stays in `shadow.db` under the OS user config directory. The raw fixture evidence key lives in the OS keyring, not SQLite. Losing it makes existing encrypted raw evidence unreadable unless a recovery bundle was created first. Use `go run ./cmd/shadow data runs` to list runs, `go run ./cmd/shadow data audit-evidence` to check encrypted evidence pairs, and `go run ./cmd/shadow data audit-provenance` to check the independent append-only event/evidence chain. Keep a copy of its head outside the local profile to detect a whole-profile rollback. See [data lifecycle and custody](docs/DATA_LIFECYCLE.md).

For an encrypted recovery bundle, create three new files in existing directories. The recovery key and SHA-256 anchor must be outside the archive directory. Keep the key offline and preserve the anchor independently; someone able to replace both the archive and its anchor can conceal rollback. The command refuses existing output files and audits the consistent SQLite snapshot before publishing the bundle. Close Shadow before restoring on a fresh machine or into an empty data location. Restore refuses an existing database or a different key in the OS keyring and audits the decrypted image before installing it.

```text
go run ./cmd/shadow data backup <archive.sbk> --key-file <offline/recovery.key> --anchor <independent/anchor.sha256>
go run ./cmd/shadow data restore <archive.sbk> --key-file <offline/recovery.key> --anchor <independent/anchor.sha256>
go run ./cmd/shadow data audit-evidence
go run ./cmd/shadow data audit-provenance
```

Backup and restore audit a SQLite image in memory, then write the encrypted archive or final database without a plaintext scratch file. Database images over 128 MiB are refused to bound memory use. Plaintext can still reach process memory or swap, and an interrupted restore may leave a partial target file that needs manual removal before retrying. Ordinary events in the active database remain unencrypted. The archive, key, and anchor are not deleted by run retention commands.

The TUI automatically prunes runs whose latest event is older than 90 days at startup, after integrity checks. `data retention-set --days N` changes this bounded 1–365 day policy for the next TUI start. `data retention-plan --days N` counts expired runs without deleting them; `data prune-expired --days N --confirm` performs an explicit sweep. A run with unresolved test-write cleanup or unfinished agent jobs remains in the database. Use `data scope <run-id>` to inspect its hashed action snapshot and `data test-actions <run-id>` to inspect cleanup obligations. `data review-test-action <run-id> <action-id> --state <state-event>` acknowledges one journal state; it neither cleans up nor proves removal. `data purge-run <run-id> --confirm <run-id>` removes one eligible run from the active database. Deletion cannot be undone and does not erase backups or storage remnants.

`purge-run` refuses a run while a test write may still need cleanup. Inspect its journal with `data test-actions`; an acknowledgment does not clear the obligation. The fixture write and cleanup APIs used in tests are not available from the CLI or model tools.

Internal loopback fixture requests share a durable per-run budget of 16 ordinary and four cleanup HTTP hops, with one in-flight request and a shared minimum interval. Purge and age-based prune wait for an active fixture request. This budget does not grant live network access to the shipped agent.

The sandbox image is a large development build. It is not pinned or release approved. `tools audit` checks the checked-in manifest against executable paths in that image and fails until 300 distinct tools are verified.

`go run ./cmd/shadow policy validate <rules.json> --target <exact-origin>` checks a bounded operator-authored action document. See [trusted rule format](docs/TRUSTED_RULES.md). Validation grants no network access to the shipped agent.

For a controlled, anonymous public read, review the exact GET/read rules and digest, then use `policy approve` and `target read` as documented in [trusted rule format](docs/TRUSTED_RULES.md). `target read` applies configured age-based retention, executes one approved action through the host gateway, saves encrypted raw evidence in the selected data directory, and prints only response metadata. `target audit --data-dir DIR` checks its evidence and provenance. These commands do not enable public-target tools in the agent or TUI, authenticate to a site, or perform test writes. Production readiness still depends on the [Phase 4 gates](docs/ROADMAP.md).

## Layout

- `cmd/shadow`: CLI entry point.
- `internal`: runtime, policy, provider discovery, Docker, and TUI.
- `sandbox`: Linux tool image and manifests.
- `docs`: architecture, [phase checklist](docs/ROADMAP.md), [current evidence and release gates](docs/CURRENT_STATUS.md), and handoff.
- `docs/PRODUCT_SPEC.md`: intended behavior and acceptance criteria, distinct from the current implementation.
- `.codex` and `.agents/skills`: repository-scoped Codex workflow.
