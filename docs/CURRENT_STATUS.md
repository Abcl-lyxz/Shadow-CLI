# Shadow CLI handoff

Updated: 2026-09-26. This is the source of truth for the next development session.

## Product decisions

- Go CLI for Windows, macOS, and Linux; Docker Engine must run Linux containers.
- Single-user, local-first TUI with a localhost evidence dashboard.
- Catalog-based provider/model selection, with custom OpenAI-compatible endpoints. Provider adapters are protocol-specific rather than a fixed list of provider names.
- One Linux image with at least 300 verified distinct security tool executables. Agent shell commands have no host fallback.
- Exact-origin target scope by default. The current development build gives agents no live target network access. Later, a runtime broker must enforce scope, rate, side effects, and cleanup for reversible test writes. RCE, destructive changes, and denial of service remain prohibited.
- Static analysis for APK/IPA and PE/Mach-O/ELF until a suitable execution environment is provided; Linux Docker cannot run native mobile/desktop GUIs.

## Implemented and verified locally

- TUI: live provider catalog with last-valid offline cache, `/connect`, custom base URL, masked key entry to OS keyring, `/models` including endpoint refresh, target/scope, read-only workspace attachment, skills, memory, agent state, stop, and dashboard link. The UI is a working development shell, not the complete planned interface.
- Model runtime: active route is copied into a bounded single-agent run; OpenAI-compatible Chat Completions tool calls are supported. Six bundled skills are discoverable and loaded on demand.
- Docker runner: network none, numeric nonroot user, read-only root and workspace, dropped capabilities, no-new-privileges, CPU/RAM/PID/time/output limits, and cleanup. No model-generated host command path exists.
- SQLite event log and scope-bound memory with source-event provenance; older tool context compacts to event IDs, and the agent can retrieve an older event from its own run.
- Fixture-only HTTP gateway: explicit URL allowlist, exact-origin and per-hop redirect checks, pinned DNS, public-destination filtering with an opt-in for loopback fixtures, one concurrent request, a 20-request budget, a one-second minimum interval, and capped response/header sizes. Its observation contains origin, status, MIME type, byte count, and hashes; response bodies, paths, queries, and headers are withheld. It is not offered to agents while side-effect and production evidence policies are incomplete.
- Fixture evidence path: `GetRecorded` commits the minimized observation event and AES-GCM encrypted raw URL/headers/capped body in one SQLite transaction. Raw evidence needs the OS-keyring-backed 32-byte key and matching run/event IDs; the agent context and dashboard API expose only the minimized event. Development retention is explicit per-run purge.
- Finding records: same-run evidence-backed source required. A later independent recorded GET can verify only a `response_observation` when URL, status, and complete body hashes match; `security_hypothesis` remains unverified. The token-gated dashboard displays finding status and source/repeat event IDs, with no raw-evidence route.
- Local dashboard: token-gated loopback server, run/event list, finding metadata list, and restrictive response headers. It does not yet manage PoCs, CVSS, or report exports.
- Repository Codex setup: `AGENTS.md`, `.codex/config.toml`, startup handoff hook, execpolicy rules, focused reviewer agents, two `.agents/skills`, and CI matrix. Project trust is required for Codex to load project configuration/hooks.
- Development Kali image built locally: `shadow-tools:dev`, approximately 4.33 GB. `sandbox/inventory.sh` generated `sandbox/tools.txt` from installed direct Kali metapackage dependencies; the CLI embeds this manifest so audit works outside the source directory. `shadow tools audit` found **797 command names, 664 distinct executable paths, 0 missing**. This passes the local numerical tool gate, not the reproducibility or release gate.

## Verification recorded on Windows

- `go test ./...` — pass.
- `go vet ./...` — pass.
- `GOOS=windows GOARCH=amd64`, `GOOS=linux GOARCH=amd64`, and `GOOS=darwin GOARCH=arm64` builds of `./cmd/shadow` — pass. Only Windows runtime was exercised.
- `docker build -t shadow-tools:dev -f sandbox/Dockerfile .` — pass with local Linux Docker Engine.
- `go run ./cmd/shadow tools audit` — pass: 797 names, 664 paths, 0 missing.
- `SHADOW_TEST_IMAGE=shadow-tools:dev go test ./internal/sandbox ./internal/agent -run 'TestDockerIsolation|TestAgentToolAndMemoryFlow' -v` — pass. Confirms read-only host mount/root and selected-model agent tool/memory flow using a fake provider.
- `go run ./cmd/shadow doctor` — Docker Engine and image available; no real provider configured.
- TUI opened in a Windows PTY and `/quit` exited with status 0. The restricted session could not reach Models.dev, so catalog fallback was covered by the fixture test rather than this smoke test.
- Live Models.dev catalog shape test passed earlier in this milestone. No real provider inference, live target test, or verified vulnerability test has been run.
- Codex hook JSON parsed, handoff helper returned this file, and execpolicy check matched the `git push` prompt rule. Both repository skills passed `quick_validate.py` earlier in this milestone.

## Gateway slice verified on Windows (2026-09-24)

- With `GOCACHE` set to this repository's `.cache/go-build`, `go test ./...`, `go vet ./...`, and `go test -race ./internal/broker` — pass. Fixture tests cover allowlist and query matching, cross-origin and unlisted redirects, pinned DNS after a simulated rebind, blocked loopback/private/shared destinations, concurrency, cancellation, the request budget, response cap, and absence of body/query data in observations.
- With `SHADOW_TEST_IMAGE=shadow-tools:dev`, `go test ./internal/sandbox ./internal/agent -run 'TestDockerIsolation|TestAgentToolAndMemoryFlow' -count=1 -v` — pass with Docker Engine access. The restricted attempt failed at the Docker named pipe; the escalated rerun passed both tests. Container networking remains disabled.
- `go run ./cmd/shadow doctor` — pass with Docker Engine access: image available, no provider configured, release incomplete. `go run ./cmd/shadow tools audit` — pass: 797 command names, 664 distinct executable paths, 0 missing. Restricted attempts failed at the Docker named pipe.
- No real target was contacted. At the end of that gateway slice, fixture responses did not establish a verified security finding and raw evidence was not yet stored. The later evidence slice below supersedes the storage limitation.

## Evidence and finding slice verified on Windows (2026-09-24)

- Windows PowerShell: `$env:GOCACHE = Join-Path (Get-Location) '.cache/go-build'; go test ./... -count=1` — pass. `$env:GOCACHE = Join-Path (Get-Location) '.cache/go-build'; go vet ./...` — pass. `$env:GOCACHE = Join-Path (Get-Location) '.cache/go-build'; go test -race ./internal/store ./internal/broker ./internal/dashboard -count=1` — pass.
- Fixture tests confirm that encrypted raw URL, headers, and body survive a database reopen with the same key while event payloads omit those values. Wrong-key reads, cross-run reads, modified ciphertext or event summaries, forged observations without raw evidence, reproductions recorded before finding creation, cross-run or altered reproductions, and attempts to upgrade security hypotheses are rejected. Dashboard finding API requires the session token; it returns finding metadata only.
- These tests used local HTTP fixtures. No live target or real provider was contacted. `verified` currently means an exact fixture response was reproduced after finding creation, not that a vulnerability or its impact was verified.

## Persistent evidence key and explicit retention slice verified on Windows (2026-09-24)

- TUI startup now creates the 32-byte raw-evidence key in a separate OS keyring service when no encrypted evidence exists, reuses it after restart, and checks it against existing evidence. A missing, corrupt, or replaced key blocks access instead of silently replacing it. The key is not stored in SQLite. There is no in-app cross-device key export or recovery; restore the original OS keyring backup or the raw records remain unreadable.
- Development data is retained until the user explicitly runs `shadow data purge-run ID --confirm ID`. The transaction removes that run's events, raw evidence, findings, and derived memories from the active database. `shadow data runs` lists recent runs. No automatic retention period or secure erasure of backups/storage remnants is provided.
- New findings write a creation event in the same transaction; response reproduction is ordered by event ID, avoiding equal-resolution wall-clock timestamps. Older finding rows retain the prior timestamp check. This is database-local provenance, not tamper-resistant audit storage.
- `$env:GOCACHE = Join-Path (Get-Location) '.cache/go-build'; go test ./... -count=1` — pass. `$env:GOCACHE = Join-Path (Get-Location) '.cache/go-build'; go vet ./...` — pass. `$env:GOCACHE = Join-Path (Get-Location) '.cache/go-build'; go test -race ./internal/ui ./internal/config ./internal/store ./internal/broker ./internal/dashboard -count=1` — pass. Tests include managed-key reopen/replacement and confirmed per-run purge.
- With `SHADOW_TEST_IMAGE=shadow-tools:dev`, Docker integration tests for isolation and agent tool/memory flow passed after allowing Docker Engine access. The restricted attempt failed at the Docker named pipe. `go run ./cmd/shadow doctor` passed: Docker Engine and image available, no provider configured. `go run ./cmd/shadow tools audit` passed: 797 command names, 664 distinct executable paths, 0 missing. Windows amd64, Linux amd64, and macOS arm64 CLI builds passed; only Windows runtime was exercised.
- No real provider inference or live target was used. This is a development milestone, not a production release.

## Side-effect policy and cleanup journal slice verified on Windows (2026-09-26)

- `internal/policy` now classifies exact URL and method pairs from trusted runtime rules as read, authentication, named reversible test write, or blocked. Unlisted and cross-origin actions are denied; a test-write rule requires a `shadow_`-prefixed resource marker and an exact in-scope DELETE cleanup request. This is preparatory policy code, not an agent network tool or evidence that a GET is safe.
- `internal/store` now persists a test-write plan before dispatch, a durable "write may have happened" state, cleanup attempts/failures, and a later same-run, same-origin authenticated observation. The cleanup observation must follow the attempt by event ID. Route URLs are stored only as hashes in the journal. `cleanup_observed` does not claim that the resource was removed; semantic verification and automated cleanup execution remain open. Per-run purge removes the journal.
- PowerShell with `$env:GOCACHE = Join-Path (Get-Location) '.cache/go-build'`: `go test ./... -count=1` — pass; `go vet ./...` — pass; `go test -race ./internal/policy ./internal/store -count=1` — pass. Negative tests cover unlisted/mismatched URLs and methods, mutating GET declarations, incomplete or cross-origin cleanup plans, duplicate rules, premature/duplicate/cross-run transitions, stale and wrong-origin cleanup observations, persistence, redacted journal events, and purge.
- No test write was dispatched. No real provider or target was contacted. Docker container settings did not change in this slice, so the Docker isolation integration test was not rerun.

## Fixture dispatcher and interrupted-cleanup review slice verified on Windows (2026-09-26)

- `NewFixtureDispatcher` accepts only trusted exact GET/read rules and a pinned loopback destination. It derives its own URL allowlist from those rules, so a caller-supplied extra URL cannot add access. Authentication and test-write rules cannot execute through this dispatcher. Redirects remain subject to the existing per-hop exact URL, origin, budget, and DNS-pinning checks. This dispatcher is an internal fixture API and is not offered to model tools.
- `shadow data test-actions ID` lists a run's test-write cleanup journal without raw URL or query data. A restart preserves `write_may_have_happened` and `cleanup_attempted` obligations; tests reject replaying those transitions. The CLI displays the stored state for manual review but does not execute cleanup or assert success.
- Focused Windows tests: `$env:GOCACHE = Join-Path (Get-Location) '.cache/go-build'; go test ./cmd/shadow ./internal/broker ./internal/store -count=1` — pass. Tests cover direct denial, caller allowlist bypass, unlisted/cross-origin redirects, cancellation, non-loopback destination rejection, encrypted fixture recording, interrupted journal recovery, and CLI output minimization.
- Final Windows checks: `go test ./... -count=1` — pass; `go vet ./...` — pass; `go test -race ./internal/policy ./internal/store ./internal/broker ./cmd/shadow -count=1` — pass, with repository-local `GOCACHE`. `GOOS=windows GOARCH=amd64`, `GOOS=linux GOARCH=amd64`, and `GOOS=darwin GOARCH=arm64` builds of `./cmd/shadow` — pass; only Windows runtime was exercised.
- With `SHADOW_TEST_IMAGE=shadow-tools:dev`, `go test ./internal/sandbox ./internal/agent -run 'TestDockerIsolation|TestAgentToolAndMemoryFlow' -count=1 -v` — both pass with Docker Engine access. Restricted Docker access returned a named-pipe permission error; the allowed rerun passed. `go run ./cmd/shadow doctor` — pass: Docker and image available, credential present in OS keyring, release incomplete. `go run ./cmd/shadow tools audit` — pass: 797 names, 664 paths, 0 missing. No real provider inference was performed.
- Initial GitHub CI on `main` passed Linux, macOS, and Docker integration, but Windows failed its format step because checkout converted Go files to CRLF. `.gitattributes` now keeps Go and build scripts at LF on all platforms; the workflow also prints unformatted filenames on failure. This is a CI checkout correction, not a change to product behavior.
- No test write was dispatched. No live target or real provider was contacted. Cross-platform runtime, real cleanup execution, and semantic cleanup verification remain open.

## GitHub handoff (2026-09-26)

- Repository: `https://github.com/Abcl-lyxz/Shadow-CLI`, branch `main`. The initial development snapshot was published as `45425d1`; the Windows CI checkout fix was published as `ea9a4b9`. The checkout tracks `origin/main`.
- GitHub Actions run `36211485992` for `ea9a4b9` passed all four jobs: Go format/test/vet/build on Windows, macOS, and Linux, plus Docker isolation and fake-provider agent integration on Linux. This is CI validation of the development snapshot, not a production release. No live target was tested.

## Immutable run scope and manual obligation review slice verified on Windows (2026-09-26)

- New agent runs atomically persist the exact origin, hash-only trusted action grants, and start event. Current agent runs have no network action grants. `PlanTestWrite` now requires an exact test-write grant from that run's immutable snapshot; legacy runs without snapshots fail closed. The snapshot table rejects updates, while explicit per-run purge removes the snapshot. This is app/database-local immutability, not tamper-resistant provenance or full production run metadata.
- The CLI now supports `shadow data scope ID`, `shadow data test-actions ID`, and `shadow data review-test-action RUN ACTION --state EVENT`. A review is bound to the current journal state event, rejects stale or duplicate acknowledgments, and survives restart. A state transition requires another review. Acknowledgment does not change cleanup status, execute cleanup, or prove resource removal. CLI displays route hashes instead of raw URL paths or queries.
- PowerShell: `$env:GOCACHE = Join-Path (Get-Location) '.cache/go-build'; go test ./... -count=1` — pass; `go vet ./...` — pass; `go test -race ./internal/store ./internal/agent ./cmd/shadow -count=1` — pass. With the same `GOCACHE`, `GOOS=windows GOARCH=amd64`, `GOOS=linux GOARCH=amd64`, and `GOOS=darwin GOARCH=arm64` builds of `./cmd/shadow` — pass; `go run ./cmd/shadow help` — pass. Focused tests covered immutable snapshots, exact-grant enforcement, legacy journal migration, stale/cross-run review rejection, restart persistence, CLI minimization, and a fake-provider agent run with no network grants. Only Windows runtime was exercised.
- Docker integration tests were attempted in the restricted environment and with Docker access; both failed before test execution because `npipe:////./pipe/docker_engine` did not exist. Docker isolation and agent sandbox flow were not reverified in this slice. Prior CI run `36211485992` predates these edits. No real provider inference, live target, or test write was used.

## Run-bound fixture read slice verified on Windows (2026-09-26)

- The internal loopback fixture dispatcher now requires an existing immutable run snapshot. Its trusted rules must match stored action grants; it derives exact GET/read routes from that intersection and binds the store and run ID so a caller cannot select a different run when recording evidence. Missing, legacy, ungranted, different-origin, and changed-method/effect cases fail before dispatch.
- The dispatcher checks the bound snapshot before each request and redirect hop. Encrypted evidence recording checks the same snapshot identity and final read grant inside the SQLite transaction, rejecting a response from a purged or reused run. A request already in flight when a run is purged cannot be recalled; this remains an internal loopback fixture path, unavailable to model tools or live targets.
- PowerShell with `$env:GOCACHE = Join-Path (Get-Location) '.cache/go-build'`: `go test ./internal/broker ./internal/store -count=1` — pass; `go test ./... -count=1` — pass; `go vet ./...` — pass; `go test -race ./internal/broker ./internal/store -count=1` — pass; `go run ./cmd/shadow help` — pass. With `GOOS=windows GOARCH=amd64`, `GOOS=linux GOARCH=amd64`, and `GOOS=darwin GOARCH=arm64`, `go build ./...` — pass. These final checks ran after the evidence transaction change; only Windows runtime was exercised.
- Docker integration was attempted in the restricted environment and with elevated Docker access. Both attempts failed before test execution because `npipe:////./pipe/docker_engine` did not exist. The prior GitHub CI run predates these edits; the updated Windows/macOS/Linux matrix has not run. No real provider, live target, or test write was used.

## Docker recheck after Engine startup (2026-09-26)

- PowerShell with `$env:GOCACHE = Join-Path (Get-Location) '.cache/go-build'` and `$env:SHADOW_TEST_IMAGE='shadow-tools:dev'`: `go test ./internal/sandbox ./internal/agent -run 'TestDockerIsolation|TestAgentToolAndMemoryFlow' -count=1 -v` — both pass with Docker Engine access. The restricted attempt was denied at the named pipe before tests ran; the elevated rerun passed. This supersedes the unavailable-Engine result above for local Windows verification.
- `go run ./cmd/shadow doctor` — pass with Docker Engine and `shadow-tools:dev` available; a credential is present in the OS keyring, but no provider inference was run. `go run ./cmd/shadow tools audit` — pass: 797 command names, 664 distinct executable paths, 0 missing. Restricted attempts for both commands were denied at the Docker named pipe; elevated reruns passed.
- These checks exercised the Windows host and local Linux containers only. The updated GitHub Windows/macOS/Linux matrix has not run; the development build is not a production release.

## Loopback fixture cleanup and semantic verification slice verified on Windows (2026-09-26)

- `NewFixtureCleanupExecutor` accepts only an existing run snapshot with exact trusted test-write and GET/read grants for the same named fixture URL. It checks encrypted evidence that the marker was present after a possible write, journals `cleanup_attempted` before an exact loopback DELETE, refuses DELETE redirects, and records a post-cleanup encrypted GET. Only the fixture's named-marker JSON contract (HTTP 200 present, then HTTP 404 absent) advances the journal to `fixture_cleanup_verified`. Unknown DELETE outcomes stay `cleanup_attempted`; a response that still shows the marker stays `cleanup_observed`. Neither path is replayed automatically.
- This is an internal Go API tested only against local fixtures. It has no model tool or CLI entry point, does not dispatch the original test write, and does not establish cleanup behavior for a real target. Docker container networking and live target access remain disabled.
- PowerShell with `$env:GOCACHE = Join-Path (Get-Location) '.cache/go-build'`: `go test ./... -count=1` — pass; `go vet ./...` — pass; `go test -race ./internal/broker ./internal/store -count=1` — pass; `GOOS=windows GOARCH=amd64`, `GOOS=linux GOARCH=amd64`, and `GOOS=darwin GOARCH=arm64` with `go build ./...` — pass. Focused fixtures cover successful named-marker removal, read/cleanup method separation, ungranted and changed rules, early evidence, DELETE redirect refusal, semantic mismatch, and replay refusal.
- With `SHADOW_TEST_IMAGE=shadow-tools:dev`, `go test ./internal/sandbox ./internal/agent -run 'TestDockerIsolation|TestAgentToolAndMemoryFlow' -count=1 -v` — both pass after allowing Docker Engine access. The restricted attempt failed at the Docker named pipe before execution. Only Windows host runtime was exercised. `gh auth status` reported an invalid GitHub token in the keyring, so this checkout's updated CI matrix has not yet run.

## Release gates still open

1. Scope-controlled network gateway for web/API work: new runs have immutable scope/action snapshots and test-write planning checks them. The internal loopback fixture dispatcher and cleanup executor are bound to run snapshots but are not attached to agent tools; no test-write dispatcher exists. Egress enforcement across every tool, real-target cleanup execution and semantic verification, and a full negative-policy suite remain. Current no-network agent cannot pentest a live website.
2. Multi-agent scheduler, role delegation, shared verified memory, token/cost/context budgets, checkpoints, and crash recovery. The current single-agent 8-step loop is a development slice.
3. Full finding lifecycle with real target evidence, vulnerability verification, PoC status, CVSS v4 calculator, duplicate handling, report exports, and safe browser presentation. The dashboard now shows event and finding metadata for the fixture slice.
4. Complete TUI UX, additional protocol adapters, endpoint capability checks, cache freshness/metadata policy, and provider/keyring testing on all three OSes.
5. Reproducible Docker image: pinned base digest/packages, SBOM, license inventory, vulnerability review, image signature, and 300+ tool audit on release artifacts. The current image uses rolling Kali and an unreviewed inventory.
6. Production evidence recovery/backup, access control, retention limits, provenance/tamper protection, and redaction. Local keyring persistence and explicit per-run purge are implemented, but existing SQLite event payloads are unencrypted and regex redaction cannot guarantee removal of secrets/PII. Do not feed sensitive source or production responses into this development build.
7. Static binary/mobile workflows, product plugin API, Windows/macOS/Linux runtime integration, negative policy tests, and release review.

## Next concrete task

Run the updated CI matrix on Windows, macOS, and Linux once GitHub authentication is restored. Next, design a bounded test-write dispatcher and a recovery workflow that can safely inspect interrupted cleanup without replaying unknown DELETE outcomes. Keep vulnerability verification separate from exact-response reproduction and cleanup observations. Add production-grade evidence backup/recovery, retention limits, and tamper-resistant provenance before accepting sensitive evidence.

## Resume commands

```text
go test ./...
go vet ./...
go run ./cmd/shadow doctor
go run ./cmd/shadow tools audit
```

Docker commands require access to the local Engine. In restricted Codex tool sandboxes, request escalation for Docker socket access rather than treating a permission error as an application failure. On Windows, use a writable `GOCACHE` under this repository when the default cache is blocked.
