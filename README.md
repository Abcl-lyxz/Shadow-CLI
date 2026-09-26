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

Start the TUI with `go run ./cmd/shadow`. Enter `/connect` to list providers, then `/connect <provider>` (or `/connect <id> <https-base-url>` for a compatible custom endpoint). Enter the API key at the hidden prompt. Run `/models refresh`, then `/models <model-id>`. Set `/target https://your-authorized-origin.example`, optionally attach a source directory with `/attach <directory>`, and type an analysis request. `/scope` shows the exact origin, `/dashboard` prints the local evidence dashboard link, `/stop` cancels the run, and `/quit` exits. `/help` lists TUI commands.

This build can analyze attached files through the network-disabled Docker sandbox and a configured model. It cannot actively test a live website or verify a vulnerability. Do not enter sensitive source or production responses into this development build; ordinary event payloads are not encrypted.

Run data stays in `shadow.db` under the OS user config directory. The raw fixture evidence key is generated in the OS keyring on first TUI start, reused after restart, and never written to the database. Losing the key makes existing encrypted raw evidence unreadable, and the TUI will refuse to replace it while evidence remains; there is no in-app key export or recovery. There is no automatic deletion. Use `go run ./cmd/shadow data runs` to list runs, `go run ./cmd/shadow data test-actions <id>` to inspect cleanup obligations for one run, and `go run ./cmd/shadow data purge-run <id> --confirm <id>` to remove one run, including its events, findings, memories, raw evidence, and test-action journal, from the active database. The purge cannot be undone; copies in backups or storage remnants are outside this development retention feature. The test-action command reports journal state only and cannot verify or perform cleanup.

The sandbox image is a large development build. It is not pinned or release approved. `tools audit` checks the checked-in manifest against executable paths in that image and fails until 300 distinct tools are verified.

## Layout

- `cmd/shadow`: CLI entry point.
- `internal`: runtime, policy, provider discovery, Docker, and TUI.
- `sandbox`: Linux tool image and manifests.
- `docs`: architecture, release gates, and handoff.
- `docs/PRODUCT_SPEC.md`: intended behavior and acceptance criteria, distinct from the current implementation.
- `.codex` and `.agents/skills`: repository-scoped Codex workflow.
