# Architecture

## Boundaries

The Go host process owns the TUI, provider HTTP connections, persistent state, Docker control, target policy, and loopback dashboard. It does not run model-generated shell commands. The sandbox image owns security executables and runs with a separate scratch directory and read-only user mounts. A host-side HTTP gateway can query explicitly allowed local fixture URLs, but is not an agent tool. General-purpose tools need complete side-effect and evidence policy before receiving live network access; container networking remains disabled.

The event log is the durable source of truth for the current development slice. It stores redacted, capped tool observations; older tool results in model context are compacted to event IDs. Fixture HTTP responses can now be recorded transactionally as a minimized observation event plus an AES-GCM encrypted raw record (URL, response headers, capped body) in a separate table. The 32-byte evidence key is supplied by the caller and is never stored in SQLite; the dashboard has no raw-evidence endpoint. The TUI generates and reuses that key through the OS keyring, checks it against existing evidence at startup, and fails closed if it is lost or wrong. Development data is retained until an explicit per-run purge; the purge transaction removes events, memories, findings, and raw evidence together. This remains a local fixture slice: cross-device key recovery, production retention controls, stronger database access controls, and tamper-resistant provenance remain open.

Finding records link to an evidence-backed observation in the same run. Creation writes a durable event in the same transaction so a later recorded fixture GET can be ordered by event ID; older findings retain the prior timestamp check. An exact response reproduction can mark only a response-observation claim verified when URL hash, status, and complete body hash match. Security hypotheses cannot be upgraded by this response-match path. The dashboard displays status and source event IDs without decrypting raw evidence.

The preparatory action policy classifies exact URL and method pairs declared by trusted runtime code; unknown actions fail closed. A named test write requires a cleanup route before it can be journaled. The store records the plan, possible dispatch, cleanup attempt, and later authenticated same-run observation without raw URLs in the event log. This journal does not execute requests or prove cleanup succeeded. The fixture gateway remains separate from agent tools, and the Docker network stays disabled.

The internal fixture dispatcher applies those trusted rules to GET requests only, derives its own exact URL list, and requires a loopback destination. Authentication and test-write classifications are denied at dispatch. The CLI can list a run's journal metadata after restart for manual review; it cannot run cleanup. Immutable run authorization snapshots and recovery execution are not yet implemented.

## Product modules

1. Provider catalog and protocol adapters resolve an active route and confirm model capability.
2. Orchestrator schedules bounded agent tasks with budgets and cancellation.
3. Policy validates target scope and actions before any side effect.
4. Sandbox manager creates restricted Linux containers via Docker.
5. Store holds runs, events, memories, findings, and evidence metadata.
6. TUI and loopback dashboard consume the same application state.

## Interfaces

The default CLI entry point is `shadow`. Implemented scriptable commands are `shadow doctor`, `shadow sandbox run`, and `shadow tools audit`; `shadow report` is planned. TUI slash commands are versioned with the app. Browser APIs are local and versioned under `/api/v1`.

Provider names and models come from Models.dev plus endpoint discovery. Transport adapters are protocol-specific; a new provider that speaks a supported protocol needs no provider-specific source change. The chosen route must be the route used for inference, including after a TUI change.

## Delivery decisions

The first release is single-user and local. Web/API requests can be tested dynamically. APK, IPA, PE, Mach-O, and ELF analysis is static unless execution is possible inside the Linux sandbox. There is no claim of Windows/macOS/iOS GUI execution.
