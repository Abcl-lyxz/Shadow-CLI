# Shadow CLI product specification

This file describes the intended production behavior. See `CURRENT_STATUS.md` for what is actually implemented and verified. Product decisions in `SAFETY.md` override agent suggestions.

## Supported work

The first production release is single-user and local. It accepts an authorized web/API origin or an attached source/binary directory. Dynamic testing is limited to explicitly scoped web/API targets. APK, IPA, PE, Mach-O, and ELF receive static analysis unless an appropriate isolated execution environment is added and tested. Every result must identify its asset, evidence, test action, and verification status.

## Run state

1. Parse the user's natural-language instruction and show the exact origin or artifact directory to be analyzed.
2. Record the scope, allowed actions, excluded hosts, rate/concurrency budget, provider/model, workspace mounts, and retention policy as an immutable run snapshot.
3. Plan bounded jobs. A coordinator delegates surface discovery, authentication/API review, source or artifact review, and finding verification to specialized agents. Agents receive only the task, relevant skills, short scope-bound memory, and references to prior evidence.
4. All tool actions go through typed runtime APIs. The shell tool runs only inside Docker; network tools go through the scoped gateway. The policy engine decides before an action, records the decision, and never delegates authorization to a prompt.
5. Agents record observations with source event IDs. A verifier checks claimed behavior using a safe reproducible test; otherwise the finding remains a hypothesis. A reporter deduplicates and explains impact, preconditions, remediation, and residual uncertainty.
6. Persist checkpoints and final reports. A restart resumes from recorded jobs without replaying side-effecting actions blindly.

## Provider router and context

Use a live provider catalog and endpoint `/models` discovery, with a cached last-known catalog for offline setup. Protocol adapters expose capability negotiation, tool-call format, context/output limits, and usage reporting. A selected route is snapshotted when a run starts. A route change affects a later run unless the user explicitly restarts the current one. Keys remain in the OS keyring; endpoint URLs and model IDs may be stored in config. Do not send keys to tool containers.

The context manager keeps policy, current task, and recent tool evidence. Older shell output becomes a short topic plus event ID; the raw observation is retrieved only on demand. Shared memory is keyed by scope and provenance, records confidence and expiration, and cannot upgrade a hypothesis to a verified fact. Track per-agent input/output tokens, cost, elapsed time, and tool budgets. Compaction must retain tool-call pairing and instructions needed for a valid continuation.

## Sandbox and network

The production image is one digest-pinned, reproducible Linux image with at least 300 curated distinct security-tool executables, a package/license inventory, SBOM, vulnerability review, and signed release artifact. Per-command containers run nonroot with a read-only root filesystem, dropped capabilities, restricted mounts, resource limits, and no Docker socket. User attachments are mounted read-only; scratch and extracted data stay in bounded temporary storage. There is no host shell fallback.

The network gateway checks origin, DNS destination, redirects, methods, paths, rate, concurrency, response size, and redirects at runtime. It must block third-party subresources and proxy requests from arbitrary tools unless they are mediated by the same policy. Classify actions by possible side effects, not only by HTTP method. Reversible test writes need a named test resource, cleanup plan, action log, and verification of cleanup. RCE, destructive changes to real data, DoS, and uncontrolled exfiltration remain blocked.

## TUI

The TUI should offer a first-run `/connect` flow, searchable provider/model picker, target and scope editor, workspace mounts, per-agent task board, live tool trace, policy decisions, memory inspector, finding queue, token/cost meter, pause/stop/resume, and dashboard launcher. Keyboard navigation and compact terminal layouts must work across Windows Terminal, macOS, and Linux. Slash commands must have discoverable help and clear errors. Secrets are never echoed.

## Browser dashboard and reports

Bind only to loopback and use a per-session secret. The dashboard needs a run timeline and finding detail view with asset, title, CWE where justified, evidence and request/response excerpts after redaction, reproducible safe PoC steps, observed versus expected behavior, prerequisites, remediation, confidence, and verification status. CVSS v4 vectors must be calculated from explicit metrics, not guessed from title or model prose. Show the vector and rationale, allow human review, and separate technical severity from business priority. Provide filtered exports such as HTML/PDF, JSON, and SARIF after source data is validated. Never claim a verified PoC from static inference alone.

## Plugins and skills

Bundled skills supply concise methodology and are loaded on demand. Future repository or user skills must have namespaced IDs, versioned metadata, a declared purpose, and provenance. Plugins may add provider adapters, parsers, passive analyzers, and report exporters through narrow typed interfaces. No plugin gets implicit host command or unrestricted network access; capabilities and data access are explicit and revocable. Validate manifests and signatures before loading release plugins.

## Release criteria

Use local vulnerable fixtures and negative tests for scope escape, DNS rebinding, redirect escape, prompt injection, policy bypass, mount escape, secret leakage, cancellation, crash replay, evidence tampering, and dashboard authorization. Test real provider routing with a configured test credential without recording it. Run the CLI and Docker integration on Windows, macOS, and Linux. Publish no production claim until `CURRENT_STATUS.md` records passing evidence for every gate.

## Design references

- [OpenCode provider interaction](https://opencode.ai/docs/providers)
- [Models.dev catalog](https://github.com/anomalyco/models.dev/blob/dev/README.md)
- [Docker Engine security](https://docs.docker.com/engine/security/)
- [Bubble Tea](https://github.com/charmbracelet/bubbletea/blob/main/README.md)
- [FIRST CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document)
