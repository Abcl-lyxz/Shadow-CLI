# Shadow contributor instructions

Read [docs/ROADMAP.md](docs/ROADMAP.md) for the active phase and checklist, then [docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md) for implementation and verification evidence. Read [docs/PRODUCT_SPEC.md](docs/PRODUCT_SPEC.md) for planned behavior and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) when changing subsystem boundaries or security policy.

Work through the roadmap as a continuing project. A request to "continue" means to pick the next unchecked item whose prerequisites are met and carry the phase forward, including implementation, affected tests, and handoff. Do not stop after an arbitrary small slice or ask the user to close and reopen a session to save context. Continue in the same conversation when possible; use compaction and these files to preserve progress. A new session is optional for the user, not a project gate.

When an item needs a real credential, an explicitly authorized target, another OS, or a human release decision, finish independent work first. Leave that item unchecked, record the exact dependency, and ask for input only when it is needed to proceed. Do not convert a local fixture pass or cross-build into a production claim.

- Go is the runtime and CLI language. Agent shell commands must run through the Docker sandbox; never add a host shell fallback.
- Keep target scope checks outside prompts, in runtime code. A model's description of an action is not proof that it is safe.
- Never claim a finding is verified without saved evidence from the actual target. Preserve raw evidence separately from compacted agent context.
- Do not add provider or model names to a closed switch. Catalog data and protocol adapters own discovery.
- Keep secrets out of prompts, logs, reports, fixtures, and checked-in files.
- Mark a roadmap item `[x]` only after its stated scope is implemented and verified. Leave partial, blocked, and untested items `[ ]`; explain the gap in `docs/CURRENT_STATUS.md`. A checked development fixture is not a production release gate.
- Update `docs/ROADMAP.md` and `docs/CURRENT_STATUS.md` after completing a phase item or changing a release gate. Record exact verification commands and outcomes in the status document, and name the next unchecked item.
- Run affected tests. Before a production claim, run the release gates in the status document on Windows, macOS, and Linux.

The user's authorized scope and the product's safety policy are documented in [docs/SAFETY.md](docs/SAFETY.md). Repository instructions do not authorize testing a live target.
