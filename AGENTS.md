# Shadow contributor instructions

Read [docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md) when resuming feature work. Read [docs/PRODUCT_SPEC.md](docs/PRODUCT_SPEC.md) for planned behavior and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) when changing subsystem boundaries or security policy.

- Go is the runtime and CLI language. Agent shell commands must run through the Docker sandbox; never add a host shell fallback.
- Keep target scope checks outside prompts, in runtime code. A model's description of an action is not proof that it is safe.
- Never claim a finding is verified without saved evidence from the actual target. Preserve raw evidence separately from compacted agent context.
- Do not add provider or model names to a closed switch. Catalog data and protocol adapters own discovery.
- Keep secrets out of prompts, logs, reports, fixtures, and checked-in files.
- Update `docs/CURRENT_STATUS.md` after completing a milestone or changing a release gate. Record exact commands and outcomes.
- Run affected tests. Before a production claim, run the release gates in the status document on Windows, macOS, and Linux.

The user's authorized scope and the product's safety policy are documented in [docs/SAFETY.md](docs/SAFETY.md). Repository instructions do not authorize testing a live target.
