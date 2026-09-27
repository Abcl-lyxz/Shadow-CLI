# Shadow production roadmap

Updated: 2026-09-27. This is the work checklist. `CURRENT_STATUS.md` holds the
commands, results, and limitations behind the checks; `PRODUCT_SPEC.md` defines
the intended product. Continue in the current conversation. The number of chat
turns and context size do not define a phase boundary.

`[x]` means the stated item is implemented and verified for its stated scope.
`[ ]` means unfinished, partly implemented, or missing required evidence. A
phase is complete only when every item in that phase is checked and the phase
exit has evidence in `CURRENT_STATUS.md`. Completed local fixture phases do not
grant public-target access or establish production readiness. Work on
independent items may overlap, but public-target work depends on Phases 2 and 3.

**Active phase: Phase 4 — production target network boundary.**
Phase 3 is complete for the local development and controlled fixture scope.
The independent Phase 5 orchestration and recovery work is complete for the
local development scope; Phase 4 still gates public-target agent actions.
Phase 7 development workflows are complete. The current-code CI run tests
TUI capability/cache logic on Windows, macOS, and Linux and passes Docker
isolation on Linux. A bounded Windows real-provider agent drill now passes for
one approved homepage action; native interactive TUI/keyring drills and broader
release routing remain Phase 8 evidence, not production claims.
The next unchecked item is production gateway mediation for every target-capable
tool, including target-specific authentication and reversible writes. The broker
has typed run-bound loopback actions and a locally approved read-only API. The
TUI can load a signed exact GET/read plan and expose only action IDs to its
surface agent; the default run has no network grant. This path has local policy
tests and one bounded public-homepage agent drill with CyberAPI. The drill
recorded a 200 response and passed evidence/provenance audit; it did not verify
a vulnerability. On 2026-09-27 the operator expanded authorization to
anonymous public routes on the exact `https://pteachlab.com` origin; an
operator-authored exact-action plan and its local approval are still required
before another Shadow request. No Google-login account is available. The
controlled-target suite and release review remain open.

- [x] **Phase 0 — Local development foundation**
  - [x] Go CLI and TUI development shell, provider/model catalog, OS-keyring
    provider keys, bundled skills, local dashboard, and event-backed memory.
  - [x] Docker-only agent shell with a network-disabled, nonroot, read-only
    container and no host shell fallback; local isolation integration test.
  - [x] Development image passes the local numerical tool audit. Its release
    reproducibility is tracked in Phase 8.

- [x] **Phase 1 — Loopback fixture network and evidence path**
  - [x] Immutable exact-origin action snapshots, fixture-only URL/DNS/redirect
    checks, durable request budget, and hashed pre-dispatch decisions.
  - [x] Encrypted raw fixture evidence, minimized observations, response
    reproduction status, and metadata-only dashboard finding list.
  - [x] Named marker write, cleanup journal, read-only recovery inspection,
    semantic presence/absence check, and `fixture_marker_v1` journal binding.
  - [x] A typed internal fixture API with negative tests. The shipped TUI
    still grants no network action.

- [x] **Phase 2 — Authentication and cleanup contracts**
  - [x] Document the run/origin/action-bound credential and session contract;
    reject URL userinfo and authentication queries in action rules.
  - [x] Separate cleanup verification from DELETE dispatch and deny fixture
    mutation for new untyped plans while preserving safe legacy inspection.
  - [x] Implement a loopback-only authentication adapter with an OS-keyring
    credential reference, an in-memory session isolated by run and origin,
    bounded cookie/redirect/expiry handling, and no secret-bearing events.
  - [x] Verify another disposable-resource cleanup contract against a
    controlled fixture, including unknown outcomes and restart without
    replaying a mutation.

- [x] **Phase 3 — Evidence and data lifecycle before public-target reads**
  - [x] Evidence key persistence, count-only consistency audit, encrypted
    recovery bundle, manual bounded prune, and structured JSON output masking.
  - [x] Independently preserve append-only provenance for active events and
    evidence, with rollback/deletion detection and recovery tests.
  - [x] Automate bounded retention while keeping unresolved cleanup actions;
    perform restore drills and define backup access controls.
  - [x] Handle sensitive free-form and unknown output fields before they can
    reach agent context, events, dashboard, or reports.

- [ ] **Phase 4 — Production target network boundary**
  - [x] Trusted exact-action rule parser and immutable grants; loopback
    fixtures and a manually approved read-only gateway enforce them.
  - [ ] Mediate every target-capable tool through one typed gateway, with
    explicit authorization, credential/session isolation, and no egress bypass.
  - [ ] Test scope, side effects, DNS/redirect escape, budgets, cancellation,
    unknown outcomes, and cleanup on an explicitly authorized controlled
    target. Do not infer safety from an HTTP method.
  - [ ] Establish trusted rule provenance and real-target evidence policy
    before granting public-target reads or writes.

- [x] **Phase 5 — Agent orchestration and recovery**
  - [x] Bounded single-agent development loop and scope-bound memory.
  - [x] Multi-agent scheduler, role delegation, shared verified memory, and
    per-agent token, cost, context, and tool budgets.
  - [x] Durable checkpoints and crash recovery that do not blindly replay
    side-effecting actions.

- [ ] **Phase 6 — Finding lifecycle and reports**
  - [x] Evidence-backed fixture response observations; security hypotheses
    remain separate from verified claims.
  - [x] Local metadata-only review records PoC status, confidence, and
    same-run canonical duplicates. Explicit CVSS v4 vectors receive calculated
    provisional scores; reviewed fixture metadata exports to HTML, PDF, JSON,
    and SARIF after an operator checks the exact report digest.
  - [x] Optional operator-authored narrative supplies title, asset label,
    observed/expected behavior, prerequisites, impact assessment, validation
    plan, remediation, business priority, and per-metric CVSS rationale to the
    same digest-reviewed development exports.
  - [x] An isolated approved-read data directory can create a response-only
    finding from already saved GET evidence, review it locally, and export a
    digest-approved report without another network request.
  - [ ] Verify vulnerabilities and impact from actual authorized target
    evidence. Authorization now covers anonymous public routes on one origin,
    but the saved homepage response cannot prove a security issue or PoC impact.
  - [ ] Integrate reviewed detail and safely redacted evidence excerpts into
    the finding UI, validate safe PoC explanations
    and full reports on an authorized controlled target, and support Unicode
    narrative in PDF without exposing sensitive target data. A local JSON report
    import and embedded Thai/Latin PDF font now cover the development path;
    controlled-target review and broader font coverage remain open. The local
    JSON import now checks the exact preview digest before displaying detail.

- [x] **Phase 7 — Product workflows**
  - [x] Basic `/connect`, provider/model selection, target/attachment commands,
    bundled skills, and dashboard launcher in the development TUI.
  - [x] Complete TUI task board, trace, memory, finding, budget, pause/resume,
    and compact keyboard workflows; fixture capability and cache freshness
    tests pass on Windows, macOS, and Linux CI. Real-provider routing and
    native interactive drills remain Phase 8 release evidence.
  - [x] Add static APK/IPA and PE/Mach-O/ELF workflows and a narrow,
    provenance-checked plugin API.

- [ ] **Phase 8 — Release evidence and packaging**
  - [x] CI passed on the 2026-09-27 code commit `f76462b` for Windows,
    macOS, Linux, and the Linux Docker isolation job. Local Windows tests
    and cross-builds passed; native interactive drills remain open.
  - [ ] Pin the image and packages; review its SBOM, licenses, vulnerabilities,
    signature, and 300+ tool inventory on the release artifact. The current
    development image has an SPDX SBOM and preliminary scanner results, with
    substantial unresolved license and vulnerability review.
  - [ ] Run current-code CLI and Docker integration on Windows, macOS, and
    Linux, real provider routing with a test credential, and the full negative
    policy suite. A bounded Windows CyberAPI four-role run succeeded against
    the previously approved exact homepage action; other native drills remain.
  - [ ] Record passing evidence for every release gate in `CURRENT_STATUS.md`
    and complete a release review before making a production claim.
