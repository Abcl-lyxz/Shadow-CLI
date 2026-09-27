# Typed network and session contract

This document defines the runtime boundary. The shipped UI defaults to no
network grants. An operator can load a locally signed exact GET/read plan into
the TUI; only its surface agent receives action IDs and the host gateway
enforces every hop. Model-generated shell commands still run in Docker with
networking disabled. Public authentication and writes remain unavailable.

## Authentication and sessions

An authentication action must be an exact-origin, exact-URL POST without URL
userinfo or a query string in the operator's immutable run snapshot. Its
protocol adapter must declare the
request shape, the expected success response, and the session material it may
accept. A model-provided URL, header, body, credential, or success claim is not
part of this contract. The internal fixture adapter now sends only a fixed
JSON credential body to a snapshotted loopback POST. The response contract is
HTTP 204 with no body and one host-only `shadow_fixture_session` cookie.

The host must resolve an opaque credential reference from the OS keyring only at
dispatch. The reference is bound to one run, one origin, and one authentication
action. Neither the reference nor the secret is available to an agent, Docker
container, event payload, report, or dashboard. A provider API key is never a
target credential. A missing key, changed run snapshot, unknown action, or
unrecognized response fails closed without creating a session.

A successful adapter creates only an in-memory session owned by that run.
Its cookies or tokens must be attached only to explicitly granted actions at
the same origin. Cookie domain, path, `Secure`, and expiry must be checked;
redirects, subdomains, HTTP downgrade, and cross-run reuse cannot carry session
material. Restart requires an explicit new authentication action, with no
blind replay of a login or other side effect. Authentication responses need
secret-aware evidence handling before their headers or body can be saved.

Loopback tests cover wrong and missing credentials, changed grants, cross-run
reuse, redirect and cookie scope escape, timeout after a possible login,
restart, expiry, and absence of secrets in saved events. A credential reference
also includes the run creation time, so a purged run ID cannot reuse its old
keyring entry. `ReadAuthenticated` attaches the cookie only to a granted GET at
the same pinned loopback destination and refuses redirects. A new adapter has
no session until an explicit login; no authentication response is saved as raw
evidence. The shipped agent and UI do not expose authentication or authenticated
reads. Public-target authentication still requires the production network and
evidence release gates.

## Cleanup protocol

Each reversible write needs an exact named resource, a trusted write action,
an exact cleanup action, a separately granted observation action, and a
runtime-selected semantic verifier. A verifier is code owned by the host; a
status code, model statement, or arbitrary target field cannot declare
success. The protocol returns `present`, `absent`, or `unknown` from validated
same-run evidence. Unknown evidence leaves the obligation open.

The runtime records a pre-write observation, journals that the write may have
happened before dispatch, and sends the mutation at most once. It records
presence evidence before attempting cleanup, journals the cleanup attempt
before dispatch, then records a later observation. On interruption it inspects
the resource with a read action and does not replay a POST or DELETE. Only a
verifier that checks the ordered before and after evidence may resolve the
journal. Unresolved obligations block purge and age-based prune.

The `fixture_marker_v1` verifier requires a complete same-URL JSON GET showing
the named marker present with HTTP 200, then absent with HTTP 404 after DELETE.
The `fixture_record_v1` verifier uses exact `/records` and
`/records/<resource>` routes. Its GET must show an exact active record with
HTTP 200, then an exact deleted record with HTTP 410. Unknown or extra fields,
truncated bodies, and mismatched IDs cannot resolve cleanup. The broker routes pre-write,
recovery, and cleanup checks through one protocol interface. New fixture
plans record that protocol ID in the journal, and untyped plans cannot reach
the fixture POST or DELETE. Pre-existing untyped obligations retain a legacy
marker and may only finish through the full fixture evidence check when their
run snapshot and evidence are available; their
write cannot be replayed. A new GET can reinspect an unresolved observation
after restart, without repeating POST or DELETE. The store performs the final
fixture-specific verification in a guarded transaction.
This does not establish generic target cleanup semantics. New adapters need
their own bounded resource and absence contract, negative tests for ambiguous
responses, and an explicit operator grant before any target write is allowed.

## Public-target release boundary

The current loopback adapter is not a public-target adapter. A public-target
gateway may open only after an operator directly selects the exact origin and
approves a bounded, versioned action document through a trusted local UI or CLI
path. The current CLI can sign and verify a 24-hour local approval over the
normalized document digest and exact origin. Trusted host code can pass a
verified approval to `StartApprovedRun`, which binds its digest and expiry to
the immutable run start. `ApprovedReadNetwork` enforces that binding for
GET/read actions. Future authentication and mutation paths must enforce the
same document, origin, action, expiry, and budget binding. Approval provenance
and the document digest must be
auditable without storing URL queries, credentials, or response data. A model,
target response, attached repository, or dashboard request cannot approve or
amend rules. Replacing the document, changing a route, or restarting without a
valid approval must fail closed. A successful `policy validate` is only syntax
validation and is not approval. A locally signed approval is not proof of
target-owner authorization.

Public-target response and request material may contain personal data and
secrets. Before dispatch, the evidence key, provenance chain, run snapshot, and
retention setting must be ready. The gateway must cap body and header sizes and
record a pre-dispatch decision and a spent HTTP-hop budget. Raw response data
belongs only in encrypted evidence, with run/event binding and a checked
provenance record. Agent context, event summaries, dashboard lists, and reports
receive only reviewed typed fields; URL paths, queries, headers, bodies,
cookies, credentials, and free-form target text are withheld by default. Auth
responses and session material stay volatile and are never stored as evidence.
Response reproduction can verify an exact observation but cannot by itself
verify a vulnerability or impact. Operators must be able to audit and prune
retained evidence without clearing unresolved cleanup obligations.

Any public-target write needs a target-specific host-owned request and semantic
cleanup adapter, bounded test resource, pre-write absence evidence, journaled
possible outcome, and later evidence of cleanup. Ambiguous, timed-out, or
cancelled outcomes remain open obligations and are never blindly replayed.
The controlled-target suite must exercise scope, DNS and redirect escapes,
budgets, cancellation, unknown outcomes, session isolation, and cleanup before
the corresponding capability is enabled. No public-target reads or writes are
enabled by this document alone.
