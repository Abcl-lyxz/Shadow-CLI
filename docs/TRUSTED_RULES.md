# Trusted action rules

This versioned JSON format is for an operator-authored runtime plan. A model response, website, or repository attachment must not supply or modify these rules. `shadow policy validate FILE --target ORIGIN` checks them but does not attach them to the UI or enable live target traffic. The current fixture tests pass validated rules into `StartRun`, which records hash-only grants in an immutable run snapshot; dispatchers still enforce those grants on every request.

```json
{
  "version": 1,
  "origin": "http://127.0.0.1:8080",
  "actions": [
    {
      "url": "http://127.0.0.1:8080/safe",
      "method": "GET",
      "effect": "read"
    }
  ]
}
```

Each action is one exact URL and method. Effects are `read`, `authentication`, `test_write`, or `blocked`. The runtime does not infer an effect from the method: a GET that mutates state must not receive a read rule. A test write also needs a `shadow_` resource marker, an exact in-scope `cleanup_url`, `cleanup_method` of `DELETE`, and a separate GET/read action for that cleanup URL. Validation rejects mismatched origins, unlisted or duplicate routes, duplicate JSON keys, unknown fields, malformed URLs, URL userinfo, authentication URLs with queries, and missing cleanup reads. It does not prove that the target really follows the declared semantics.

The shipped agent still has no live network grants. Fixture POST and DELETE outcomes that are interrupted or unknown remain in the cleanup journal; a read-only inspection does not replay the mutation. Production network access requires egress enforcement across every tool, real-target side-effect semantics, evidence policy, and negative-policy tests.

`policy validate` confirms syntax and exact-origin consistency and prints a digest of the normalized rule document and IDs for GET/read actions. It does not prove who authored the file or that the target owner authorized the routes. A local operator can run `shadow policy approve FILE --target ORIGIN --confirm DIGEST --out APPROVAL.json` after reviewing the exact rules and digest. The command creates a 24-hour HMAC attestation using a key in a separate OS-keyring service and refuses to overwrite an approval file. `shadow policy verify FILE --target ORIGIN --approval APPROVAL.json` checks the exact origin, rules, expiry, and signature. `shadow target read FILE --target ORIGIN --approval APPROVAL.json --action ID --data-dir DIR` sends one approved GET/read through the gateway and prints only evidence metadata; raw response data is encrypted in the selected directory. `shadow target audit --data-dir DIR` verifies evidence and provenance without printing raw response data. The agent and TUI do not load approval files or expose public-target actions. This local operator provenance is not evidence of target-owner permission. `NETWORK_CONTRACT.md` defines the remaining real-target evidence and controlled-target gates before production use.

Fixture marker and record actions record `fixture_marker_v1` or `fixture_record_v1` in the journal. Untyped generic plans cannot dispatch through the fixture mutation path. `NETWORK_CONTRACT.md` records the runtime session and cleanup requirements. The internal authentication adapter can reach only a snapshotted loopback POST with a run-bound keyring credential; the shipped UI exposes no network action.
