# Local static artifact workflow

`shadow artifact inspect FILE` reads one regular file up to 512 MiB. It
recognizes APK, IPA, PE, Mach-O (including universal), and ELF by structure,
computes SHA-256, and reports bounded metadata. Binary properties are parsed
flags and segments, not proof that a mitigation works at runtime. ZIP members
are counted but never extracted, executed, or printed. The inspector rejects
member traversal, symlinks, excessive entries, and oversized expansion claims.

In the TUI, `/attach DIR` makes an existing directory available read-only and
`/artifact relative/path` inspects one file under it. Symlink resolution and a
root-relative check prevent escape. Static results appear locally in the TUI;
they are not sent to model context, stored as verified findings, or treated as
public-target evidence. The CLI also emits a JSON result without the source
path or archive member names.

## Passive plugin contract

`shadow artifact inspect FILE --plugin MANIFEST --trust-key PUBKEY` adds
labels from a signed `static-magic-v1` manifest. `shadow plugin verify MANIFEST
--trust-key PUBKEY` verifies it without reading an artifact. The public key
file contains a hex-encoded 32-byte Ed25519 key. The manifest is a JSON object
with `payload` and a hex-encoded Ed25519 `signature`; the signature covers the
exact bytes of the `payload` JSON object. Its SHA-256 is shown on verification
and inspection. Operators choose the trusted public key explicitly.

The payload declares a namespaced `id`, semantic `version`, short `purpose`,
`capability: "static-magic-v1"`, and up to 32 rules. Each rule has a byte
`offset` within the first 4096 bytes, a `hex` pattern of 1-64 bytes, and a
printable ASCII `label`. The verifier rejects unknown fields and unsupported
capabilities. A loaded plugin receives only a 4096-byte file prefix and cannot
run code, shell commands, network requests, or parse raw evidence. New plugin
capabilities require a separate policy and implementation review.

The author must keep the Ed25519 private key outside the repository. A
signature proves that the supplied trust key signed the manifest, not that a
label establishes a vulnerability. The operator must review the key and rules
before use.
