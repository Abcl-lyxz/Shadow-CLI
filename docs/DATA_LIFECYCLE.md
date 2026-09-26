# Phase 3 data lifecycle

This describes the local development build. It does not grant public-target
access. The active SQLite database contains unencrypted event metadata and may
contain older free-form event text. Raw fixture HTTP evidence is encrypted.

## Active provenance

The TUI and normal `shadow data` commands open the database with the OS-keyring
evidence key, check SQLite/evidence integrity, and verify an authenticated
append-only event/evidence digest ledger. The ledger and its head are in two
private sibling directories outside the SQLite directory. Each entry binds the
current active event rows, encrypted evidence rows, previous entry, sequence,
and reason with an HMAC derived from the evidence key. A trusted store writer
syncs the ledger and head before committing its SQLite event/evidence change.
An interrupted commit can leave the ledger ahead of SQLite; the next open
fails closed. It does not silently discard or rewrite provenance.

`shadow data audit-provenance` checks the chain, independently held head, and
current database. It detects an edited, deleted, or rolled-back sealed row and
an edited or truncated ledger. A legitimate run purge creates a new entry;
the old entry retains only a digest, not recoverable raw data. First enrollment
seals the existing database as a baseline and cannot prove earlier history.
The default head is a separate local directory, not an off-machine witness.
Copy its exact bytes to independent custody after each session if protection
against a whole-profile rollback or deletion is required. A person able to
replace the database, ledger, head, and OS-keyring key together is outside this
local integrity claim. Concurrent independent Shadow processes are not yet
coordinated by a cross-process provenance lock; run one writer at a time.

## Retention

At each TUI start, after provenance and evidence checks, Shadow removes runs
whose latest event is older than 90 days. Set 1-365 days with
`shadow data retention-set --days N`; it takes effect at the next TUI start.
`retention-plan --days N` remains read-only and `prune-expired --days N --confirm`
remains an explicit CLI sweep. All paths recheck age inside the purge
transaction. Runs with unresolved test-write cleanup or an active fixture
request lease stay in the active database. The TUI reports purged and blocked
counts. No background daemon runs while the TUI is closed. Neither automatic
nor manual retention deletes backup bundles, key files, anchors, SQLite storage
remnants, or the provenance ledger.

## Backup custody and restore drill

Create the archive, recovery key, and archive anchor in three new files. The
key and anchor must be outside the archive directory. Only the operator's OS
account and an explicitly designated recovery custodian should be able to read
them. Create parent directories with private permissions/ACLs; Shadow creates
new files with mode `0600` and refuses existing output files, but this does not
audit inherited Windows ACLs or permissions on removable/cloud storage. Keep
the archive, recovery key, archive anchor, and a copy of the active provenance
head in separate protected locations. Do not put the recovery key in a report,
prompt, repository, or shared sync folder. Restrict backup readers even though
the archive is encrypted: its key restores the raw evidence key. Record who
created and tested each backup outside the Shadow database.

For a drill, create an encrypted bundle with `shadow data backup ARCHIVE
--key-file KEY --anchor ANCHOR`, transfer those files to an isolated test
profile or VM, and run `shadow data restore ARCHIVE --key-file KEY --anchor
ANCHOR` there. The destination `shadow.db` must be absent and its OS keyring
must be empty or hold the same evidence key. Then run `shadow data
audit-evidence` and `shadow data audit-provenance`, confirm expected run/event
counts, and inspect one fixture evidence record through a trusted local test.
The first open on the fresh location creates a new provenance baseline; keep
the source ledger/head in custody to distinguish the restored point in time.
Never delete an active database to make room for a drill. The automated fixture
drill exercises the same encrypted bundle, key installation callback, evidence
read, and fresh provenance enrollment; a real cross-OS keyring/ACL drill remains
a release gate.

Restore rejects an existing target and damaged archive, anchor, key, SQLite
image, or evidence. The in-memory image is capped at 128 MiB. An interrupted
final database write may leave a partial target for a human to inspect before
retry; a failed write after key installation may leave a key without a database.
Plaintext may exist in process memory or swap. There is no secure erase claim.

## Free-form output boundary

Untrusted Docker stdout/stderr is withheld from the agent, event log, and
dashboard; only trusted exit code and output byte count pass through. Model
answers are shown in the local TUI but their free-form text is withheld from
the event log. Model-written memory summaries are withheld, and remembered
event references remain unverified. The dashboard exposes event identity and
metadata with payloads withheld; finding title and asset text are withheld.
Fixture HTTP observations remain typed metadata with only six known MIME
values, while raw responses and headers remain encrypted. A future typed
parser may expose a reviewed subset of source or
tool output. Current shell-only agent analysis cannot use arbitrary command
output, and no report export is available yet.
