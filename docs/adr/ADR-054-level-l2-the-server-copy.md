# ADR-054 — Level L2: the server keeps a copy of the code

**Status:** Proposed for [issue #1308](https://github.com/orgFinishUP/finishup/issues/1308), layer 6
of the unified client/server model ([ADR-051](ADR-051-client-server-cut-and-server-targets.md),
*Delivery in layers*), built in two parts. The first builds the copy's write side: the wire format
of a server copy and its one verifier, the sanitized exporter, the pull sync that only the
target's helper answers, the server's encrypted store with forget and expiry, the `code_copy`
method, consent at level L2 and the owner's per-repository choices. The second builds what makes a
copy honest to offer, then opens it: reads served from the copy (decision 12), task pins and the
subject-state commitment (decision 13), per-evidence provenance in every receipt rendering with
the count of fenced reads (decision 14), the erasure of the excerpts derived from a forgotten copy
(decision 15), the `task_close` expiry (decision 8), the server owner's `[server.code_copy]` table
in config 1.4.0 (decision 16) and the remaining reverse paths (decisions 7 and 10). It is the
record [ADR-052](ADR-052-shared-authorization-generations-gate-and-consent-envelopes.md) decision 8
left for level L2; the authorization every sync runs under stays in ADR-052, and the REST contract
in [ADR-053](ADR-053-rest-v1-public-contract.md). **Level L2 is released in this build** (decision
11): `protocol.server_copy.L2_RELEASED` is `True`. Level L1 stays the default byte for byte: a
server offers L2 only when its owner's `[server.code_copy]` table enables an offer, and a client
sends a copy only after its owner consents at L2 on the trusted console.
Design gates: protocol (two workspace operations in a new `copy` family, nine reply reasons, the
`code_copy` method and the `fenced` count of outside reads, in place on the unreleased control
2.10.0; `code_copy` in a REST scope; the `evidence_provenance` member of the unreleased
receipt-result 1.5.0; the `[server]` table as config 1.4.0), privacy/egress (a copy of the code as
a new egress) and storage/durability (the server's encrypted copy store, its tombstones, checkouts
and pending-erasure record; the client's export database and per-repository record; the ledger's
`content_forgotten` family and bundle migration 0020). Maintainer acknowledgement: the maintainer
accepted the unified design on 2026-11-08 (U3, U4, U6, U10, U11, U19 and U20 in ADR-051) and asked
for its delivery as stacked pull requests; under the intake rule in `AGENTS.md` that explicit
request is the design-gate acknowledgement for this scope. The kernel erasure path, which the
first part left as a storage design gate, is covered by the owner's ruling 1 (*Owner rulings*),
which is the maintainer acknowledgement of the storage/durability gate for it. None of this grants
runtime, credential, disclosure or destructive-action authority.
**Implemented by (layer 6, first part):** `src/finishup/protocol/server_copy.py` (the wire format,
the verifier, the snapshot manifest, the release switch and the provenance tokens),
`src/finishup/domain/code_exclusions.py`, `src/finishup/client/code_secrets.py`,
`src/finishup/client/code_copy_settings.py`, `src/finishup/client/code_export.py`,
`src/finishup/client/code_sync.py`, the code-sync responder in
`src/finishup/client/workspace_agent.py` and `code_sync=True` in
`src/finishup/client/remote_binding.py` (used by `src/finishup/client/helper.py`), the `copy`
family and its reasons in `src/finishup/ports/workspace_agent.py`, `ControlMethod.CODE_COPY` in
`src/finishup/ports/control.py` and `ServiceClient.code_copy` in `src/finishup/service/client.py`,
`CodeCopyOffer` in `src/finishup/service/server_profile.py`, `src/finishup/service/code_store.py`,
`src/finishup/service/code_copy.py`, the sync before a read in
`src/finishup/service/workspace_routing.py`, the hub's puller and non-replay in
`src/finishup/service/workspace_hub.py`, the `code_copy` method in
`src/finishup/service/daemon.py` and `src/finishup/service/control_protocol.py`, the key domain in
`src/finishup/service/vault.py`, `code_copy` in the scopes of `src/finishup/rest/contract.py`, the
L2 consent in `src/finishup/cli/server.py`, `src/finishup/cli/server_code.py`, the control 2.10.0
schemas amended in place through `scripts/generate_schemas.py` and the REST contract's entry in
`fixtures/service/rest-api-manifests.case.json`.
**Implemented by (layer 6, second part):** `src/finishup/service/code_checkout.py` (the checkout
reads are served from); the routed readers and the approved-check pin in
`src/finishup/service/workspace_routing.py`; the pins, the evidence tally, the `task_close` expiry
and the erasure hand-off in `src/finishup/service/code_copy.py` and
`src/finishup/service/code_store.py`; `evidence_task_scope` in
`src/finishup/ports/change_capture.py`; the subject-state commitment in
`src/finishup/client/code_sync.py`; the `fenced` counts in `src/finishup/ports/workspace_agent.py`
and `src/finishup/client/workspace_agent.py`; `src/finishup/domain/evidence_provenance.py`; the
receipt lines in `src/finishup/domain/receipts.py` and `src/finishup/application/receipt.py`; the
client renderings in `src/finishup/client/attribution.py`, `src/finishup/cli/render.py`,
`src/finishup/mcp/server.py`, `src/finishup/mcp/summaries.py` and `src/finishup/tui/runtime.py`;
`src/finishup/application/content_forgetting.py`; `src/finishup/kernel/forgotten_content.py`, the
`content_forgotten` family in `src/finishup/domain/events.py` and its projection in
`src/finishup/kernel/projections.py`; `migrations/bundle/0020.sql`; `ServerConfig` and
`ServerCodeCopyConfig` in `src/finishup/config/models.py` (written by
`src/finishup/config/write.py`), `code_copy_offer` in `src/finishup/service/server_profile.py` and
the wiring in `src/finishup/service/daemon.py` and `src/finishup/service/ready_composition.py`;
`retention_from_token` in `src/finishup/protocol/consent_envelope.py`; `allow add|list|remove`,
`forget --all` and `server remove`'s question in `src/finishup/cli/server_code.py` and
`src/finishup/cli/server.py`; the schemas `schemas/config/yoetz-config-1.4.0.schema.json` and
`schemas/events/content-forgotten-1.0.0.schema.json`, receipt-result 1.5.0 amended in place
through `scripts/generate_schemas.py`; and `tests/unit/architecture/test_level_l2_released.py`.
**Amends:** ADR-051 (decision 5: the workspace agent's catalogue gains the `copy` family, eighteen
operations to twenty; *Built in layer 6*), ADR-052 (decision 8's level-L2 follow-ups and O7; the
gate is unchanged and runs again before every export), ADR-053 (decision 6: `code_copy` joins the
`agent` scope, claim-bound only; the REST contract 1.0.0 entry of the manifest vectors is amended
in place), ADR-008 (the vault's installation MAC derives each copy's key-encryption key) and
ADR-009 (zero network and the repository hold refuse before any export; only forget removes what
was sent). **Relates to:** ADR-031 (its credential names start the always-excluded list).

## Context

ADR-051's level L2 (U3, U4) has the server keep a copy of the code, so that a server can read
evidence without this computer's workspace agent answering every read. U6, U10, U19 and U20 fix its
shape: code reaches the server as git data the client sends; the copy holds git-visible files minus
secrets (patterns plus a content scan, each held-out file named); forgetting deletes the copy and
the excerpts derived from it. U11: on a self-hosted server the user chooses the retention among the
options the server offers. ADR-052 decision 8 lists what L2 needs: no sync while the gate refuses
(the hold checked before a bundle is built), stopping future egress and forgetting retained copies
kept apart (design v2 section 8.10; FR-7), code sync in the helper (design v2 section 4.2), consent
at L2 with a retention, and the revision on every sync. Design v2 section 8.3 keeps L2 unavailable
until sync consent, the hold, encrypted storage, forget, provenance and receipts all exist.

A copy of code is an egress that cannot be taken back: once sent, stopping or holding cannot unsend
it.
The first part of this layer built the copy's write side — what is sent, how both ends check it,
where it is kept and how it goes away — and kept L2 unreleased, because the read side that makes a
copy useful (reads routed to the copy, per-evidence provenance on receipts, task pins) and the
erasure of excerpts derived from a forgotten copy that U20 promises were not built. The second
part builds them, with the server owner's configuration table that makes an offer, and releases
L2 in its last code commit (decision 11).

ADR-051 left these questions to the layer that uses them; this record answers them: downgrading
from L2 to L1 and what happens to the copy (decision 9 and *Reverse states*: the copy stays until
it is forgotten or expires); interrupted uploads (decision 6); links, hard links and case
collisions in an export (decision 2); hostile packs (decision 1); exclusion-policy changes
(decisions 2 and 9); key rotation during an upload (decision 4); and the per-repository override
and its reverse (decision 10).

## Decisions

### 1. The wire format: `git-bundle-1` and two synthetic commits

`protocol.server_copy` (SHARED, pure) owns the one sync method, `git-bundle-1`: a git bundle v2
with exactly one ref, `refs/finishup/snap/<n>`, whose v2 pack holds whole blob, tree and commit
objects only, in the sha1 object format, each id computed by the client from the bytes it read. A
snapshot has exactly two synthetic commit shapes: a **base** (no parent) and a **snapshot** whose
one parent is that base, both with author and committer `FinishUP export
<export@finishup.invalid> 0 +0000` and the message `finishup snapshot`. No history, author, date
or message of the repository crosses; the original base commit and its object format travel only
as provenance in the manifest.

One verifier, `verify_snapshot_bundle`, serves the client's own audit and the server's admission,
so the two cannot disagree. It refuses deltas, tags, a second ref, bad ids, trailers or counts,
unreachable or missing objects, any other commit shape, unsorted, duplicate or case-colliding tree
entries, `.git` aliases (by case, trailing dots or spaces, HFS+ ignorable code points, `git~1`,
NTFS streams), `.gitmodules`, `.gitattributes`, `.gitignore` or `.mailmap` as links, unknown
modes, links over 4 KiB or holding NUL, trees deeper than 128 and sizes over the caps.

The snapshot manifest, `yoetz.code-snapshot/1`, travels with the bundle: the snapshot and base
commits and their trees, the original base commit and object format (provenance), the export id,
the worktree identity, the exclusion-policy digest, the completeness lists (`excluded`,
`held_for_content`, `too_large`, `lfs_content`, `case_collision`, `nested_repository`: paths only,
at most 256 each plus an overflow count) and counts (`links`, `gitlinks`, `lfs_pointers`,
`special`, `unrepresentable`), the subject-state commitment (decision 13), the profile-revision
triple, the purpose (`base` or `check`), `synced_at`, `files` and `bytes`. The module also defines
the per-evidence provenance tokens (`EVIDENCE_PROVENANCE`: `server_copy_read`,
`client_attested_read`, `client_check`, `client_observation`, `outside_read`, `stale_copy_read`),
which a level-L2 task's receipt counts (decision 14).

### 2. The export: what is sent, what is held out, and the export database

`client.code_export` is the sanitized exporter, and only the helper runs it (decision 4). Its gate
runs first (FR-7): a refusal raises before any file is read or any object written. The **base** is
the original commit, listed with `git ls-tree` and read with `git cat-file`; the **current tree**
is every git-visible file, tracked or untracked but not ignored (the owner's own global ignore file
included), read from the worktree without following links (`O_NOFOLLOW` for each directory, the
type checked on the open descriptor).

Held out of **both** trees, so that nothing held out reads as deleted: paths matching an exclusion
pattern; files over `max_file_bytes`; known secret content (decision 3) unless the owner allowed
those exact bytes; a Git LFS file whose bytes are not its pointer; case-fold collisions; nested
repositories — each named in its completeness list — and unsafe or non-UTF-8 names, special files
and multiply-linked files, which are counted. A link is sent as its target text, a submodule as a
gitlink, an LFS file as its pointer. A sanitized tree over `max_repo_bytes` is refused
(`code_copy_too_large`): no partial copy is sent.

The exclusion patterns start from `domain.code_exclusions.ALWAYS_EXCLUDED`: ADR-031's credential
names (`.env`, `.env.*`, `.envrc`, `.git-credentials`, `.htpasswd`, `.netrc`, `_netrc`, `.npmrc`,
`.pgpass`, `.pypirc`, `credentials`, `credentials.json`, `credentials.toml`, `id_rsa`, `id_dsa`,
`id_ecdsa`, `id_ed25519`, `*.jks`, `*.kdbx`, `*.key`, `*.keystore`, `*.p12`, `*.pem`, `*.pfx`,
`*.tfstate`, `*.tfvars`) plus `.aws/credentials`, `.docker/config.json`, `.dockercfg`, `*.asc`,
`*.gpg`, `*.kubeconfig`, `*.ovpn`, `*.p8`, `*.ppk`, `*.secret`, `*.secrets`, `id_*`, `kubeconfig`
and `secrets.*`. The server's `exclusions.always` and the owner's list for the repository
(decision 10) add to it; nothing removes a name. Matching is case-insensitive: a pattern without
`/` matches the last component, one ending in `/` a directory anywhere, one with an inner `/` the
whole path from the root. The server's exclusions are part of its profile, so a change to them is
a profile change (decision 9); the manifest records the digest of the policy each snapshot was
built under.

The **export object database** is FinishUP-owned git loose objects under
`<target root>/state/code-export/<digest of the repository key>/`, never the repository's own
`.git`, with `export.json` (`yoetz.code-export/1`: the export id, the next ref number, the
snapshots sent and, once the gate passed, `root`, the repository's folder, so that `server code
forget --all` can claim it again; decision 7). Every admitted object is made again there from the
bytes read. A bundle carries only what the server's have-set does not reach (incremental). Before
it is offered, the **object-closure audit** parses it back with the server's verifier and requires
that every object in it was admitted in this run; any difference refuses the export
(`code_export_audit_failed`, answered to the server as `code_export_failed`). The verifier's own
caps (64 MiB and 200,000 objects per bundle) hold whatever `max_repo_bytes` the server offers.

### 3. The content scan

Before a file enters the export its bytes are scanned (`client.code_secrets`): the diagnostic
privacy scanner's high-confidence findings (private key blocks, `sk-`, `ghp_`, `github_pat_`,
`xox*` and `AKIA` tokens, passwords in URLs) plus formats only L2 adds (`sk_live_` and `rk_live_`,
`AIza…`, `glpat-`, `npm_…`, `pypi-AgEI…`, `xapp-`, Slack webhooks, Azure `AccountKey=`,
`ASIA…`). A match holds the file (`held_for_content`, named in the manifest) until the owner allows
those exact bytes (decision 10). Heuristic matches such as `password = …` do not hold a file
(*Owner rulings*, 2). The scan is not a secret guarantee, and the disclosure says so.

### 4. The pull sync: the workspace-agent channel, in the helper only (FR-7)

The server pulls; a client never uploads on its own. Two workspace operations form a new `copy`
family (the catalogue grows from eighteen operations to twenty): `code_sync_prepare` `{purpose,
have (at most 16), base_commit, issuer, revision, profile_digest}` → `{unchanged, sync_id,
manifest, size, sha256, retention}`, and `code_sync_read` `{sync_id, offset, length (at most
3 MiB)}` → a base64 chunk. They are ordinary `workspace_call` frames on every edge (SSH control
frames, REST agent work), so no upload route exists (*Owner rulings*, 3).

Only the target's helper declares them: `client.code_sync.CodeSyncResponder` is given to a
background agent built with `remote_workspace_binding(..., code_sync=True)` for a target consented
at L2. The MCP bridge, CLI commands and hooks never declare them; the hub sends an operation only to
an agent that declares it, so the server never asks them, and it never replays either to another
connection.

`code_sync_prepare` checks, in this order and before anything is read for the export (FR-7):

1. level L2 is released in this process;
2. the connection's own admission still holds (generations, credential, the consent's identity,
   the repository's hold as admitted);
3. the gate again, on the record as it is now (`client.authorization.gate`: zero network, the
   disclosure, the kind, the consent verdict, the repository's hold);
4. the consent is at L2, and the revision the server names is the one that consent admits (else
   `server_profile_changed`);
5. the owner's per-repository level is not L1, and that record can be read (fail closed).

Its refusals are closed reply reasons: refused `code_copy_not_consented`, `repository_egress_held`,
`repository_egress_kept`, `server_authorization_changed`, `server_profile_changed` and
`zero_network_remote_selected`; unavailable `code_copy_too_large`, `code_export_failed` and
`code_sync_unknown` (no bundle prepared under that id, or its time passed). A prepared bundle is
kept in the helper's memory for two minutes, shared by every agent of that worktree in the helper
process. Only after every check passes does the responder compute the subject-state commitment
(decision 13) and build the bundle.

On the server, `service.code_copy.CodeCopies` pulls in the worker thread of the read it precedes:
the task base (`read_task_base`) and a check (`capture`, `capture_metadata`, and an approved check
of a task the copy serves, decision 13). One sync per repository runs at a time (a caller that
finds one running waits for its outcome); each outcome is a closed bounded event
(`code_copy_sync_<outcome>`), and a sync never fails the read. The puller names the original base
commit to the client. Which reads the copy then serves is decision 12.

A key change (`server login`, `server logout`, `server remove`) moves the credential generation and
stops the helper (ADR-052 decisions 4 and 23), so a sync under way cannot finish its reads, and an
upload that does not complete is never committed (decision 6).

### 5. The `code_copy` method

Control method `code_copy`: body `{action: status | forget}`, result `{action, copy, forgot}`.
`copy` is `{snapshots, stored_bytes, created_at, last_sync_at, retention: {kind, days}}` or `null`;
`forgot` is what forget deleted (decision 7) or `null`. It is claim-bound only (it names the
claimed repository and no other), structural (answered while the vault is locked and under another
revision) and never answered to the MCP bridge; a service that keeps no copies refuses it
`method_forbidden`, which the CLI names `server_level_unavailable`. Over REST it is in the `agent`
scope, and so in `operator`, and in `CLAIM_BOUND_ONLY_METHODS`: making a server keep less is never
an operator privilege. It joins the full method list only, never the released one a
manifest-mismatch answer lists (#436). Control 2.10.0 (unreleased) is amended in place, and so is
the REST contract 1.0.0 (unreleased) entry in `fixtures/service/rest-api-manifests.case.json`. The
second part does not change it: a forget's erasure of task content (decision 15) runs on the
server after the answer's own deletes.

### 6. The server's encrypted store: keys under the vault's authority, admission, quotas, ownership

`service.code_store` keeps copies under `<state>/code-copies/`, one copy per (principal,
repository commitment), both kept only as digests. The principal namespace comes from the claim,
which the REST edges namespace by the key's principal (ADR-053 decision 6), so keys with different
principals never share a copy.

Every object, every snapshot manifest and the copy's index is an AES-256-GCM frame whose associated
data binds the copy and the object. Each copy has its own random data key, stored only wrapped
(AES key wrap) under a key-encryption key that the vault's installation MAC derives for that copy
(domain `yoetz/code-copy-kek/v1`) and that is never stored; the wrapping record is
`yoetz.code-copy-wrap/1`. A locked vault reads and admits nothing, so relocking the vault makes
every copy unreadable (*Owner rulings*, 4).

An upload is staged encrypted under a key held only in memory. Commit decrypts it, verifies it with
the verifier of decision 1, checks the manifest against what was verified, against the revision the
service issues and against the claim's worktree, and applies the quotas: a checkout of at most
`max_repo_bytes`, four times that per copy and sixteen times per principal. It writes the objects,
then the manifest, then the index, and the copy record (`copy.json`, `yoetz.code-copy/1`) last, so
a crash leaves the previous snapshot in force; a service start removes staged uploads and folders
without a record.

### 7. Forget, the tombstone, the fence and every repository at once

Forget advances the copy's epoch in the tombstone record (`yoetz.code-copy-tombstones/1`)
**first**; then, when tasks are pinned to the copy, it writes the owner-only pending-erasure record
(`<state>/code-copies/erasures.json`, `yoetz.code-copy-erasures/1`: per task the forget's id, its
reason, the task id and its evidence account, at most 4,096 pending tasks); then it deletes the
copy's folder and its checkout (decision 12); then each pinned task's ledger erasure runs
(decision 15), and its entry leaves the pending record only once that task's erasure says it is
done. A pending erasure is retried at the next forget, expiry or service start. Forget is
idempotent and reports exactly what it deleted (copies, snapshots, objects, bytes) with `backups:
not_managed`. A sync is fenced from the moment the server asked for it: the puller reads the epoch
before `code_sync_prepare`, and an upload begun under an older epoch is refused
(`code_copy_forgotten`). Forget acts on the repository the claim names; another repository's copy
needs its own.

`finishup server code forget [--repository FOLDER]` prints what the server deleted, says that
backups of the server's folder are not managed and that the tasks that read the copy lose the
captured changes and review excerpts they kept from it and say their content was forgotten, while
their findings and checks stay; it removes this computer's export folder for that repository.

`finishup server code forget --all [--json]` forgets every repository this computer's export
records name for the selected server: since `code_copy` acts on the claimed repository only, each
record's `root` is claimed and forgotten in turn, as `server code forget` does. One that cannot be
forgotten is named by its position and short id with its closed reason and what to do
(`export_record_unreadable`, `repository_folder_unknown`, `repository_folder_missing`,
`repository_invalid`, `repository_changed`, or the server's refusal), never skipped; the command
exits 0 only when every one was forgotten, else 20 (`code_copy_forget_incomplete`). `--all` with
`--repository` is a usage error. An export record written before `root` was recorded is
unreadable to it, and the next sync starts a new export.

`finishup server remove NAME` of a target this computer sent copies to asks first on the trusted
console: `yes` forgets every repository through that target's own root, as `forget --all` does,
and stops before anything is removed if one is not forgotten (`code_copy_forget_incomplete`);
`no` removes it and says the copies stay; any other answer is `authorization_declined` and nothing
is removed. `--forget-copies` and `--keep-copies` (not both) answer without the console; with no
console and no flag it removes as before and prints the warning naming `--forget-copies`.
Removing a target deletes its claim salt, so this computer can never forget those copies
afterwards: they stay until they expire or the server's owner deletes them.

### 8. Expiry

The retention is `days:N`, `task_close` or `until_forgotten`, chosen at consent among the options
the server offers. Expiry runs at service start and every 10 minutes, and forgets as in decision 7
(reason `expired`): a `days:N` copy once N days passed without a sync; a `task_close` copy once the
work of every task pinned to it (decision 13) is no longer open, as the lineage catalog keeps it
(an unknown or unreadable work state counts as open, an abandoned one as closed), so a copy no
task was pinned to does not expire this way; `until_forgotten` never.

### 9. Consent at L2 and the disclosure

A server offers L2 (levels `L1` and `L2`, `L1` required) only with a code-copy offer
(`service.server_profile.CodeCopyOffer`: `max_repo_bytes`, `max_file_bytes`, the retention options
and default, its exclusions), which comes only from the server owner's `[server.code_copy]` table
(decision 16), **and** L2 released; the profile's `exclusions.always` is the offer's set together
with `ALWAYS_EXCLUDED`.

`finishup server add|use … --level L1|L2 --retention task_close|until_forgotten|days:N` records
the consent on the trusted console; both options are shown in help. `--level L2` is refused
`server_level_unavailable` when the server does not offer it, and the retention must be one the
server offers (the server's default when none is given); `--retention` is parsed by
`retention_from_token`, the one parser the configuration table also uses, so `days:0` is a usage
error. `server use` keeps a level and retention already agreed to, and
never narrows on its own: `server use` of a target consented at L2 whose server no longer offers L2
is refused `server_level_unavailable` until the owner chooses `--level L1`. The L2 disclosure is
locally owned text, never server prose: the server keeps a copy of each repository used with it —
its git-visible files, never its history, minus the always-excluded names, the server's exclusions
and the owner's list; the names of left-out files are sent, never their contents; contents are
scanned for known secret formats, and a match is held back until the owner allows it; names and
scans are no guarantee; the retention chosen; how to forget and how to keep one repository at L1;
holding or stopping later does not remove what was sent, only forget does. The L1 text is unchanged
and so is `DISCLOSURE_VERSION` (3), so no consent already given is asked again. A change to the
server's exclusions follows ADR-052 O6: a set that only adds patterns is a narrowing, anything else
asks again. Moving a target from L2 to L1 (`server use NAME --level L1`) stops future sends; the
copy stays until it is forgotten or expires.

### 10. The owner's per-repository choices

`<target root>/config/code-copy.json` (`yoetz.server-code-copy/1`: owner-only canonical JSON, read
fail-closed, so a record that is not owner-only, is a link, is too large, malformed or another
target's refuses every export) holds, per repository key (the key the repository hold uses):
`level` (only `L1`, a step down from the consent, never more), `exclude` (patterns added to that
repository's copy) and `allow` (a path and the `sha256` of the exact bytes allowed after the scan
held them; any other content of that path is scanned again). It is a record of its own, not a `/2`
of the per-target repository map (*Owner rulings*, 4).

`finishup server code` (`client_only`, shown in help): `list` and `forget` (`[--repository FOLDER]
[--json]`, and `forget --all`, decision 7) ask the server; `exclude add|remove|list PATTERN`,
`allow add FILE`, `allow list [--json]`, `allow remove PATH` and `level L1|default` edit this
computer's record. What sends less needs no question (`exclude add`, `level L1`, `allow remove`);
what sends more is confirmed on the trusted console (`exclude remove`, `level default`, `allow
add`). `allow add` records the path and the digest of the file's exact bytes and refuses a folder
or a named pipe as not a regular file; `allow list` shows the paths with `sha256:` and the first
12 hex digits, never contents; `allow remove` is idempotent, says when the path was not allowed,
and says that what was already sent stays until it is forgotten. An exclusion is checked before
the scan, so `exclude add` of an allowed path keeps it out again. A server that keeps no copies
refuses the commands that reach it (`server_level_unavailable`).

### 11. The release switch: `L2_RELEASED` is true, and what it rests on

`protocol.server_copy.L2_RELEASED` is `True`, set in the last code commit of this layer, as
`ssh`, `https` and `local_port` opened in the last code commits of theirs. `l2_released()` reads
it; no flag, variable or file a user can set changes it, and the in-process switch that tests and
the first part's real-network harness used before the release is gone. The release rests on
every protection design v2 section 8.3 requires, each named by the code that enforces it and the
tests that hold it in `tests/unit/architecture/test_level_l2_released.py`, so none can be removed
or renamed away while L2 stays released: **sync consent** (`CodeSyncResponder`,
`remote_workspace_binding`, `retention_from_token`; decisions 4 and 9), **the hold before the
bundle** (`export_snapshot`; decision 2), **encrypted storage** (`CodeStore`, `VaultCopyKeyring`,
`CopyCheckouts`; decisions 6 and 12), **forget** with the erasure of derived excerpts
(`CodeStore.forget`, `CodeCopies.attach_erasure`, `forget_task_content`, `forget_every_copy`;
decisions 7 and 15), **provenance** (`EvidenceProvenance`, `CodeCopies.provenance`,
`RoutedChangeCapture`; decisions 12 to 14) and **receipts** (`server_copy_receipt_block`,
`evidence_provenance_section`; decision 14).

Releasing it opens nothing by itself: a service offers L2 only when its owner's
`[server.code_copy]` table enables an offer (decision 16), and a helper syncs only for a target its
owner consented at L2 (decision 9). Without both, every surface behaves as at level L1, byte for
byte. The terminal interface has no L2 flows: consent, `server code` and `server remove`'s question
are CLI only, and the terminal interface renders a receipt's evidence lines (decision 14).

### 12. Reads from the copy

`service.workspace_routing` decides, per claim-bound read, who answers it. A read is **served from
the copy** when this service keeps copies (decision 11), the claim's repository has a copy, and
the read's snapshot is known: the sync that precedes it (task base or check) returned `synced` or
`unchanged`, or, when the client is offline, the task's pinned snapshot (decision 13).

- **One source per task.** A task whose base was read from the copy reads every git read from the
  copy; a task whose base the client read (started at L1, or before its first sync) keeps every
  git read with the client's agent (client-attested), so commit identities never mix. A capture
  from the copy diffs against the pinned snapshot's own sanitized base when it has the same
  original base as the task base, so a file held out later never reads as changed or deleted.
- **Served from the copy:** the task base, the capture and its metadata, the probe of requested
  paths, change line counts, the classification of undeclared references, the reviewer's list,
  read and declared-test reads beneath the root, task inputs inside the root, and an observation
  workspace's changed paths and inspection.
- **Still answered by the client's agent:** reads outside the root (`outside_read`, under the
  outside-read policy, counted apart), the check policy, the subject state and approved checks
  (`client_check`; U7).
- **Offline.** When the sync finds no client (no agent, a disconnected agent, the hub unavailable,
  its deadline), reads use the task's pinned snapshot, the copy as last synced (`stale_copy_read`,
  with its sync time); a reviewer read that follows a check served offline is stale too. An
  approved check then fails `workspace_agent_unavailable` (agent reason `no_agent`), never a pass.
- **A refused sync never falls back to the copy.** After a refusal (the hold, zero network,
  consent, revision) the read goes to the client's agent, which answers or refuses as at L1.

`service.code_checkout` materializes the snapshot a read needs: one owner-only (`0700`/`0600`)
working directory per copy under `<state>/code-copies/checkouts/`, written only from objects the
store verified and decrypted, never through a link, `HEAD` detached at the snapshot's synthetic
base and an index built in the adapters' isolated git environment; links stay links and gitlinks
are empty directories. It is updated in place, rewriting only changed paths, so unchanged files
keep their `stat` identity and the task-start untracked baseline stays valid; a per-copy lock
serialises its readers. The service's own local adapters read it unchanged. It is removed at
service start, on forget and on expiry. Each read is attributed to its task by
`evidence_task_scope`, entered by every check, the task-start base record, the semantic case
evaluation and the observation-verification workers.

### 13. Pins, the subject-state commitment and `code_snapshot_mismatch`

Every sync for a task pins the task to that snapshot in the copy record (`pins`, plaintext task ids
with ids and counts only); later reviewer reads of the task read that snapshot, and the
`task_close` expiry reads the pinned tasks (decision 8). The client fills the manifest's
`subject_state` with the same subject-state digest its agent computes for an approved check, or
`null` when it cannot be captured. An approved check of a task the copy serves syncs first
(purpose `check`); a run whose subject-state digest differs from the pinned snapshot's is `stale`
/ `subject_state_mismatch` and records the bounded event `code_snapshot_mismatch`; never a pass.

### 14. Per-evidence provenance, the receipts and O7

`domain.evidence_provenance.EvidenceProvenance` (`yoetz.evidence-provenance/1`) is one task's
account: `reads` per token (`server_copy_read`, `client_attested_read`, `client_check`,
`client_observation`, `outside_read`, `stale_copy_read`), `fenced_reads`, `snapshot` (`{synced_at,
tree}` of the copy snapshot last read, or `null`) and `content_forgotten` (`{at, reason: owner |
expired}`, or `null`). It is counted per task in the copy record's pin entry: buffered, and
written at each sync, account, forget and expiry and every 32 reads. Client observations are
counted from the task's own ledger (hook-observed events).

- **The receipt member.** Receipt-result 1.5.0 (unreleased, amended in place) gains the optional
  `evidence_provenance` member, exactly the account's JSON, present only for a claim-bound task
  whose account is level L2's (a read from the copy, fresh or stale, or a forgotten copy's
  marker). It is recomputed on every receipt and replay, stored receipts and their digests are
  unchanged, and a paged result delivers it on its first page. The REST contract 1.0.0 manifest
  digest is amended in place.
- **The service's text and markdown.** `domain.receipts.server_copy_receipt_block` ends such a
  receipt's "Workspace evidence" section with fixed lines, never level L1's sentence that the
  server did not read the repository: that the server read evidence from its copy synced from the
  client machine and the client's agent answered the rest (or, when no read from the copy is
  counted, that none is); "Evidence reads by source (yoetz.evidence-provenance/1): …" with all six
  tokens, zeros included; the fenced count; the copy's sync time and the tree id's first 12 hex
  digits; what a stale read means (the client was offline); the content-forgotten marker ("the
  owner forgot it" or "its retention expired"; findings and checks remain without their
  excerpts); the hook-observation line when hook-observed; and "Served by FinishUP service <id>
  (connection: client_claim)". The longest block is 1,310 characters, within the 2,048 of a
  closing section.
- **When the account cannot be read**, the receipt has no member and an "evidence unknown" block
  that says neither that the server read its copy nor that it did not; an unreadable
  `content_forgotten` event reads as unknown, never as level L1's words.
- **Client renderings.** CLI text, MCP text and summary, and the terminal interface render the
  same lines from the member of a JSON receipt (`client.attribution.evidence_provenance_section`)
  and never add the L1 line; paged receipts keep naming only the producing service. A connection
  whose target was consented at L2 says, beside its status, that the server reads evidence from
  its copy where it has one and the client's agent answers the rest (`ServiceAttribution.level`,
  `ServiceClient.consent_level`); level L1's bytes are unchanged.
- **O7.** `OutsideInputsRead.fenced` and `OutsideSnapshotsRead.fenced` (0 to 4,096, required on
  the wire, control 2.10.0 amended in place) count the outside reads the client's agent refused
  because they reached a held repository; the service adds them to the task's `fenced_reads`, which
  the receipt shows when the account is level L2's.

### 15. Forgetting what tasks derived from a copy (U20)

When a copy is forgotten (by its owner or on expiry), the service forgets, in every task pinned to
it, the content derived from it (`application.content_forgetting.forget_task_content`, outcomes
`forgotten`, `task_not_found`, `task_unavailable`, `erasure_incomplete`):

1. It appends one service-written `content_forgotten` 1.0.0 event
   (`schemas/events/content-forgotten-1.0.0.schema.json`; payload `forget_id` (32 hex), `reason`
   `owner|expired`, `source` `server_copy`, `objects_erased`, and `provenance`, the task's account
   counts and fenced reads). Agents cannot publish it (`event_family_not_admitted`), and a ledger
   in which anyone but the service wrote one is corrupt. Bundle storage version 20 (migration
   0020) admits the family; a bundle at 19, as v0.3.0 wrote it, upgrades.
2. It then erases the task's standalone content objects: check-change objects (the captured diff
   and the task inputs inside the root) and the reviewer's semantic-response objects (its judgment
   with the snippets it quoted), marked `redacted` in the object inventory and deleted. Never an
   event's payload object: the ledger is hash-chained, so a recorded event stays exactly as
   written.

It is idempotent by `forget_id`: a retry records nothing new and erases what is left.
`kernel.forgotten_content` masks, in every projection built after the event, the quoted excerpts
of checks that tested work from before it: finding challenge snippets and check review summaries
read as absent, and the snippet of each verified row reads as a fixed "forgotten" text (released
contracts require one). Findings, checks, ids, severities, outcomes and counts stay, so the task
never reads as if it had no content. The mask covers projected findings, the evidence view (status
and the next review packet), receipt context (receipts pinned before the event too), check results
live and after a restart, and pinned or cached status views. A recovered job whose check change
was erased ends with the gap `check_time_change_unavailable_content_forgotten` (reason
`content_forgotten`). Status history omits the event's rows; the receipt shows its marker
(decision 14).

### 16. The server owner's offer: `[server.code_copy]`, config 1.4.0

The offer comes from the server's own `config.toml`, as config 1.4.0
(`schemas/config/yoetz-config-1.4.0.schema.json`), since 1.3.0 was released with v0.3.0 and is
frozen (*Owner rulings*, 5). `ServerConfig` (`[server]`) holds only `code_copy`
(`ServerCodeCopyConfig`):

| Key | Default | Rule |
|---|---|---|
| `enabled` | `false` | `false` (or no table) offers nothing |
| `max_repo_bytes` | 67108864 (64 MiB) | 1 to 2^40 |
| `max_file_bytes` | 16777216 (16 MiB) | 1 to 2^40, at most `max_repo_bytes` |
| `retention` | `["task_close", "days:30", "until_forgotten"]` | 1 to 16 distinct tokens: `task_close`, `until_forgotten`, `days:N` (N 1 to 36500, no sign or leading zero) |
| `retention_default` | `"days:30"` | one of `retention` |
| `exclusions` | `[]` | patterns of 1 to 512 characters, no control or DEL characters, not only slashes or stars, no repeats; with `ALWAYS_EXCLUDED` at most 256 patterns and 32,768 canonical bytes |

Only `config.toml` sets it (no variable or override), and no CLI command writes it. Unknown keys are
`unknown_config_key`, bad values `config_value_invalid` naming the key only; every value is checked
even when `enabled` is `false`, and a `[server]` table without `code_copy` is valid and offers
nothing. The service reads it at start: a change takes a restart, which advances the profile
revision, so clients are asked to consent again. The daemon builds `CodeCopyOffer` from it
(`code_copy_offer`) and, only then, the copy store, its checkouts and its expiry.

## Not built

- The terminal interface's L2 flows: consent at L2, `server code` and `server remove`'s question
  are CLI only (the terminal interface renders a receipt's evidence lines).
- Any macOS or WSL 2 run of level L2.
- A Codex, Claude Code or Cursor session against a server keeping a copy.
- The WAN timing gate and an upgrade over running helpers and services (layer 7).

## Honest limits

1. Filename patterns and the content scan are not a secret guarantee, and heuristic matches do not
   hold a file.
2. The names (paths) of left-out files are sent; their contents are not.
3. Relocking the server's vault makes its copies unreadable but does not erase plaintext a server
   owner already copied out of a running service. A copy's checkout is plaintext while the copy is
   in use, until the service starts again, the copy is forgotten or it expires.
4. Backups of the server's folder are not managed (`backups: not_managed`).
5. Holding a repository, narrowing to L1, zero network or stopping stop future sends only; only
   forget removes what was sent.
6. Forget from one computer reaches the copy of the repository it names; `forget --all` reaches
   only the repositories this computer's export records name, and one whose record predates `root`
   needs `server code forget` in that repository. Once a target is removed this computer cannot
   forget its copies at all: a `days:N` or `task_close` copy waits for its expiry, an
   `until_forgotten` one for the server's owner.
7. Expiry runs at service start and every 10 minutes, so a copy past its retention stays until the
   next run. A `task_close` copy no task was pinned to does not expire on `task_close`.
8. A server whose owner turns the offer off (or removes the table) keeps the copies an earlier offer
   left, encrypted, without serving them: nothing is synced or read from them (a sync is refused
   `server_level_unavailable` before the client is asked), and they can still be listed, forgotten
   and expire, and their tasks' excerpts erased.
9. The checks run once per sync, at `code_sync_prepare`; `code_sync_read` serves only the bundle
   prepared then, for at most two minutes; a chunk the server already read stays with it.
10. `max_repo_bytes` above 64 MiB is accepted, but a sync over 64 MiB or 200,000 objects fails the
    export's audit.
11. Evidence counts are buffered (written at each sync, account, forget and expiry and every 32
    reads), so a crash or a service stop can lose a few counts (the real-network run showed one
    copy read uncounted after a stop).
12. Copy-served evidence: commit ids are synthetic; task inputs named by an absolute client path
    are not found in the copy; a file tracked but not committed that matches `.gitignore` reads as
    ignored, and every file in the copy counts as not ignored; after a service restart the
    checkout is rebuilt, so untracked files that predate a task read as additions (more change,
    never less).
13. Erasure (decision 15): event payloads keep their encrypted bytes, masked in every view;
    receipts already delivered and recorded receipt objects keep what they showed; the operation
    journal's resume roots (`CHECK_RESUME` objects, which embed the projection a check read,
    earlier snippets included) are kept; task-input snapshot sets (files outside the repository the
    client sent) and hook-captured content are kept; reviewer prose (finding summaries and details,
    challenge discrepancies and uncertainties, correctness advisories) is kept; no status surface
    shows the marker; the privacy-audit review packet is held only in service memory, never on
    disk. At most 4,096 tasks wait in the pending-erasure record.
14. The real-network runs were on Linux only. The first part's: the gateway edge over real TLS,
    the native edge and a private `sshd`; consent at L2; syncs at start and at a check; `server
    code list`; a store holding no plaintext; the hold and zero network refused before any bundle;
    forget; a sync in flight refused `code_copy_forgotten`; a `days:7` expiry with the time
    simulated. The released build's, with the offer from a real `[server.code_copy]` table: on the
    gateway and native edges and over a private `sshd` (relay), consent at L2, the task base and a
    check read from the copy, the receipt's evidence lines in text, JSON (`evidence_provenance`) and
    the CLI's rendering, the L2 status line; on the gateway edge also an offline client's check
    read from the copy as last synced (`stale_copy_read`), the hold and zero network refused before
    any bundle, `allow add|list|remove`, forget with the content-forgotten marker in text and JSON
    and the erasure recorded, a sync in flight fenced, a `task_close` expiry after the task closed
    and a restart, and `forget --all`; `server remove --forget-copies` (native) and `server remove`
    asking on the trusted console (`sshd`). Not run over a network: a reviewer read from the copy
    (it needs an AI-powered review against a real provider credential), the erasure of real
    captured excerpts (no review held any) and an approved check while offline (none configured);
    each is covered in process. Over REST, a client whose helper stopped without closing its
    connection is noticed only when the sync's 60-second wait ends (`deadline_exceeded`), so that
    check returned `operation_pending` while the server finished it.

## Reverse states

| Way in | Way out | Way to see it |
|---|---|---|
| The server's owner offers L2: `[server.code_copy] enabled = true`, then a service restart | `enabled = false` or no table, then a restart (clients are asked again; the copies kept can still be listed, forgotten and expire: honest limit 8) | The disclosure `server add\|use` shows a client's owner; `server code list` refused `server_level_unavailable` when there is no offer |
| Consent at L2: `server add\|use NAME --level L2 [--retention …]` on the trusted console | `server use NAME --level L1` (future sends stop; the copy stays until forgotten or expired); `server use local` or another server; `server remove` (asks to forget first; `--forget-copies`, `--keep-copies`) | `server status [--json]` (`target.consent`); the status line of an L2 connection |
| A sync stores a snapshot on the server and objects in this computer's export folder | `server code forget [--repository FOLDER]` or `server code forget --all` (deletes the copy there, the export folder here and the tasks' derived excerpts); a `days:N` or `task_close` expiry | `server code list [--json]`; the bounded events `code_copy_sync_<outcome>` and `code_copy_expiry`; a receipt's evidence lines |
| A task reads evidence from the copy | Forget or expiry erase what it derived (decision 15); the erasure itself is deliberately one-way | The receipt's `evidence_provenance` member and its lines, the content-forgotten marker after a forget |
| `server code level L1` (no question) | `server code level default` (trusted console) | `server code exclude list` ("kept at level L1") |
| `server code exclude add PATTERN` (no question) | `server code exclude remove PATTERN` (trusted console) | `server code exclude list` |
| `server code allow add FILE` (trusted console; those bytes only) | `server code allow remove PATH` (no question; what was sent stays until forgotten); `exclude add` of that path; any other content is scanned again | `server code allow list [--json]` |

## Owner rulings

1. **Forget deletes the copy, its snapshots and the derived excerpts** (U20). Built: decision 15,
   with a "content forgotten" marker in task records; backups are named honestly as kept until
   they rotate. This ruling is the maintainer acknowledgement of the storage/durability design
   gate for the erasure path.
2. **The secret scan holds known formats only** (U19). A known format holds a file; heuristic
   matches such as `password = …` do not (honest limit 1).
3. **Pull over the existing workspace-agent channel, with no upload routes.** Accepted because
   every pull carries the consented revision and the hold, zero-network and consent checks run
   before the bundle is built (decision 4).
4. **A per-repository `code-copy.json`, and per-copy keys from the vault's installation key.**
   The record of decision 10 is accepted with its exact fields, owner-only modes and reverse
   path; the per-copy keys derived from the installation key with a versioned derivation
   (`yoetz/code-copy-kek/v1`) are accepted because relocking makes them unreadable (decision 6).
5. **The `[server]` table lands as config 1.4.0** (decision 16): 1.3.0 is released in v0.3.0 and
   frozen.

## Consequences

- Level L2 is available in this release, and nothing changes for anyone who does not choose it:
  a server offers it only from its owner's table, a client sends a copy only after its owner's
  consent at L2, and level L1 keeps its exact bytes on every surface.
- A server copy has one wire format and one verifier both ends run, and the server reads only
  verified snapshots, from its own checkout.
- A level-L2 task's receipt says where each kind of evidence was read, and keeps a marker once the
  copy it read is forgotten.
- New closed tokens are the nine workspace reply reasons, the `copy` family, the `code_copy`
  method, store refusals such as `code_copy_forgotten`, the bounded events
  `code_copy_sync_<outcome>`, `code_copy_expiry` and `code_snapshot_mismatch`, the six provenance
  tokens, the `content_forgotten` family and gap reason, and the CLI's
  `code_copy_forget_incomplete`; no protocol reason code or continuation is added. Control 2.10.0,
  `rest-agent-work` 1.0.0 (whose calls are control `workspace_call` frames), receipt-result 1.5.0
  and the REST contract 1.0.0 manifest change in place, all unreleased; config 1.4.0 and
  content-forgotten 1.0.0 are new.
