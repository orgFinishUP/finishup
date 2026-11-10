# ADR-054 — Level L2: the server keeps a copy of the code

**Status:** Proposed for [issue #1308](https://github.com/orgFinishUP/finishup/issues/1308), layer 6
of the unified client/server model ([ADR-051](ADR-051-client-server-cut-and-server-targets.md),
*Delivery in layers*): the wire format of a server copy and its one verifier, the sanitized
exporter, the pull sync that only the target's helper answers, the server's encrypted store with
forget and expiry, the `code_copy` method, consent at level L2 and the owner's per-repository
choices. It is the record
[ADR-052](ADR-052-shared-authorization-generations-gate-and-consent-envelopes.md) decision 8 left
for level L2; the authorization every sync runs under stays in ADR-052, and the REST contract in
[ADR-053](ADR-053-rest-v1-public-contract.md). **Level L2 is unreleased in this build**
(decision 11): `protocol.server_copy.L2_RELEASED` is `False`, no server profile offers L2, and
nothing in this layer sends a copy of code anywhere.
Design gates: protocol (two workspace operations in a new `copy` family, nine reply reasons and
the `code_copy` method, in place on the unreleased control 2.10.0; `code_copy` in a REST scope),
privacy/egress (a copy of the code as a new egress, kept closed) and storage/durability (the
server's encrypted copy store and its tombstones; the client's export database and per-repository
record). Maintainer acknowledgement: the maintainer accepted the unified design on 2026-11-08 (U3,
U4, U6, U10, U11, U19 and U20 in ADR-051) and asked for its delivery as stacked pull requests;
under the intake rule in `AGENTS.md` that explicit request is the design-gate acknowledgement for
this scope. It grants no runtime, credential, disclosure or destructive-action authority, and it
does not cover the kernel erasure path named in *Owner questions*, which stays a storage design
gate.
**Implemented by (layer 6):** `src/finishup/protocol/server_copy.py` (the wire format, the
verifier, the snapshot manifest, the release switch and the provenance tokens),
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
schemas amended in place through `scripts/generate_schemas.py`, the REST contract's entry in
`fixtures/service/rest-api-manifests.case.json`, and
`tests/unit/architecture/test_level_l2_unreleased.py`.
**Amends:** ADR-051 (decision 5: the workspace agent's catalogue gains the `copy` family, eighteen
operations to twenty; *Built in layer 6*), ADR-052 (decision 8's level-L2 follow-ups; the gate is
unchanged and runs again before every export) and ADR-053 (decision 6: `code_copy` joins the
`agent` scope, claim-bound only; the REST contract 1.0.0 entry of the manifest vectors is amended
in place). **Relates to:** ADR-031 (its credential names start the always-excluded list), ADR-008
(the vault's installation MAC derives each copy's key-encryption key) and ADR-009 (zero network
and the repository hold refuse before any export).

## Context

ADR-051's level L2 (U3, U4) has the server keep a copy of the code, so that a server can later
read evidence without this computer's workspace agent answering every read. U6, U10, U19 and U20
fix its shape: code reaches the server as git data the client sends; the copy holds git-visible
files minus secrets (patterns plus a content scan, each held-out file named); forgetting deletes
the copy and the excerpts derived from it. U11: on a self-hosted server the user chooses the
retention among the options the server offers. ADR-052 decision 8 lists what L2 needs: no sync
while the gate refuses (the hold checked before a bundle is built), stopping future egress and
forgetting retained copies kept apart (design v2 section 8.10; FR-7), code sync in the helper
(design v2 section 4.2), consent at L2 with a retention, and the revision on every sync.

A copy of code is an egress that cannot be taken back: once sent, stopping or holding cannot unsend
it.
This layer builds the copy's write side — what is sent, how both ends check it, where it is kept
and how it goes away. The read side that would make a copy useful (reads routed to the copy,
per-evidence provenance on receipts, task pins) is not built, and neither is the erasure of
excerpts derived from a forgotten copy that U20 promises. L2 therefore stays unreleased: every part
is tested in process and was run over real networks with the switch turned on in that harness's
own process only; no shipped build can turn it on.

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
`special`, `unrepresentable`), a subject-state commitment (`null` for now), the profile-revision
triple, the purpose (`base` or `check`), `synced_at`, `files` and `bytes`. The module also defines
the per-evidence provenance tokens (`EVIDENCE_PROVENANCE`: `server_copy_read`,
`client_attested_read`, `client_check`, `client_observation`, `outside_read`, `stale_copy_read`);
no rendering uses them yet.

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
`.git`, with `export.json` (`yoetz.code-export/1`: the export id, the next ref number and the
snapshots sent). Every admitted object is made again there from the bytes read. A bundle carries
only what the server's have-set does not reach (incremental). Before it is offered, the
**object-closure audit** parses it back with the server's verifier and requires that every object
in it was admitted in this run; any difference refuses the export (`code_export_failed`).

### 3. The content scan

Before a file enters the export its bytes are scanned (`client.code_secrets`): the diagnostic
privacy scanner's high-confidence findings (private key blocks, `sk-`, `ghp_`, `github_pat_`,
`xox*` and `AKIA` tokens, passwords in URLs) plus formats only L2 adds (`sk_live_` and `rk_live_`,
`AIza…`, `glpat-`, `npm_…`, `pypi-AgEI…`, `xapp-`, Slack webhooks, Azure `AccountKey=`,
`ASIA…`). A match holds the file (`held_for_content`, named in the manifest) until the owner allows
those exact bytes (decision 10). Heuristic matches such as `password = …` do not hold a file
(*Owner questions*). The scan is not a secret guarantee, and the disclosure says so.

### 4. The pull sync: the workspace-agent channel, in the helper only (FR-7)

The server pulls; a client never uploads on its own. Two workspace operations form a new `copy`
family (the catalogue grows from eighteen operations to twenty): `code_sync_prepare` `{purpose,
have (at most 16), base_commit, issuer, revision, profile_digest}` → `{unchanged, sync_id,
manifest, size, sha256, retention}`, and `code_sync_read` `{sync_id, offset, length (at most
3 MiB)}` → a base64 chunk. They are ordinary `workspace_call` frames on every edge (SSH control
frames, REST agent work), so no upload route exists (*Owner questions*).

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
process.

On the server, `service.code_copy.CodeCopies` pulls in the worker thread of the read it precedes:
the task base (`read_task_base`) and a check (`capture`, `capture_metadata`). One sync per
repository runs at a time (a caller that finds one running waits for its outcome); each outcome is
a closed bounded event (`code_copy_sync_<outcome>`), and a sync never fails the read. **The reads
themselves still go to the client's agent, as at L1**: the copy is stored, not read yet.

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
the REST contract 1.0.0 (unreleased) entry in `fixtures/service/rest-api-manifests.case.json`.

### 6. The server's encrypted store: keys under the vault's authority, admission, quotas, ownership

`service.code_store` keeps copies under `<state>/code-copies/`, one copy per (principal,
repository commitment), both kept only as digests. The principal namespace comes from the claim,
which the REST edges namespace by the key's principal (ADR-053 decision 6), so keys with different
principals never share a copy.

Every object, every snapshot manifest and the copy's index is an AES-256-GCM frame whose associated
data binds the copy and the object. Each copy has its own random data key, stored only wrapped
(AES key wrap) under a key-encryption key that the vault's installation MAC derives for that copy
(domain `yoetz/code-copy-kek/v1`) and that is never stored; the wrapping record is
`yoetz.code-copy-wrap/1`. A locked vault reads and admits nothing.

An upload is staged encrypted under a key held only in memory. Commit decrypts it, verifies it with
the verifier of decision 1, checks the manifest against what was verified, against the revision the
service issues and against the claim's worktree, and applies the quotas: a checkout of at most
`max_repo_bytes`, four times that per copy and sixteen times per principal. It writes the objects,
then the manifest, then the index, and the copy record (`copy.json`, `yoetz.code-copy/1`) last, so
a crash leaves the previous snapshot in force; a service start removes staged uploads and folders
without a record.

### 7. Forget, the tombstone and the fence

Forget advances the copy's epoch in the tombstone record (`yoetz.code-copy-tombstones/1`)
**first**, then deletes the copy's folder. It is idempotent and reports exactly what it deleted
(copies, snapshots, objects, bytes) with `backups: not_managed`. A sync is fenced from the moment
the server asked for it: the puller reads the epoch before `code_sync_prepare`, and an upload begun
under an older epoch is refused (`code_copy_forgotten`). Forget acts on the repository the claim
names; another repository's copy needs its own. `finishup server code forget` prints what the
server deleted, says that backups of the server's folder are not managed and that evidence already
recorded in tasks stays with the task, and removes this computer's export folder for that
repository.

### 8. Expiry

The retention is `days:N`, `task_close` or `until_forgotten`, chosen at consent among the options
the server offers. Expiry runs at service start and every 10 minutes: a `days:N` copy is forgotten
as in decision 7 once N days passed without a sync; `until_forgotten` never expires; `task_close`
does not expire yet, because it needs task pins (*Not built*).

### 9. Consent at L2 and the disclosure

A server offers L2 (levels `L1` and `L2`, `L1` required) only with a code-copy offer
(`service.server_profile.CodeCopyOffer`: `max_repo_bytes`, `max_file_bytes`, the retention options
and default, its exclusions) **and** L2 released; the profile's `exclusions.always` is the offer's
set together with `ALWAYS_EXCLUDED`. There is no `[server]` configuration table yet, so no
production service has an offer (*Owner questions*).

`finishup server add|use … --level L1|L2 --retention task_close|until_forgotten|days:N` (both
options hidden) records the consent on the trusted console. `--level L2` is refused
`server_level_unavailable` while L2 is unreleased or not offered, and the retention must be one the
server offers; `server use` keeps a level and retention already agreed to. The L2 disclosure is
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
of the per-target repository map (*Owner questions*).

`finishup server code` (hidden, `client_only`): `list` and `forget` (`[--repository FOLDER]
[--json]`) ask the server; `exclude add|remove|list PATTERN`, `allow FILE` and `level L1|default`
edit this computer's record. What sends less needs no question (`exclude add`, `level L1`); what
sends more is confirmed on the trusted console (`exclude remove`, `level default`, `allow`). An
exclusion is checked before the scan, so `exclude add` of an allowed path keeps it out again. While
L2 is unreleased the commands still answer, and those that reach a server are refused there, since
no server keeps copies. `finishup server remove` warns that copies sent stay there until they are
forgotten.

### 11. The release switch: `L2_RELEASED`, and why it stays false

`protocol.server_copy.L2_RELEASED` is `False`, pinned by
`tests/unit/architecture/test_level_l2_unreleased.py`. While it is false no server profile offers
L2, `--level L2` is refused `server_level_unavailable`, `--level`, `--retention` and the
`server code` group are hidden from help, no helper declares the sync operations and no service
keeps copies. `l2_released()` is true only after `enable_unreleased_l2()`, which only tests and the
layer-6 real-network harness call, each in its own process: no flag, variable or file a user can
set reaches it.

It stays false because what would make a copy honest to offer is not built: reads from the copy,
per-evidence provenance on receipts, task pins with the `task_close` expiry, and the deletion of
derived excerpts kept in task records that U20 promises. The commit that sets it to `True` must be
the last code commit of the layer that completes them, as `ssh`, `https` and `local_port` opened in
the last code commits of their layers.

## Not built

- Reads from the copy: `read_task_base`, capture, metadata, changed paths, inspect, reviewer reads
  and task inputs routed to the pinned snapshot through a materialized checkout; stale-copy reads
  while the client is offline, and checks then refused `workspace_agent_unavailable`.
- Task pins, and the check-versus-snapshot mismatch (`code_snapshot_mismatch`).
- Per-evidence provenance in every rendering, the O7 count of fenced reads (ADR-052) and the
  receipt version bound that carries them.
- The subject-state commitment in the manifest (`null` now).
- The `task_close` expiry.
- Deleting the derived excerpts kept in task records (captured diffs, review excerpts) when a copy
  is forgotten, and the "content forgotten" marker in their place (*Owner questions*).
- The `[server]` configuration table that would make a code-copy offer (config 1.4.0).
- `server code forget` for every repository at once; a way to list or remove an `allow` entry
  (`exclude add` of the path keeps it out again); the terminal interface's flows; `server remove`
  asking interactively before it removes a target that was sent copies.
- Any macOS or WSL 2 run.

## Honest limits

1. Filename patterns and the content scan are not a secret guarantee, and heuristic matches do not
   hold a file.
2. The names (paths) of left-out files are sent; their contents are not.
3. Relocking the server's vault does not erase plaintext a server owner already copied out of a
   running service.
4. Backups of the server's folder are not managed (`backups: not_managed`).
5. Holding a repository, narrowing to L1, zero network or stopping stop future sends only; only
   forget removes what was sent.
6. Forget from one computer reaches the copy of the repository it names; copies of other
   repositories need their own forget, and evidence already recorded in task records stays with
   the task.
7. Expiry runs at service start and every 10 minutes, so a copy past its retention stays until the
   next run. `task_close` is offered and disclosed ("until the tasks that read it are closed") but
   nothing expires on it yet.
8. The checks run once per sync, at `code_sync_prepare`; `code_sync_read` serves only the bundle
   prepared then, for at most two minutes; a chunk the server already read stays with it.
9. The real-network run was on Linux only, with L2 turned on in the harness's own process: the
   gateway edge over real TLS, the native edge and a private `sshd`; consent at L2 on the trusted
   console; a sync at start and at a check (`operation_not_declared` until the helper's background
   agent registered, then `synced`, then `unchanged`); `server code list`; a server store holding
   no plaintext; the hold and zero network refused before any bundle (the export database
   unchanged); forget (one snapshot, 10 objects, 732 bytes); a sync in flight refused
   `code_copy_forgotten`; a `days:7` expiry with the time simulated. No Codex, Claude Code or Cursor
   session ran against it.

## Reverse states

| Way in | Way out | Way to see it |
|---|---|---|
| Consent at L2: `server add\|use NAME --level L2 [--retention …]` on the trusted console (refused `server_level_unavailable` while L2 is unreleased) | `server use NAME --level L1` (future sends stop; the copy stays until forgotten or expired); `server use local` or another server; `server remove` (warns that copies sent stay until forgotten) | `server status [--json]` (`target.consent`) |
| A sync stores a snapshot on the server and objects in this computer's export folder | `server code forget [--repository FOLDER]` (deletes the copy there and the export folder here); a `days:N` expiry | `server code list [--json]`; the bounded events `code_copy_sync_<outcome>` and `code_copy_expiry` |
| `server code level L1` (no question) | `server code level default` (trusted console) | `server code exclude list` ("kept at level L1") |
| `server code exclude add PATTERN` (no question) | `server code exclude remove PATTERN` (trusted console) | `server code exclude list` |
| `server code allow FILE` (trusted console; those bytes only) | `server code exclude add` of that path; any other content is scanned again; `server remove` removes the record with the root (no command lists or removes an entry yet, *Not built*) | none yet beyond the owner-only record |

## Owner questions

1. **Erasing derived excerpts is a storage design gate.** U20 has forgetting delete the copy and the
   excerpts derived from it. Forget deletes the copy; excerpts the kernel already recorded in task
   records (captured diffs, review excerpts) stay, because the event-sourced ledger has no erasure
   path. Building one, with a "content forgotten" marker where erased content was, changes storage
   and durability: it needs the owner's acknowledgement before a layer builds it, and L2 stays
   unreleased until then.
2. **Heuristic secret matches do not hold a file.** Only the high-confidence formats of decision 3
   hold one; `password = …` and similar matches do not. Confirm, or ask for heuristic matches to
   hold too (with `allow` as the way through).
3. **Pull over the workspace-agent channel instead of upload routes.** The server pulls through
   two workspace operations the helper answers, so SSH and REST carry the sync alike, under the
   helper's admission, and REST v1 gains no route. Confirm, or ask for upload routes in a later
   REST contract.
4. **A separate per-repository code-copy record.** The owner's per-repository L2 choices live in
   `config/code-copy.json` (`yoetz.server-code-copy/1`), not in a `/2` of
   `config/repositories.json` (`yoetz.server-repositories/1`), the per-target repository map that
   ADR-052 decision 8 named; the `/1` map and its readers are unchanged. Confirm, or ask for the
   map's `/2`.
5. **A `[server]` configuration table needs config 1.4.0.** A server's owner cannot make a
   code-copy offer yet: the table that would hold it cannot go into config 1.3.0, which v0.3.0
   released and froze. The owner decides whether it lands as config 1.4.0, and in which release.

## Consequences

- Nothing a user sees changes: help, the L1 disclosure, `DISCLOSURE_VERSION` and every surface are
  as in layer 5, and the architecture test keeps it so until the release commit.
- A server copy has one wire format and one verifier both ends run; a later layer that reads the
  copy reads only verified snapshots.
- New closed tokens are the nine workspace reply reasons, the `copy` family, the `code_copy`
  method, store refusals such as `code_copy_forgotten`, and the bounded events
  `code_copy_sync_<outcome>` and `code_copy_expiry`; no protocol reason code or continuation is
  added. Control 2.10.0, `rest-agent-work` 1.0.0 (whose calls are control `workspace_call` frames)
  and the REST contract 1.0.0 manifest change in place, all unreleased.
