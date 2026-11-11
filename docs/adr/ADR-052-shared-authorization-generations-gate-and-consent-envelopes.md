# ADR-052 — Shared authorization: generations, the gate and consent envelopes

**Status:** Proposed for [issue #1308](https://github.com/orgFinishUP/finishup/issues/1308), layers 2
to 4 of the unified client/server model ([ADR-051](ADR-051-client-server-cut-and-server-targets.md),
*Delivery in layers*). It is the new decision record the unified design names for levels, server
profiles and the server copy: layer 2 built generations, the gate and consent envelopes; layer 3
builds the server profile, its revision, the consent binding and the helper's workspace
registration API (decisions 9 to 12); layer 4 builds the unified helper, the SSH transport in its
relay and direct styles, SSH discovery, and opens the `ssh` kind (decisions 13 to 19); the
level-L2 sections are recorded as **not built** and are filled in by the layers that build them.
Design gates: privacy/egress (what may reach a server elsewhere, and when it stops; in layer 4 the
first network edge) and storage (three new owner-only client records; in layer 4 the helper's
records). Maintainer acknowledgement: the
maintainer accepted the unified design on 2026-11-08 and asked for its delivery as stacked pull
requests, and on 2026-11-09 gave the answers O1 to O9 recorded below; under the intake rule in
`AGENTS.md` those explicit requests are the design-gate acknowledgement for this scope. They grant
no runtime, credential, disclosure or destructive-action authority.
**Implemented by (layer 2):** `src/finishup/client/authorization.py`,
`src/finishup/protocol/consent_envelope.py`, the connect seam and `ServiceClient` checks in
`src/finishup/service/client.py`, `src/finishup/client/remote_binding.py`,
`src/finishup/client/repository_hold.py`, `src/finishup/client/everyday_repository.py`, the
repository reports in `src/finishup/client/everyday_policy.py`, `targets.remote_target_recorded`,
the `server repositories` group in `src/finishup/cli/server.py`, and the closed tokens
`server_authorization_changed` / `server_connection_renew` in `src/finishup/protocol/errors.py` and
`src/finishup/protocol/recovery.py`.
**Implemented by (layer 3):** `src/finishup/protocol/server_profile.py` (and its schema contract
`server_profile_contract.py`), `src/finishup/service/server_profile.py`, the `server_profile`
operation and the revision checks in `src/finishup/service/daemon.py` and
`src/finishup/service/control_protocol.py`, `src/finishup/client/server_profile.py`, the `/2`
records in `src/finishup/client/targets.py`, the consent step in
`src/finishup/client/authorization.py`, the open-kind `server add`/`server use` flows in
`src/finishup/cli/server.py`, `src/finishup/client/helper_registrations.py`, the agent roles in
`src/finishup/service/workspace_hub.py`, and the bridge's registration in `src/finishup/mcp/server.py`.
**Implemented by (layer 4):** `src/finishup/client/helper_status.py` (lock, stamp, status record,
spawn, stop, reaper; hook-safe), `src/finishup/client/ssh_transport.py` (fixed OpenSSH argv,
failure classification, the observed host key, the relay master and the direct stream),
`src/finishup/client/ssh_discovery.py` (discovery and `PROFILE_SOURCES["ssh"]`; never on a hook
path), `src/finishup/client/helper.py` and `src/finishup/cli/helper.py` (the helper process),
`src/finishup/client/helper_runtime.py` (`SshTargetRuntime`, the CLI registrant),
`authorize_target` and the transport summaries in `src/finishup/client/authorization.py`,
`styles_offered` in `src/finishup/client/server_profile.py`, the style dispatch, helper start and
`connect_service_via` in `src/finishup/service/client.py`, `connect_owner_only_endpoint` in
`src/finishup/adapters/control/unix_socket.py`, SSH add/use and `server set` in
`src/finishup/cli/server.py`, `target.connection` in `src/finishup/protocol/server_target_status.py`,
and the bridge's request-id map in `src/finishup/mcp/server.py`.
**Amends:** ADR-051 (decision 8 gains the repository egress hold and, in layer 3, the consent to a
server profile; decisions 5, 6 and 12 the fence, the phases and the waiting rows), ADR-008 (the
credential generation; the server's profile revision record), ADR-009 (the hold of a repository
whose grant forbids network egress; in layer 4 the SSH edge and who reads an SSH key) and ADR-030
(two continuations in layer 2, two in layer 3; in layer 4 four directives reworded for SSH).

## Context

Design v2 section 8.3 requires every egress protection before any new egress path: shared
authorization, generations, the round-5 repository hold and consent binding land before any
remote kind opens. Layer 1 closed every remote kind; layer 2 builds the protections and keeps them
closed. Nothing in this layer adds a network edge: a remote root is still refused before anything
is sent, now by one gate whose later steps are exercised in process by tests that open a kind on
purpose (`tests/builders/server_targets.py:open_remote_kinds`), and an architecture test keeps the
release's own set of open kinds empty. Layer 4 adds the first network edge, SSH, and opens `ssh`
in its last code commit, once the helper's admission, the relay's per-frame check and the direct
style's checks exist; the architecture test then pins the set to exactly `{ssh}`.

## Decisions

### 1. One gate, one order, every path

`client.authorization.gate(record, repository_key=None)` refuses a connection to a server
elsewhere with the first closed reason, in this order:

1. the record is readable (an unreadable one may name a remote kind: `target_root_is_remote`);
2. `zero_network_remote_selected` (ADR-051 decision 8);
3. `target_reauthorization_required` (the disclosure version);
4. the kind is open in this release (`OPEN_REMOTE_KINDS`, empty in layers 2 and 3; `{ssh}` from
   layer 4): any other remote root (`https`, `local_port` until layer 5) is refused as
   `target_root_is_remote`, the phase layer 1 gave every connection and spawn path;
5. (layer 3) the consent to the server's profile (decision 10): `server_profile_changed` or
   `server_level_unavailable`. It comes after the kind step, not with the disclosure as layer 2
   planned, because its way on (`finishup server use NAME` on the trusted console) exists only for
   an open kind: with the kind closed, the kind is the truthful first refusal;
6. (layer 5) a credential is present for a kind that needs one;
7. `repository_egress_held` or `repository_egress_kept`, once the repository is known.

Both connect paths (`connect_service`, `connect_service_on_demand`) run it before any claim, dial,
spawn or supersede (`service.client._admit_remote`); `remote_binding.binding_for_active_root` runs
it unless the caller passes its admission; `preflight_refusal()` is its record-only form for the
root this process uses, which the SessionStart auto-attach asks before any dial. Server-host
actions (setup, the menu's service actions, the terminal interface's first run) keep asking
`targets.active_remote_refusal`, which refuses every remote root whatever kinds open later; in
layer 2 the two agree on every root (tested). Surfaces that show the hold (setup, the menu, the
terminal interface, the unconsented SessionStart notice) show it only where the gate's earlier
steps admit the server, so with every kind closed they show what layer 1 showed.

### 2. The authorization generation

A generation is the `lstat` stamps (device, inode, size, modification and change times) of every
owner-controlled record a decision reads: the selection file (or `pinned` when an isolation
variable or pin names the root), the target root and its `target.json`, the credential generation,
this computer's zero-network marker, its repository reports and the target's repository choices.
Every FinishUP writer renames a new file into place, so each write changes a stamp; so does a hand
edit. `folders.json` is deliberately not a component: the workspace agent re-reads the outside-read
settings on every call (ADR-051 decision 5), so a change applies without ending a connection.

`authorize_active_root()` reads the generation, then the record again, then runs gate steps 1 to
4, so a change made while the gate runs is seen at the first check. A root the selection named is
admitted only while the selection file, read after the generation, still names it: a process
remembers the root it started with (the MCP bridge's selection memo), and a selection another
process changed before the generation was read would otherwise be stamped into the accepted
generation and never seen; such an admission is refused `server_authorization_changed`, and the
bridge follows the selection (O1). A `selection_override` block (one named target, probed or
stopped) is bound to its own root, not to the selection file. `ConnectionAuthorization`
holds the grant (target id, kind, an identity digest over id, kind, location and claim salt, a
consent digest, the repository key once known, and whether the selection named the root) and the
accepted generation. `refusal()`:

- the same generation passes;
- a selection that no longer names the target, a replaced or removed target, or a new credential
  generation is **`server_authorization_changed`** (continuation `server_connection_renew`:
  FinishUP stopped sending over the connection and what the server received stays there; a request
  already sent may be recorded there and is never resent, since the server selected now may be
  another (ADR-051: no replay across targets), so its outcome is unknown; later requests run under
  the current selection or name the refusal now in force);
- anything else re-runs gate steps 2 to 6 on the re-read record and accepts the new generation
  when they pass, so a rewrite with the same content never ends a connection;
- a refusal is final for that connection; a check that cannot be made keeps the last decision;
- before anything is written the phase itself refuses the connection, and its words say it was
  refused before anything was sent; once a connection is open (its hello, at least, was sent) any
  phase ends it as **`server_authorization_changed`**, whose words say FinishUP stopped sending
  over it and that what the server received stays there, never that nothing was sent (design v2
  section 8.10: no hold reaches back over what was already sent). The next connection's admission
  names the refusal now in force, before anything is sent.

### 3. Where the checks run

A connection admitted to a server elsewhere keeps its `AuthorizationCheck` (`service.client`). A
connection given a prebuilt workspace binding keeps the binding's own check (its repository's
hold) beside the admission (`bind_prebuilt_check`), and one made for another target is refused
`server_authorization_changed` before the dial. The check runs right before the dial, again right
before the hello (which carries the claim and the agent declaration) is written, before every
later frame, by `connect()` (the MCP bridge's reuse check), before a workspace
reply leaves (a reply computed while it lapsed is not sent), and by a watch every
`GENERATION_RECHECK_SECONDS` (1 s; an injectable tick for tests). A lapse fails pending calls with
`server_authorization_changed` and later calls with the same stored failure. The workspace agent of that connection
checks it on every call (`own_authorization`) and answers `workspace_unavailable` once it refuses,
so background work between the connection's own checks reads nothing more. **Local roots get no
authorization, no check and no watch** (the owner's answer O2): a connection to a server on this
computer is made exactly as before.

### 4. The credential generation

`<target root>/config/credential-generation` (`yoetz.credential-generation/1`, owner-only
canonical JSON `{"generation":"<32 hex>","schema":"yoetz.credential-generation/1"}` and a newline,
renamed into place) is bumped only by the owner's own commands: `server logout` and `server remove`
(before the key is deleted, so a folder that outlives a failed remove still ends the connections
made under the key), and `server login` once it can store a key (layer 5); never by an automatic
token refresh (O8). A bump never blocks the command it belongs to. A key changed in the platform
store outside FinishUP is not seen.

### 5. The repository egress hold (round 5)

Recorded in ADR-051 decision 8, *A repository whose policy on this computer allows no network
use*: the hold is the gate's sixth step; the reports and the session-start live read stay
**dormant until this computer records a server elsewhere** (O3).

### 6. Consent envelopes

`protocol.consent_envelope` (SHARED, pure) defines the canonical consent envelope design v2
section 8.2 binds consent to: the endpoint (kind, origin, TLS or SSH identity), the principal and
key scope, the level and the server's required minimum, code sync with its caps, retention,
exclusions, review egress and the disclosure version.

- **Strict, never lossy.** Every known member is required, typed and bounded; an unknown member or
  enumerated value is kept in place in the canonical form and named in `unknown_paths`; an
  envelope with anything unknown is never consentable. Malformed input is a closed
  `EnvelopeError`.
- **Canonical form and digest.** `protocol.canonical` encoding (sorted keys, sets as byte-sorted
  arrays, explicit nulls, integers only) of `{"schema":"yoetz.consent-envelope/1", …}`; digest
  `sha256:` over `yoetz/consent-envelope/v1\x00` and those bytes.
- **The partial order** `a ⊑ b` (a sends or keeps no more than b) is the product of one order per
  field: endpoint, principal and disclosure version equal; key scope by subset only; level L1 < L2;
  required minimum by rank; code sync absent below any, else methods by subset and both caps by
  value; retention with nothing kept at the bottom, `until_forgotten` at the top, `days:N ⊑ days:M`
  for N ≤ M, and `task_close` and `days:N` incomparable; exclusions by exact pattern superset only
  (no pattern semantics); review `none` below `server_policy`, a provider named only with
  `server_policy`, and any other change of the providers named (another provider, a fallback
  added, removed or swapped with the first) incomparable.
- **`compare(consented, current)`** returns a typed verdict: anything unknown → `ask_again`; a
  required minimum above the level agreed → `level_unavailable` (never a silent upgrade); identical
  canonical bytes → `same`; `current ⊑ consented` → `narrower` with the fields whose narrowing
  reduces coverage (level, code sync, exclusions, review) for a receipt to name; anything else →
  `ask_again` with what widened or changed. L1 → L2 always widens.

Layer 3 reads them (decision 10): an envelope is built from a server profile and the endpoint
identity the client observed, the consented one is recorded beside `target.json`, and the verdicts
map to `server_profile_changed` (`remote_reconsent`) and `server_level_unavailable`
(`server_level_decision_required`) (O5).

### 7. The owner's answers of 2026-11-09 (O1 to O9)

- **O1 — follow the new selection.** A claim-bound connection to a server elsewhere ends with
  `server_authorization_changed`; the MCP bridge then forgets the root it started with and follows
  the current selection on its next connection (`mcp.server._follow_selection_after`). A request
  found lapsed by the reuse check, before it was sent, goes on that next connection; a request
  already sent over the connection that ended is never sent again (`_invoke_with_reconnect`), since
  the server selected now may be another one and it could then run on both (ADR-051: no replay
  across targets): the agent is told its outcome is unknown, and only later requests follow the
  selection. `server_authorization_changed` is not latched as the bridge's availability outage, so
  the next request makes a fresh connection under the current selection, starting a service on
  this computer when one is selected. An admission whose remembered root the selection no longer
  names is refused the same way (decision 2). A switch between servers on this computer is
  unchanged: the bridge keeps the server it started with. The open-sessions line says both.
- **O2 — local connections are never checked.** No authorization object, generation read or watch
  for the everyday server, a named local server or an isolated root that is not a target.
- **O3 — dormant until a server elsewhere exists.** The session-start live read and the owner-only
  repository reports do nothing until the first remote target record exists
  (`targets.remote_target_recorded`: a bounded presence check, two `lstat` calls however many
  targets or leftover folders exist, of `servers/remote-target-recorded`, which is made before any
  remote record is written and removed once the last one is; a registry folder or presence file
  that cannot be examined switches them on). The shared live read itself
  (`read_everyday_repository`) is dormant at its own boundary, so no surface (`server repositories
  list`, `server status`, a privacy change, a session start) asks or records anything. With none, a
  session start, a privacy ceremony, `provider status` and a policy change are byte for byte as
  before the hold (tested on every host). Once one exists they switch on; there is no report from
  before then, and `server repositories list` says so. Removing the last server elsewhere deletes
  the reports (their way out).
- **O4 — `server repositories` hidden.** The group is hidden from help; `add` and the terminal
  interface's "Send this repository's work to this server anyway" refuse `remote_kind_unavailable`
  before the console while no kind is open; `keep`, `list` and `remove` work. Reopened by the layer
  that opens remote kinds: from layer 4 the group is shown and `add` acts for an SSH target (a
  closed kind still refuses before the console).
- **O5 — profile tokens in layer 3.** `server_profile_changed` (with `remote_reconsent`) and
  `server_level_unavailable` (with `server_level_decision_required`) are registered in layer 3,
  with ADR-030 directives, on every surface (decision 10); layer 2's `compare` returned typed
  verdicts.
- **O6 — stricter everywhere.** Anything incomparable or unknown, `task_close` against `days:N`
  included, asks again; L2 → L1 is a narrowing that reduces coverage, typed so receipts can show it
  in a later layer; exclusions narrow only by an exact pattern superset; key scope only by subset.
- **O7 — an honest limit.** A held repository fenced from another repository's outside reads is
  not counted on receipts in layer 2; the count lands with level-L2 provenance (layer 6), since it
  needs a workspace-agent reply reason on the wire.
- **O8 — owner actions only.** The credential generation bumps on `login`, `logout` and `remove`,
  never on an automatic token refresh. A credential change ends every remote connection, the
  helper's relay included, from layer 4 on (built: for an SSH target the owner's `server remove`
  bumps it between its two stops of the helper; `logout` does not apply to SSH).
- **O9 — this ADR.** Started in layer 2 for generations and consent envelopes.

### 8. Not built (later layers)

- **Built in layer 4** (decisions 13 to 19), so no longer follow-ups: every background agent the
  helper serves is built through `remote_workspace_binding(target=…, role="background")` with the
  fence and the helper's admission (critic gap 1, FR-1); the direct SSH style carries, checks and
  watches `ConnectionAuthorization`, and the helper's relay re-checks before each relayed client
  frame (critic gap 2, FR-2); the helper admits itself through the gate (FR-3); the line after a
  remote `server use` or `server add` naming a held or kept repository (FR-5). From layer 3's list:
  the SSH profile source (the server's `finishup service profile --json` through the recorded
  launcher), the helper's profile refresh, the helper reading `served_workspaces` and declaring
  `role: background`, `service profile` shown in help, and CLI commands as a registrant.
- **REST (layer 5):** HTTPS and `local_port` through the same helper (a REST upstream) and the one
  REST client in the direct style; `server login`; API-key principals and scopes in the profile;
  which processes read an API key in the direct style; REST requests carrying the revision
  (`GET /v1/server` as the HTTPS profile source); `server logout` stopping the helper; approach
  A's HTTPS-only lifecycle fixes (A-STOP-DELETE, A-CRED-STALE, A-KEYRING-LOOP). Still open from
  layer 3's list: a direct process recording the revision the server answered so later admissions
  refuse before the dial (for SSH the client leaves the refresh marker instead, decision 17).
- **Other registrants and the terminal interface (follow-ups):** the terminal interface does not
  register its workspace with the helper (its own connection answers its live calls) and adds
  only a server on this computer (an SSH server is added in a terminal, where OpenSSH can ask).
- **Level L2 (layer 6):** no sync while the gate refuses (the hold is checked before a bundle is
  built), and stopping future egress, cancelling server work and forgetting retained copies kept
  apart (design v2 section 8.10; FR-7); the receipt count of fenced reads (O7); code sync in the
  helper (design v2 section 4.2). From layer 3: a `[server]` configuration table offering L2 with
  its code sync, retention options and exclusions; consent at L2 (a retention chosen among those
  offered); the per-repository L1/L2 consents in the per-target repository map; the revision on
  every sync upload; the receipt line for a narrowing that reduced coverage.
- **Lifecycle (layer 7):** upgrade over running bridges and helpers, the WAN timing gate, and the
  host × surface × operating system acceptance rows for the hold, the generation and the helper
  (FR-6), and for a service restarted under a new profile revision. macOS (the helper's reaping
  under `launchd`, `/private/tmp`, the Homebrew launcher path) and WSL 2 have no recorded run of
  the helper or of SSH yet.

### 9. The server profile and its revision (layer 3)

`server-profile` 1.0.0 (design v2 section 2.2, `schemas/service/server-profile-1.0.0.schema.json`,
golden vectors in `fixtures/service/server-profile.case.json`) is what a FinishUP server offers and
requires: its release and schema manifest, the service instance, the caller's key, its edges, the
levels offered and the minimum required, code sync, retention options and exclusions (level L2
only, present exactly when L2 is offered), its AI-review egress, its `official` claim (never
counted on its own, section 2.4) and its revision.

- **The digest.** `profile_digest` is `sha256` over `yoetz/server-profile/v1` NUL and the canonical
  JSON of `{levels, code_sync, retention, exclusions, review}`, each shared member encoded exactly
  as a consent envelope encodes it. A client recomputes it and refuses a profile whose stated
  digest differs; parsing is strict (`protocol.server_profile`, hook-safe, no pydantic): an
  unknown member or value refuses the whole document, so nothing the client does not understand
  can be agreed to.
- **Where the offer comes from (layer 3's decision).** Levels are pinned by the release: L1
  offered and required (a server elsewhere always keeps the tasks), L2 never offered before
  layer 6, which adds a configuration table for it. Review egress is derived from the server's own
  `config.toml` (its semantic capability and provider), the settings that decide whether it can
  reach an AI provider at all, so the profile never understates it: an external provider states
  `server_policy` (its owner's privacy policy decides) and names, by closed tokens, every provider
  its review may send to: `provider_disclosure`, the one it sends to first, and
  `fallback_disclosure`, the one a `[semantic_fallback]` pairing falls back to when the first
  fails (`null` without one), so pairing, dropping or swapping a fallback changes the digest and
  advances the revision (review of layer 3, A1). Anything else states `none`. A configuration the
  profile cannot state exactly (a provider id that is not a profile token) offers **no profile**
  rather than one that understates it: no revision is issued or recorded, the `server_profile`
  operation is refused (`method_forbidden`) and every hello naming a revision or a claim is
  refused (`server_profile_changed`). Provider granularity is the token: the model, endpoint
  profile or owner-declared origin behind the same provider id is the server owner's policy, as
  `server_policy` says. `official` is false (the official service is built in another
  repository); the edge is `ssh-control`; a peer-authenticated session is the owner's.
- **The revision.** The server keeps `<state dir>/server-profile-revision.json`
  (`yoetz.server-profile-revision/1`, owner-only canonical JSON): a random issuer, a number and the
  digest it stands for. At start a new offer advances the number; a record that cannot be read is
  replaced under a new issuer (every consent asks again); one that cannot be written keeps the
  revision in memory (the digest in the triple keeps a reused number from matching another offer).
  It is "authenticated" in three ways: it is issued only by the `server_profile` operation and in
  the hello result of a peer-authenticated session (never by unauthenticated discovery), it is
  bound to this server's own state by its issuer, and the server compares the whole triple.
- **Producing it.** The structural control operation `server_profile` (also while locked) and
  `finishup service profile [--json]`, which starts this root's service on demand; hidden in
  layer 3, shown from layer 4, whose SSH discovery runs it on the server. Control wire 2.10.0 (unreleased) is amended in place; the
  manifest-mismatch answer keeps listing only the methods a released peer knows, so a 2.9.0
  client still names `manifest_mismatch` (#436).

### 10. The consent binding (layer 3)

- **The records.** A consented remote `target.json` is `yoetz.server-target/2` with an exact
  `consent` object: level, profile digest, the revision's issuer and number, retention, the
  digest of the consented envelope kept beside it (`config/consent-envelope.json`), and whether a
  narrowing adjusted it. A local record stays `/1` byte for byte; a `/1` remote record still
  reads and is refused `target_reauthorization_required` (`DISCLOSURE_VERSION` 2 → 3: the
  disclosure now names the level and the review egress). The last profile fetched is kept in
  `state/server-profile.json` (`yoetz.server-profile-cache/1`) with the endpoint identity the
  transport itself observed. The generation watches both new files.
- **The consent step** (gate step 5, hook-safe, file reads only) builds the current envelope from
  that profile within the consented level and compares it with the consented one: same or
  narrower admits the connection under the profile's revision, which its hello names; a level
  above the one agreed is `server_level_unavailable`, never a silent upgrade; anything wider,
  changed or unknown, another issuer, another endpoint identity, or a record that is missing,
  unreadable or inconsistent is `server_profile_changed`. An open connection whose consent moves to
  another revision ends with `server_authorization_changed` (decision 2's rule).
- **Narrowing adjusts (stricter).** Recording a newly fetched profile (`refresh_profile`) on a
  narrowing rewrites the consent down to it and keeps when and what coverage it reduced, so a later
  widening, even back to what the owner once confirmed, asks again; `server status` shows the
  `server_profile_narrowed` notice until the owner next confirms. The same offer under a new
  revision records only the revision. The record is changed field by field as stored, under the
  registry lock (SRV-12). A narrower profile is cached only after the reduced consent is committed
  (the envelope, then the record), so no reader admits the narrower revision under the broader
  consent and a refresh that stops part way never lets the broader offer back as `same` (review of
  layer 3, B1): stopped between the two consent writes, they disagree and refuse until the owner
  agrees again; stopped after them, the older cache is wider than the consent and refuses until
  the next refresh records the profile.
- **The server holds it before any work.** A hello that names a revision or a claim is admitted
  only under the revision the service issues now; otherwise the service answers its current one
  and closes, before the claim is keyed, an agent registered or a request read. Every request
  that does work on a session bound to an older revision is refused `server_profile_changed`;
  the structural methods and `server_profile` are still answered. The client says only what the
  server guarantees (review of layer 3, B2): the refused hello or request is
  `server_profile_changed`, "refused before that server did any work for it" (its hello or request
  was sent, so never "nothing was sent"), and so is every later request on that connection, never
  sent; every other call already sent over it ends as `server_authorization_changed`, whose
  outcome is unknown and which is never resent.
- **Which continuation a changed profile names** (after the macOS dogfood of 2026-11-11). Every
  surface resolves the continuation of `server_profile_changed` by the target's consent as this
  computer holds it (`targets.profile_change_continuation`, read through
  `targets.remote_root_continuation` for the active root; hook-safe, file reads only). When the
  consent step already refuses on what this computer holds (a wider or changed profile, another
  issuer, a level above the consent, a consent missing or unreadable), it is `remote_reconsent`:
  only the owner agrees again. When it still admits the cached profile, the refusal was the
  server's, naming a revision this computer has not fetched: what changed is not known yet, and
  the refresh such a refusal asks for may show only a narrowing this computer adjusts to by
  itself. It is then `remote_profile_checking`: FinishUP is checking what changed, so the agent
  repeats the same request (the server did no work for it) and follows the next refusal's
  continuation, never asking the owner on the first, ambiguous one. That token is attached by the
  client that knows the target's state, never through a reason code; the registry keeps
  `server_profile_changed` → `remote_reconsent`. A command naming a target (`server connect
  NAME`, `server status NAME`) resolves by that record.
- **Consent only on the trusted console.** With a kind open and a profile source for it (SSH
  from layer 4, decision 17; tests opened one in layer 3), `server add` and `server use` check the address
  and remote paths (SRV-11), this computer's zero-network state (SRV-3), fetch the profile, refuse
  before any console what this release cannot agree to, show the versioned disclosure with what
  the profile means in this release's own words only (design v2 section 8.8), ask the add-time
  outside-read question, and take the typed name; the terminal interface reads it on its loop
  thread (SRV-6). Agents only ever get the `remote_reconsent` directive (or
  `remote_profile_checking`, which asks them only to repeat the request).
- **The per-repository override map** is the per-target `repositories.json` of decision 5's hold:
  with one remote level its only override is L0 (`keep`); layer 6 adds L1/L2 entries with their
  own consent.

### 11. The helper's workspace registration API (layer 3)

Design v2 section 8.5. `client.helper_registrations`: one owner-only canonical record per
registering process and workspace, `<target root>/state/registrations/<claim>-<worktree>-
<registrant>.json` (`yoetz.helper-registration/1`), at most 64 per target, leased for 15 minutes
and renewed by its registrant, naming the claim, the worktree (never sent), the hold key and what
the registering connection was admitted under (identity and consent digests, credential
generation, profile revision) and whether it followed the selection (`selection_bound`) or was
pinned to its root on purpose. `register` writes only under an admission that refuses nothing
now; `renew` re-admits or releases with the phase; `release_registrant` serves a bridge retiring
and Cursor's roots changing. `served_workspaces`, the helper's read, serves a registration only
while all of that still holds, the selection still names its target when it followed the
selection (`selection_changed`; a pinned one is exempt, O1), the gate passes for its repository,
and its claim derives again from its own worktree under the target's salt (a copied or edited
record is never served). The MCP bridge is the first registrant; the helper process (layer 4,
decisions 13 and 16) is its reader, and CLI commands register too from layer 4.
Each claim-bound bridge connection registers under a registrant of its own and owns a renewal
task that renews at half the lease while the connection lives, idle or not; closing the
connection or Cursor's roots changing cancels the task and releases the record, and a renewal
already under way writes nothing back (review of layer 3, C3).

Registration and pruning take the registry lock, the one the owner's `server logout`, `remove`
and `use` hold (review of layer 3, C2 and C4): `register` re-admits the connection, checks its
target still exists as the one admitted, reads the credential generation and the consent, counts
the live registrations and publishes the record under one hold, never creating a removed target's
folder again, so an owner action is wholly before it (refused) or wholly after it (the helper
drops it). The helper removes a dropped record only under the lock and only while it still holds
the bytes judged, so a lease its registrant renewed meanwhile is kept.

### 12. Which agent answers (layer 3)

An agent declares its `role` in the hello: `connection` (default) or `background` (the helper's).
The hub sends each call to one channel: a live call to its own connection's agent, else the newest
background agent, else the newest connection agent; background work to the newest background
agent, else the newest connection agent (layer 1's behaviour when there is no helper). They never
compete.

### 13. The helper process and its records (layer 4)

Design v2 section 3. `finishup helper run --target <id>` (`cli/helper.py`; hidden, scope
`client_only`) is the one background helper of an SSH target. Exit 0 when it stopped or another
helper already serves the target; exit 2 (`helper_target_invalid`) for an id that is not an SSH
target in this computer's registry, or while an isolation variable or pin names another root;
exit 20 (`helper_failed`) when its endpoint cannot be bound safely. It runs in its own session
with a fixed, scrubbed environment (no FinishUP variable; `SSH_AUTH_SOCK` kept so OpenSSH can use
the owner's agent), its stderr in `log/helper.stderr`, and resolves every path under
`selection_override(<target root>)`.

- **One per target.** The flock `state/helper.lock`, stamped with the holder's pid, package
  version and schema-manifest digest. The stamp is advisory (the release a client compares, the
  status latch): a client stops or supersedes a helper only through the target's stop epoch
  (below), never by signalling a pid (a stamped pid may belong to another process once the helper
  exited) and never by a process name or path.
- **Started on demand, never by `service run`.** In the relay style a connecting client that finds
  nothing answering on `<troot>/run/control.sock` spawns it and waits for it within its own
  deadline; a holder stamped by an older release of this client is stopped through the stop epoch
  and replaced, a newer one never. In the direct style a process that registered a workspace (the MCP
  bridge, a CLI command) starts it when none runs, as does `server connect`. A client dialling
  while the helper ends its idle exit starts its successor; any other stop (`server use`,
  `disconnect`, `remove`, zero-network) has no successor in that client's wait (A-HANDOFF).
- **Stopped** by `server disconnect`, `server remove`, a `server use` that leaves the target and
  `server set --style`: the stop replaces the target's owner-only stop epoch
  (`state/helper-epoch`, `yoetz.helper-epoch/1`, a random token), which the helper reads on its
  one-second tick and stops for; no process is ever signalled. A stop succeeds only once the lock
  is seen free (a lock held under an unreadable stamp is not "stopped"); one that does not see it
  free in time is `target_still_connected` (`remove` then removes nothing). A helper is spawned
  with the epoch its spawner read (`helper run --epoch`, hidden); one that finds another epoch once
  it holds the lock (a stop came while it was starting) records `stopped`/`stop_requested` and
  exits without binding or sending anything, so a stop also fences a pending start. The OpenSSH
  master is asked to exit through its control socket (`ssh -S <troot>/run/m -O exit`), and the
  direct style's master record is removed (decision 20).
- **Idle exit** 15 minutes after its last relayed client connection while it serves no
  registration (in the direct style a live registration is its client).
- **Reaping (RE-3).** The spawner reaps exactly its own child on a daemon thread; a spawner that
  exits first leaves it to the system. Ownership is the lock and its stamp, never the spawner.
- **Status** `state/helper-status.json` (`yoetz.helper-status/1`): `generation`, `phase`
  (`starting`, `ready`, `unavailable`, `stopped`), `reason` (for `unavailable` a remote connection
  phase; for `stopped` `idle_timeout`, `stop_requested`, `helper_failed`, `target_removed` or
  `zero_network_remote_selected`), `correlation_id`, `pid`, `started_at`, `style`; written before
  the lock is released. The generation moves on every change of phase or reason and with every new
  process. It is the MCP bridge's availability latch: `service_holder_identity()` of a remote root
  answers the live helper (its pid and `helper-<generation>`), so a repair clears a latched outage.
  A client whose connection the helper closed unanswered names the phase the helper recorded.

### 14. The helper's admission and where each check sits (layer 4; FR-1 to FR-3, O1, O8)

`authorization.authorize_target(record)` admits a process that serves a target itself: pinned to
the target's root (not selection-bound; the owner's `server use` of another server stops the
helper instead), it reads the generation, then the record again (a record removed, replaced or
changed meanwhile is `server_authorization_changed`) and runs gate steps 2 to 5. The helper's
relayed connections, its background agents and its drain run only under an admission that
refuses nothing now; the captured admission is asked again right before every hello the helper
forwards and every remote `service start` it asks for (the master's start, the channel's open and
the start all await, and the authorization may change meanwhile). Its profile refresh needs steps
2 to 4 only (zero-network, the disclosure, the kind), since the refresh is how the consent catches
up, and it is scheduled on those alone, not under the admission: a consent that no longer admits
the cached profile (an interrupted narrowing) is repaired by it. A lapse (the owner's credential
bump on `server remove`, O8; a consent or record change), whether one relay's frame check, the
refresh or the watch sees it, ends every relayed connection made under that admission (both
directions) and every agent before another admission is taken, and records `unavailable` with the
phase; the next local connection is admitted again. Each upstream attempt (the master's start, the
channel, the hello and the server's first answer) is bounded at 30 seconds (`remote_unreachable`
past it), and the stream it opened is closed on every failure and on a cancellation. While this
computer last reported a zero-network policy the helper relays nothing, records
`zero_network_remote_selected`, asks its master to exit and stops at once, with no last delivery
(ADR-051 decision 8).

| Path | Before any claim, dial or sync | While open |
|---|---|---|
| relayed client | the client's gate and hold (`_admit_remote`); the helper's admission per connection | the client's check before every frame and its watch; the relay's check before each client frame; the helper's one-second tick |
| direct client | the client's gate and hold | `ServiceClient` before every frame and its watch (O1, O2 unchanged) |
| helper agent | `served_workspaces` (gate and hold) and the binding built under the helper's admission | the binding's check before every frame and its watch; the agent's `own_authorization` |
| registration | layer 3 (under the registry lock) | `served_workspaces` on every read |
| profile refresh | gate steps 2 to 4 | — |
| the server's `service start` | only inside an admitted client connection | — |
| `server add` and `server use` | zero-network (SRV-3); the trusted console for the consent | — |

### 15. Connection styles (layer 4)

Design v2 section 1.2 (U21). The owner's choice is `config/connection-style.json`
(`yoetz.connection-style/1`: `relay` or `direct`; absent is `relay`).

- **Relay** (the default). The helper serves `<troot>/run/control.sock` with the service's
  owner-only fences and peer-UID check, and carries each local connection over one channel of one
  OpenSSH master's `-L <troot>/run/upstream.sock:<remote control.sock>` forward (`BatchMode=yes`,
  `StrictHostKeyChecking=yes`, `ExitOnForwardFailure=yes`, `StreamLocalBindMask=0177`,
  `StreamLocalBindUnlink=yes`, `ServerAliveInterval=15`, `ServerAliveCountMax=3`; ADR-051
  *Topology*). It reads the hello within 10 seconds and never forwards one that names a
  `workspace_locator` (a path on this computer never leaves it) or no `server_profile` revision.
  **Every later client frame is checked against the helper's admission before it is forwarded**
  (FR-2); a refusal ends that relay. Frames from the server pass unparsed. A channel the server
  refuses (its service is not running) starts the server's own `<launcher> service start` over the
  master, at most once per 30 seconds and only for a client's connection (A-SVC-RESTART).
- **Direct** (advanced; approach B's seam). Each dialing process opens `ssh -S <troot>/run/m -o
  ControlMaster=no … -W <remote control.sock>` through the target's verified master
  (`ssh -M -S <troot>/run/m -o ControlPersist=15m -N`, started and recorded by whichever process
  needs it first, decision 20), with FinishUP's own variables removed from the child's
  environment; `service.client` dials it in place of the local endpoint and the connection is an
  ordinary `ServiceClient`, so the gate runs before the dial and the authorization before every
  frame and on its watch. A stopped server service is started once through the launcher, on that
  client's demand. The helper still runs for the background agents, the drain and the refresh.
- **`finishup server set NAME --style relay|direct`** (`client_only`, shown in help) chooses among
  the styles the server's last profile offers (`server_profile.styles_offered`: edge `ssh-control`
  offers relay and direct; a target with no readable profile offers none). Refusals:
  `style_invalid`, `style_not_applicable` (not an SSH target), `style_unavailable`. Under the
  registry lock it stops the helper and the master first (refusing `target_still_connected` while
  they do not stop), then writes the record; `--style relay` is the reverse. It is not an
  authorization change and moves no generation: OpenSSH reads the SSH key in either style (ADR-008
  amendment, layer 4).
- **`server status`**: `target.connection` = `{style, styles_offered, helper}` (null for a target
  that is not SSH), `helper` = `{running, phase, reason, generation}` or null until a helper
  recorded a status; text "Connection: relay (…)" or "Connection: direct (…)", then "Helper:
  running|not running; last <phase>[, <reason>]." File reads only.

### 16. Background agents, registrants and the drain (layer 4; FR-1, design v2 section 8.5)

- **Agents.** The helper reads `served_workspaces(record)` when the registrations folder changes
  (its one-second tick) and every 30 seconds, and keeps one background agent per served
  registration. Its binding is built through `remote_workspace_binding(…, target=record,
  authorization=<the helper's admission>, role="background")`, so the repository's hold is decided
  before the claim, and the agent fences held repositories and answers nothing once its check
  lapses; its claim must equal the registration's; its hello declares `role: background`
  (decision 12). It connects through the helper's own dial (relay: a socket pair into the helper's
  own relay, never its endpoint and never client activity; direct: `ssh -W`) with
  `service.client.connect_service_via`, reconnects with back-off, asks its check before each
  attempt, never reconnects to a removed target (A-REMOVE-RACE) and never starts the server's
  service. A dropped registration closes its agent.
- **Registrants.** The MCP bridge registers and renews as in layer 3. CLI workflow commands to an
  SSH server answer their own live workspace calls and register the workspace once (source `cli`,
  no renewal and no release at exit: the 15-minute lease is the window in which the helper's agent
  answers background work the server goes on with after the command returned). In the direct style
  a registrant starts the helper when none runs. Hooks never register. The terminal interface does
  not register yet (decision 8).
- **Drain.** Every 30 seconds per agent with a live connection, what this computer's hooks
  captured for that workspace is delivered over it, as its own task so it never holds the tick or a
  stop (A-ZN-DRAIN); nothing while zero-network or while the agent's check refuses; one last
  bounded pass (2 seconds) at a stop that is neither zero-network nor a removed target.

### 17. SSH discovery, the endpoint identity and the profile refresh (layer 4)

Design v2 sections 2.1, 2.3 and 8.2. `client.ssh_discovery` (never on a hook's path):

- **Discovery** at `server add` (order and texts in ADR-051 decisions 3 and 7): the launcher
  (`--remote-launcher`, or the first executable of four fixed install paths, never a remote `PATH`
  lookup; none is `remote_launcher_not_found`), `<launcher> service endpoint --json` (the endpoint;
  another schema manifest, or a launcher the remote shell cannot run, is `remote_incompatible`)
  and `<launcher> service profile --json` (it starts the server's service on demand; exit 20 there
  is `remote_service_not_running`), each pinned to `--remote-root` with `env
  FINISHUP_ISOLATED_ROOT=…` when given. Strict first; asked once, on the trusted console only,
  for an unknown key; `remote_host_key_unconfirmed`, `remote_identity_changed` (never asked) and
  `trusted_console_required` as ADR-051 decision 7 records. `PROFILE_SOURCES["ssh"]` fetches the
  profile alone for `server use` and the helper.
- **The endpoint identity.** Every profile fetch is non-multiplexed (`ControlPath=none`) and
  verbose (`-v`); the identity is the host key OpenSSH verified in that very connection, read from
  its own `debug1: Server host key: <type> SHA256:<base64>` line as `ssh_host_key`
  `sha256:<hex>`; the server never supplies it. No such line, or more than one key (a host
  certificate, an OpenSSH that prints none), is `remote_identity_changed`: fail closed. Every other
  byte OpenSSH prints only chooses among fixed failure classes and is never stored, logged or
  shown. A host key the owner later re-pins changes the envelope's endpoint, so the next connection
  is `server_profile_changed` and the owner agrees again with `server use`.
- **Refresh.** The helper fetches the profile over SSH and records it with `refresh_profile` under
  the registry lock: at its start (after the relay is bound), every 10 minutes only while an
  upstream was used in the last 10 minutes (the fetch starts the server's service on demand, so an
  unused helper never starts it), when one of its own agents is refused `server_profile_changed`,
  and when a client left `state/profile-refresh-requested` (`service.client` leaves that marker
  when the server refuses a hello or request with `server_profile_changed`); at most once every 30
  seconds. The marker (`yoetz.profile-refresh-request/1`) and an agent's refusal name the revision
  the refused hello named. When that is the revision the cached profile still holds, the cache is
  stale for certain: the fetch waits only 2 seconds after the last one, so a narrowing made
  shortly after a fetch adjusts at the next tick instead of being refused for up to 30 seconds
  (found in the macOS dogfood). A request naming another revision (a fetch happened since), or
  none (an older client's empty marker, still accepted), keeps the 30-second floor, as does the
  periodic fetch. A narrowing adjusts quietly (decision 10); anything else makes the next
  connection refuse until the owner agrees again.

### 18. Transport outages on every surface; request ids across servers (layer 4)

- The five transport outages (`remote_unreachable`, `remote_auth_failed`,
  `remote_identity_changed`, `remote_service_not_running`, `remote_incompatible`) are named like
  the authorization refusals: every surface that admitted `AUTHORIZATION_REFUSAL_PHASES` now
  admits `REMOTE_CONNECTION_PHASES` (CLI text and JSON, MCP `safe_details.phase` and its text,
  the SessionStart attach and mapped texts with a head of their own, the terminal interface and the
  menu). `authorization.refusal_summary(phase)` gives each a fixed summary (no host, path or
  OpenSSH text), and each keeps its own continuation: `remote_server_test`,
  `remote_credential_repair`, `remote_identity_verify`, `remote_service_start_required`,
  `remote_release_mismatch`. None names a local service to start; hooks fail open naming the
  phase.
- **Request ids (L2 review A1).** The MCP bridge keeps a bounded map (4,096) of where each request
  id it sent went (a target id, or this computer); a request id already sent to another server, or
  between a server elsewhere and this computer, is refused `server_authorization_changed` before it
  is sent (its outcome there is unknown, and it is never resent). A replay to the same server, and
  local-to-local, are unchanged.
- **Directives reworded** (ADR-030): `server_reauthorization_required` (the owner runs `finishup
  server use local`, or `finishup server use NAME` on their own terminal for SSH, then starts a new
  session), `remote_target_no_local_service` (an HTTPS or port server this release does not reach,
  or an unreadable record), `remote_root_override_clear` (a server elsewhere this computer
  refused) and `server_on_this_computer_required` (servers on this computer and over SSH).
- **Layer 1's known edges, closed.** `requires_server_host` (and `service run`/`start`) names
  clearing the isolation override when an isolation variable or pin names the root, `server use
  local` otherwise; the terminal interface names a server elsewhere's phase and never says "the
  local FinishUP service is not reachable" for it; the menu's "Stop the service" asks the gate
  first (no question while refused) and names the server elsewhere it would stop.

### 19. The hook cold path (layer 4; design v2 section 8.9)

`connect_service_on_demand(timeout_seconds=)` uses one deadline for the gate (file reads), the
helper's start (relay only: spawn, then wait for its endpoint), the dial and the handshake; every
wait inside takes what remains. A CLI `connect_service` gives a remote transport the 30-second
start budget, never a local service.

- **Cold helper:** started and waited for within the remainder, else `service_unavailable` with
  phase `remote_unreachable`; hooks fail open naming it.
- **Stale cache:** admitted under the cached revision; the server refuses
  (`server_profile_changed`) and the client leaves the refresh marker; a hook never fetches.
- **Locked keyring:** does not apply to SSH; with `BatchMode=yes` an unloaded key is
  `remote_auth_failed`, and nothing is asked.
- **Reconnect:** none past the deadline.
- **Sleeping machine:** a dead master is noticed by `ServerAliveInterval=15` and
  `ServerAliveCountMax=3` (about 45 seconds at most) or by the next channel failure, and the helper
  restarts it; a hook spends only its own budget.
- **Imports:** a hook loads neither `client.helper`, `client.helper_runtime` nor
  `client.ssh_discovery` (the hook import-diet test); it reaches an SSH server through
  `client.helper_status` and `client.ssh_transport` only, lazily.
- **Failure classification:** why a direct stream ended (`ssh`'s exit and its diagnostics) is
  asked only within what is left of the connection's deadline, and not at all once it passed; the
  stream's close stays bounded (50 ms), and a close that bound cancels still kills and reaps its
  `ssh` (decision 20).

### 20. The consented host key on every connection; OpenSSH's own limits (layer 4 review)

The review of layer 4 (Codex, findings B1 to B5) made these binding:

- **Every new OpenSSH connection verifies the consented host key before any hello.**
  `known_hosts` decides whether OpenSSH connects; the owner's consent is bound to one key (the
  envelope's endpoint identity, `server_profile.consented_host_key`, read again for each
  connection). Every connection FinishUP makes to a target runs at `-o LogLevel=DEBUG1` (an option,
  never `-v`, so a master backgrounded by `ControlPersist` leaves its standard error to
  `/dev/null`) and is used only once its own `debug1: Server host key:` line named exactly that
  key; another key, or none, is `remote_identity_changed` and nothing is sent. So a key that
  rotated, with `known_hosts` updated and the server's installation and profile revision
  unchanged, is refused until the owner agrees again (`server use`).
  - The relay's master is ready only when its forward listens and it verified the key; a running
    master is reused only for the key it verified, so a re-consent replaces it.
  - The direct style's master is started only by `ssh_transport.ensure_direct_master`, under the
    owner-only lock `state/ssh-master.lock`; its key line is read and compared before it is
    recorded in `state/ssh-master.json` (`yoetz.ssh-master/1`: the key and the control socket's
    device and inode). A master is ridden only when that record names the current consent's key
    and its socket and it answers `-O check`; anything else at `run/m` (an older master, another
    consent's, a relay's, a stale socket) is asked to exit and replaced. A `-W` stream never
    becomes a master (`ControlMaster=no`) and is handed back only after OpenSSH printed that it
    rode the master (`mux_client_request_stdio_fwd: master session id`) or verified the key over a
    connection of its own (the master had just gone).
  - A remote `service start` that connected on its own is checked the same way after it ran (it
    carries no hello, only the fixed launcher command).
- **Socket paths.** OpenSSH takes a socket path with spaces as written (the default root on macOS
  lives under "Application Support"), but splits `-L` on `:` and expands `%` tokens and `${VAR}`
  in forward and control paths. Paths holding `:`, `%`, `$` or a control character are refused
  (`remote_unreachable` at connect); `server add ssh://` refuses `ssh_path_unusable` before
  anything reaches the server when this computer's target folder holds one, and again for the
  endpoint the server reports, before the consent and the record.
- **Bounded output.** Every fixed OpenSSH command (discovery's probes, the profile fetch, a
  remote start, the masters) has its standard output and error read as they arrive and bounded
  while read (64 KiB each; discovery: the report bound and its newline); past a bound the command
  is killed by its own pid and reaped at once, and the failure is `remote_incompatible`.
- **Termination and reaping.** A killed command's pipes are drained and dropped so its wait ends
  even when a pipe was paused on an unread buffer. A direct stream's close that its caller's bound
  cancels kills its `ssh` at once and hands the wait to a task of its own, so the child is ended
  and reaped whatever the caller does next.

## Honest limits

1. Before layer 4 no server elsewhere could be used, so nothing was held; from layer 4 an SSH
   server can, and the hold acts for it. HTTPS and port servers stay closed. What this computer
   records once a server elsewhere is recorded is the repository reports and the owner's choices.
2. A request already under way may finish; the watch acts within about a second. The texts say
   "nothing more", never "never sent".
3. The credential generation tracks the owner's FinishUP commands only.
4. A check that cannot be made keeps the last decision (fail-soft).
5. Same-user tampering with any record changes nothing FinishUP can prevent; a hand edit does
   change the generation.
6. Processes older than this release keep their rules until they restart (critic gap 14).
7. The profile is what the server states: a server that breaks FinishUP's rules can send more
   than its profile says. The consent binds this client's own sending, the revision binds the
   server's admission, and neither can bind a server that lies.
8. In layers 2 and 3 nothing fetched a profile, so no consent could be given; from layer 4 SSH
   discovery, `server use` and the helper fetch it over OpenSSH (decision 17).
9. A client learns a changed profile only when it is fetched again (the helper's refresh,
   decision 17) or the server refuses its revision; until then the server's own check refuses the
   work.
10. The relay checks each client frame before forwarding it, and the watch acts within about a
    second; a frame already forwarded may still be processed, and frames from the server are not
    parsed (the client's own connection checks what it sends and answers).
11. The SSH endpoint identity is the host key the owner's OpenSSH verified against the owner's
    `known_hosts`; FinishUP never writes `known_hosts`, and a host certificate (`@cert-authority`)
    is not supported as an identity (it fails closed as `remote_identity_changed`). Every
    connection is verified from OpenSSH's own `DEBUG1` lines (decision 20): an OpenSSH that prints
    no `Server host key` line, or no multiplexing line for a `-W` stream, fails closed, and so does
    a `ProxyJump` route, whose jump host prints a key line of its own (checked on OpenSSH 9.6).
    A master that verified the consented key before the server's key rotated is still ridden until
    it exits (it is that server's own authenticated connection); `server disconnect` ends it.
12. SSH is owner-equivalent: anyone who can log in as the service owner over SSH reaches that
    service's control socket, as they could on the server host itself (ADR-008 amendment,
    layer 4).
13. Real OpenSSH was exercised on Linux only (the capability tests against a private `sshd`, and an
    end-to-end run); macOS and WSL 2 have no recorded run (layer 7), and PR CI does not run the
    capability tests.

## Reverse states

| Way in | Way out | Way to see it |
|---|---|---|
| An owner command on a key (`server logout`, `server remove`; `server login` from layer 5) writes a new credential generation | `server remove` removes it with the root | its effect: a connection made under the old key ends with `server_authorization_changed` |
| The first server elsewhere is recorded: the repository reads and reports switch on (O3) | removing the last server elsewhere deletes the reports | `server repositories list` |
| The owner's consent to a server profile (`server add`/`server use`, a kind open) | `server remove` removes it with the root; `server use local` stops using it | `server status` (`target.consent`) |
| A narrowing adjusts the consent | the owner's next consent (`server use`) clears the notice | `server status` (`server_profile_narrowed`) |
| A bridge registers its workspace with the helper | closing the connection, Cursor's roots changing, or the lease expiring | the registrations folder of the target root |
| Layer 4: a CLI command registers its workspace once (source `cli`) | the 15-minute lease expires (no renewal); `server remove` removes it with the root | the registrations folder of the target root |
| Layer 4: a client starts an SSH target's helper (`state/helper.lock`, its status, its master) | `server disconnect`, `server remove`, a `server use` that leaves the target, `server set --style`; its idle exit | `server status [--json]` (`target.connection.helper`) |
| Layer 4: `server set NAME --style direct` | `server set NAME --style relay` | `server status [--json]` (`target.connection.style`) |
| Layer 4: a client the server refused leaves `state/profile-refresh-requested` | the helper's next refresh takes it | `server status` (consent) after the refresh |
| Layer 4 review: a stop writes `state/helper-epoch` (a new token) | none needed: it only fences helpers started before it; `server remove` removes it with the root | the helper's status (`stopped`, `stop_requested`) |
| Layer 4 review: a direct-style master is started and recorded (`state/ssh-master.json`, `state/ssh-master.lock`) | `server disconnect`, `remove`, `use <other>`, `set --style` (`-O exit` and the record removed); its own 15-minute `ControlPersist` idle exit (the record then names a socket that is gone and is never ridden) | `ssh -S <troot>/run/m -O check`; the record |

## Consequences

Every remote path a later layer opens inherits the gate, the generation and the watch through
`service.client` and `remote_binding`; a layer that adds a transport must route its connection
through them (or carry `ConnectionAuthorization` itself, FR-2). The protocol registry gains one
reason code and one continuation; `REMOTE_CONNECTION_PHASES` and the admitted `phase` safe details
(`AUTHORIZATION_REFUSAL_PHASES`) gain the hold and the changed authorization, and every surface
renders all six phases alike. A command that answers in JSON (`--json`, or a stdout that is not a
terminal) answers such a refusal in JSON too: the operation commands (`start`, `publish-work`,
`check`, `respond`, `status`, `receipt`, the support commands and `closure prepare`) print, on
stdout, the same body `service status --json` prints (`ok`, `public_code`, `reason`, `phase`,
`retryable`, `correlation_id`, `recovery`), with the same exit code and stderr lines
(`bootstrap.is_remote_refusal`, added after the macOS dogfood, 2026-11-11). Any other control
failure of an operation command still prints nothing on stdout, as on `main`. Layer 3 adds `server_profile_changed` and `server_level_unavailable`
(eight phases), the continuations `remote_reconsent` and `server_level_decision_required` (and
`remote_profile_checking`, attached by the client, decision 10), the
control error code `server_profile_changed`, the `server_profile` method and the `server-profile`
schema. Layer 4 adds no protocol reason code: the five transport phases were registered in layer 1
and are now rendered on every surface (decision 18); its new refusals (`remote_launcher_not_found`,
`remote_host_key_unconfirmed`, `ssh_path_unusable`, `style_invalid`, `style_not_applicable`,
`style_unavailable`, `helper_target_invalid`, `helper_failed`) are `finishup server` and `finishup
helper` command texts, and `server-target-status` 1.0.0 (unreleased) is amended in place with
`target.connection`. Its owner-only records beneath an SSH target root (`yoetz.helper-status/1`,
`yoetz.connection-style/1`, `yoetz.helper-epoch/1`, `yoetz.ssh-master/1`) are local files, never on
the wire.
