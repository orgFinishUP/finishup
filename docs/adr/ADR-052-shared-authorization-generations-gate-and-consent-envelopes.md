# ADR-052 — Shared authorization: generations, the gate and consent envelopes

**Status:** Proposed for [issue #1308](https://github.com/orgFinishUP/finishup/issues/1308), layers 2
and 3 of the unified client/server model ([ADR-051](ADR-051-client-server-cut-and-server-targets.md),
*Delivery in layers*). It is the new decision record the unified design names for levels, server
profiles and the server copy: layer 2 built generations, the gate and consent envelopes; layer 3
builds the server profile, its revision, the consent binding and the helper's workspace
registration API (decisions 9 to 12); the level-L2 sections are recorded as **not built** and are
filled in by the layers that build them. Design gates: privacy/egress (what may reach a server elsewhere, and when it
stops) and storage (three new owner-only client records). Maintainer acknowledgement: the
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
**Amends:** ADR-051 (decision 8 gains the repository egress hold and, in layer 3, the consent to a
server profile; decisions 5, 6 and 12 the fence, the phases and the waiting rows), ADR-008 (the
credential generation; the server's profile revision record), ADR-009 (the hold of a repository
whose grant forbids network egress) and ADR-030 (two continuations in layer 2, two in layer 3).

## Context

Design v2 section 8.3 requires every egress protection before any new egress path: shared
authorization, generations, the round-5 repository hold and consent binding land before any
remote kind opens. Layer 1 closed every remote kind; layer 2 builds the protections and keeps them
closed. Nothing in this layer adds a network edge: a remote root is still refused before anything
is sent, now by one gate whose later steps are exercised in process by tests that open a kind on
purpose (`tests/builders/server_targets.py:open_remote_kinds`), and an architecture test keeps the
release's own set of open kinds empty.

## Decisions

### 1. One gate, one order, every path

`client.authorization.gate(record, repository_key=None)` refuses a connection to a server
elsewhere with the first closed reason, in this order:

1. the record is readable (an unreadable one may name a remote kind: `target_root_is_remote`);
2. `zero_network_remote_selected` (ADR-051 decision 8);
3. `target_reauthorization_required` (the disclosure version);
4. the kind is open in this release (`OPEN_REMOTE_KINDS`, empty in layers 2 and 3: every remote
   root is refused as `target_root_is_remote`, the phase layer 1 gave every connection and spawn
   path);
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
  that opens remote kinds.
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
  helper's relay included, from layer 4 on.
- **O9 — this ADR.** Started in layer 2 for generations and consent envelopes.

### 8. Not built (later layers)

- **The helper and direct styles (layers 4 and 5):** every background agent the helper serves is
  built through `remote_workspace_binding(target=…)` with the fence and its own authorization
  (critic gap 1, follow-up FR-1); the direct SSH style and the single REST client carry, check and
  watch `ConnectionAuthorization`, and the helper's relay re-checks before each relayed frame
  (critic gap 2, FR-2); the helper's own handshake takes the authorization (FR-3); the line after a
  remote `server use` or `server add` naming a held repository (FR-5). From layer 3: a profile
  source per kind (SSH runs the server's `finishup service profile --json` through the recorded
  launcher in layer 4; REST answers `GET /v1/server` in layer 5), the helper's profile refresh at
  its start, every N minutes and on `server_profile_changed`, a direct process recording the
  revision the server answered so later admissions refuse before the dial, the helper reading
  `served_workspaces` and declaring `role: background`, `service profile` shown in help, the other
  registrants (the terminal interface, long commands), REST requests carrying the revision, and
  API-key principals and scopes in the profile.
- **Level L2 (layer 6):** no sync while the gate refuses (the hold is checked before a bundle is
  built), and stopping future egress, cancelling server work and forgetting retained copies kept
  apart (design v2 section 8.10; FR-7); the receipt count of fenced reads (O7). From layer 3: a
  `[server]` configuration table offering L2 with its code sync, retention options and
  exclusions; consent at L2 (a retention chosen among those offered); the per-repository L1/L2
  consents in the per-target repository map; the revision on every sync upload; the receipt line
  for a narrowing that reduced coverage.
- **Lifecycle (layer 7):** upgrade over running bridges and helpers, the WAN gate, and the host ×
  surface × operating system acceptance rows for the hold and the generation (FR-6), and for a
  service restarted under a new profile revision.

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
  `finishup service profile [--json]`, which starts this root's service on demand and is hidden
  until layer 4's SSH discovery runs it. Control wire 2.10.0 (unreleased) is amended in place; the
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
- **Consent only on the trusted console.** With a kind open (a later layer; tests here) and a
  profile source for it (none in this release), `server add` and `server use` check the address
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
record is never served). The MCP bridge is the first registrant; the helper process is layer 4.
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

## Honest limits

1. No server elsewhere can be used in this release, so nothing is held yet; what this computer
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
8. In this release nothing fetches a profile, so no consent can be given and no revision is ever
   sent; the server side is live (it issues a revision and answers `server_profile`).
9. A client learns a changed profile only when it is fetched again (layer 4's helper) or the server
   refuses its revision; until then the server's own check refuses the work.

## Reverse states

| Way in | Way out | Way to see it |
|---|---|---|
| An owner command on a key (`server logout`, `server remove`; `server login` from layer 5) writes a new credential generation | `server remove` removes it with the root | its effect: a connection made under the old key ends with `server_authorization_changed` |
| The first server elsewhere is recorded: the repository reads and reports switch on (O3) | removing the last server elsewhere deletes the reports | `server repositories list` |
| The owner's consent to a server profile (`server add`/`server use`, a kind open) | `server remove` removes it with the root; `server use local` stops using it | `server status` (`target.consent`) |
| A narrowing adjusts the consent | the owner's next consent (`server use`) clears the notice | `server status` (`server_profile_narrowed`) |
| A bridge registers its workspace with the helper | closing the connection, Cursor's roots changing, or the lease expiring | the registrations folder of the target root |

## Consequences

Every remote path a later layer opens inherits the gate, the generation and the watch through
`service.client` and `remote_binding`; a layer that adds a transport must route its connection
through them (or carry `ConnectionAuthorization` itself, FR-2). The protocol registry gains one
reason code and one continuation; `REMOTE_CONNECTION_PHASES` and the admitted `phase` safe details
(`AUTHORIZATION_REFUSAL_PHASES`) gain the hold and the changed authorization, and every surface
renders all six phases alike. Layer 3 adds `server_profile_changed` and `server_level_unavailable`
(eight phases), the continuations `remote_reconsent` and `server_level_decision_required` (and
`remote_profile_checking`, attached by the client, decision 10), the
control error code `server_profile_changed`, the `server_profile` method and the `server-profile`
schema.
