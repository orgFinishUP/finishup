# ADR-052 — Shared authorization: generations, the gate and consent envelopes

**Status:** Proposed for [issue #1308](https://github.com/orgFinishUP/finishup/issues/1308), layer 2
of the unified client/server model ([ADR-051](ADR-051-client-server-cut-and-server-targets.md),
*Delivery in layers*). It is the new decision record the unified design names for levels, server
profiles and the server copy, started here with the parts layer 2 builds; the profile,
registration and level-L2 sections are recorded as **not built** and are filled in by the layers
that build them. Design gates: privacy/egress (what may reach a server elsewhere, and when it
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
**Amends:** ADR-051 (decision 8 gains the repository egress hold; decisions 5, 6 and 12 the
fence, the phases and the waiting rows), ADR-008 (the credential generation), ADR-009 (the hold of
a repository whose grant forbids network egress) and ADR-030 (two continuations).

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
3. `target_reauthorization_required` (layer 3 adds the consent-envelope comparison here);
4. the kind is open in this release (`OPEN_REMOTE_KINDS`, empty in layer 2: every remote root is
   refused as `target_root_is_remote`, the phase layer 1 gave every connection and spawn path);
5. (layer 5) a credential is present for a kind that needs one;
6. `repository_egress_held` or `repository_egress_kept`, once the repository is known.

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
  `server_policy`.
- **`compare(consented, current)`** returns a typed verdict: anything unknown → `ask_again`; a
  required minimum above the level agreed → `level_unavailable` (never a silent upgrade); identical
  canonical bytes → `same`; `current ⊑ consented` → `narrower` with the fields whose narrowing
  reduces coverage (level, code sync, exclusions, review) for a receipt to name; anything else →
  `ask_again` with what widened or changed. L1 → L2 always widens.

Nothing reads an envelope in layer 2: building one from a server profile, recording the consented
digest and revision in `target.json`, and mapping the verdicts to `server_profile_changed`
(`remote_reconsent`) and `server_level_unavailable` arrive with profiles (layer 3; O5).

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
  `server_level_unavailable` are not registered here; `compare` returns typed verdicts.
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

- **Profiles and registration (layer 3):** the server profile and its revision on every request,
  registration and upload; consent fields in `target.json` (a record-schema change, since the field
  sets are exact); `server_profile_changed`, `server_level_unavailable`; the helper's workspace
  registration API, each registration bound to a grant and its generation.
- **The helper and direct styles (layers 4 and 5):** every background agent the helper serves is
  built through `remote_workspace_binding(target=…)` with the fence and its own authorization
  (critic gap 1, follow-up FR-1); the direct SSH style and the single REST client carry, check and
  watch `ConnectionAuthorization`, and the helper's relay re-checks before each relayed frame
  (critic gap 2, FR-2); the helper's own handshake takes the authorization (FR-3); the line after a
  remote `server use` or `server add` naming a held repository (FR-5).
- **Level L2 (layer 6):** no sync while the gate refuses (the hold is checked before a bundle is
  built), and stopping future egress, cancelling server work and forgetting retained copies kept
  apart (design v2 section 8.10; FR-7); the receipt count of fenced reads (O7).
- **Lifecycle (layer 7):** upgrade over running bridges and helpers, the WAN gate, and the host ×
  surface × operating system acceptance rows for the hold and the generation (FR-6).

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

## Reverse states

| Way in | Way out | Way to see it |
|---|---|---|
| An owner command on a key (`server logout`, `server remove`; `server login` from layer 5) writes a new credential generation | `server remove` removes it with the root | its effect: a connection made under the old key ends with `server_authorization_changed` |
| The first server elsewhere is recorded: the repository reads and reports switch on (O3) | removing the last server elsewhere deletes the reports | `server repositories list` |

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
failure of an operation command still prints nothing on stdout, as on `main`.
