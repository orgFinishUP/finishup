# FinishUP architecture

How the system is put together and why. This page describes shape and ownership; the code under
`src/finishup/` is the executable truth, and the ADRs under [`docs/adr/`](adr/) are the decisions that
bind it. Shared names — ID prefixes, error codes, event families, coverage dimensions, port
signatures — live in [`docs/INTERFACES.md`](INTERFACES.md).

## The one-sentence version

A persistent local service owns the keys, the decrypted state, the writers, the privacy authority,
and all outbound access; the CLI, the MCP bridge, and any future UI are clients that ask it to do
things. That service runs on your own machine: the everyday one by default, or a named local
server the owner added, each with its own vault and ledger. A client can also use the owner's own
FinishUP server on another machine over SSH, or over HTTPS (on the web, or on a port of this
computer) through its REST v1 edge (see [Client and server](#client-and-server)).

## Trust topology

```
  agent (via MCP)   human (via CLI)   human (terminal UI)
         \                   |                  /
          \                  |                 /
           +--------- control protocol --------+
                              |
                    +---------v----------+
                    |   trusted local    |   owns: vault keys, decrypted state,
                    |      service       |          storage writers, privacy policy,
                    +---------+----------+          outbound dispatch
                              |
        +---------------------+---------------------+
        |                     |                     |
   SQLite bundle        object store           provider egress
   (structural)         (encrypted)            (policy-gated)
```

The boundary is the point. A client process never holds an encryption key or a decrypted bundle
handle, and never talks to a provider directly. That is what makes "the agent cannot quietly
exfiltrate your repository" a structural property rather than a promise
([ADR-008](adr/ADR-008-local-service-vault-trust-boundary.md),
[ADR-009](adr/ADR-009-data-egress-privacy.md)).

Privacy authority has two durable levels: the machine policy is an installation ceiling, while
external LLM work also requires an exact row for the installation-keyed commitment of the trusted
session's canonical repository. The service derives that identity from actual/configured working
directory, resolves Git's common root (or a resolved non-Git directory), and discards the raw path.
Branches and linked worktrees share authority; independent clones do not. The public
`workspace_ref` used to attach a task is a different, model-controlled identity and cannot select
privacy authority.

Secret material never travels over an ordinary CLI argument, environment variable, config file,
log, trace, transcript, or LLM context. Credentials are provisioned through a confidential terminal
ceremony ([ADR-015](adr/ADR-015-elevated-bootstrap-consent.md),
[ADR-016](adr/ADR-016-human-review-non-default-actions.md)). An SSH server needs no FinishUP
credential: OpenSSH authenticates with the owner's own keys and agent, and FinishUP never reads or
stores an SSH key. An HTTPS server's API key is typed at a masked prompt on the owner's terminal
(or read once from an owner-only key file), checked with the server, and kept in the OS
credential store or, where none is usable, an owner-only credential file
([ADR-051](adr/ADR-051-client-server-cut-and-server-targets.md) decision 7); only the target's
helper reads it, or, in the direct style the owner may choose, each dialing process
([ADR-053](adr/ADR-053-rest-v1-public-contract.md)).

The terminal interface sits on the human-CLI leg and is bound by the same rule. It has no
credential path of its own: when a secret is needed it suspends itself and hands the controlling
terminal to that same ceremony, so no secret byte enters the interface's widget state, transcript,
or any snapshot of it ([ADR-017](adr/ADR-017-full-screen-terminal-interface.md) decision 7).

## Module map

| Package | Role |
|---|---|
| `protocol/` | Canonical wire form: IDs, request/result models, canonical JSON, digests. Pure. |
| `domain/` | Values and events — the vocabulary of what happened. Pure. |
| `kernel/` | Local-check truth: reducers, projections, the check engine, ranking, proof-based finding resolution, receipt building, and the versioned policy packs under `kernel/policies/`. Pure — no IO, no clock, no network. |
| `ports/` | The interfaces the application depends on. First-class boundaries: `ledger`, `objects`, `keys`, `runtime`, `semantic`, `privacy`, `importer`, `integrations`, `subject_state`, `observation` ([ADR-010](adr/ADR-010-harness-integration-port.md)), `plugin_artifacts` ([ADR-023](adr/ADR-023-portable-plugin-carrier-host-activation.md)), `control`, `harness_mcp`, `maintenance`, `check_sandbox`, `workspace_inspect`, `secret_memory`; the rest are small effect ports (`clock`, `ids`, `diagnostics`) and read-only catalogs (`start_catalog`, `publish_response_catalog`). |
| `adapters/` | Concrete implementations of those ports: `sqlite/`, `objects/`, `keys/`, `memory/` (the in-memory reference used for conformance parity), `providers/`, `privacy/`, `importers/`, `integrations/`, `control/`, plus the single-module adapters at the package root — `mcp_stdio.py`, `git_subject_state.py`, `repository_identity.py`, `workspace_inspect.py`, `session_events.py`, `runtime.py`, `approved_checks.py`, `check_sandbox.py`, and `observation_semantic_advice.py`. |
| `application/` | Use cases. One module per public operation (`start`, `publish_work`, `check`, `respond`, `status`, `receipt`), plus egress, privacy policy and privacy control, maintenance, package update, import review, recommendations, harness integration (`harness_mcp`, `applied_mcp_route`, `codex_plugin`, `integrations`), the AI-powered review case and attempt builders, and the observation family (`observation_coordinator` with its `drain`, `health`, `verification`, `materialize`, `check_policy`, `advice`, and `control` modules). |
| `service/` | The persistent trusted process: lifecycle, vault, unlock, control protocol, composition. |
| `cli/`, `mcp/` | Client surfaces. Thin — they translate, they do not decide. |
| `tui/` | The full-screen terminal interface. Presentation only. `runtime.py` is the sole bridge to application services and originates no decision; `render.py` is pure text with no rendering-framework import, so safety-relevant wording is snapshot-tested; `widgets/` holds no security logic. |
| `config/`, `observability/`, `version.py` | TOML settings, privacy-safe logging, resource manifest and identity. |
| `resources/` | Generated byte-mirror of the repo-root `schemas/`, `fixtures/`, `guidance/`, `skills/`, `migrations/`, and `support/` trees, packaged with the wheel and verified against `resources/manifest.json` at load. Edit the root sources; `scripts/sync_resource_ripple.py` converges this mirror. |

`memory/` existing alongside `sqlite/` is deliberate: the conformance suite runs the same scenarios
against both, so "the durable adapter behaves like the reference" is a test result rather than an
assumption.

Multi-agent work has three separate owners. `application/lineage.py` and
`adapters/sqlite/lineage_catalog.py` own recoverable delegation and attachment capabilities;
`application/lineage_coordinator.py` records authorized child dependency snapshots in the parent
ledger, and `kernel/lineage.py` evaluates those frozen snapshots for checks and receipts.
`application/projects.py` owns project membership and admission, while `application/coordination.py`
and `adapters/sqlite/project_coordination.py` own attributable overlap detections and durable
delivery. `application/task_views.py` builds their read-only status views. Host observations enter
through `ports/host_lineage.py` and `adapters/sqlite/host_lineage.py`; a provisional observation has
no task bundle until a separately authorized child start binds it.

`tui/` sitting beside `cli/` rather than inside it is also deliberate. It is a second presentation
of the same operations, not a second authority over them: every gate — preview digests, foreign
MCP entries, privacy widening, vault state, provider readiness — is enforced by the owning service
and merely transcribed by the interface. The split makes that reviewable, because anything in
`tui/` that reached past `runtime.py` would be visible as an import.

## Client and server

[ADR-051](adr/ADR-051-client-server-cut-and-server-targets.md) (Proposed) separates the FinishUP
*client* — everything between the agent or user and the service: hooks, the MCP bridge, the CLI
and the terminal interface — from the *server*, without moving a package. The cut line is a
contract: every module carries one side, and an AST test that also sees imports inside functions
fails on any crossing that its ledger of today's crossings does not list. That ledger may only
shrink. A `finishup.client` module may carry one kind of entry only, `client_outbox`: the drain that
delivers what a remote root's hooks captured opens that root's own observation outbox, a module the
service's observation store still shares.

| Side | Modules |
|---|---|
| **SHARED** (imports SHARED only) | `protocol`, `ports`, `domain`, `config`, `observability`, `resources`, `legacy_names`, `version`; `rest` (the REST v1 contract, key store, routes and listeners, hosted by either server edge; a client imports only `rest.contract`); `service.control_protocol` and `service.confidential_protocol` (wire codecs); `adapters.control`; the credential-store primitives `adapters.keys.os_keyring` and `adapters.keys.owner_file_store`; the pure renderers `kernel.fact_lineage` and `kernel.claim_verification`. |
| **WORKSPACE** (imports WORKSPACE and SHARED only; CLIENT and SERVER may import it) | The workspace readers, which run wherever the workspace is: in the local service for a local root, and in the client's workspace agent for a remote one. `adapters.git_change_capture`, `task_input_read`, `approved_checks`, `check_sandbox`, `workspace_inspect`, `home_project_reads`, `input_summary`, `git_subject_state`, `git_rev_parse`, `git_version`; `adapters.workspace_root` (the one rule for "which directory is this workspace"); and `application.observation_check_policy` (the repository's own `checks.toml`). None of them reaches storage, the vault, providers, the service or a client surface. |
| **CLIENT** | `cli`, `mcp`, `tui`, the new `client` package, `service.client`, `service.confidential_client`, the host integration adapters under `adapters.integrations` (except the observation store), `adapters.workspace_binding`, `workspace_fingerprint`, `mcp_stdio`, `process_lifetime`, `release_runtime`, `package_upgrade`, and the client-side application modules `harness_mcp`, `host_connection`, `codex_plugin`, `applied_mcp_route`, `upgrade`, `package_update`, `observation_drain`. |
| **SERVER** | The rest of `service`, `application`, `kernel` and `adapters`: storage, the vault, providers, privacy and the runtime. |
| **GATEWAY** (server host) | `gateway`: the gateway server edge (layer 5), a same-user control client of the service that serves REST v1 and re-enters the service over its control socket. It may import SHARED modules and `service.client`, never a workspace reader, and never touches the vault or storage. No module carried this side before layer 5. |

Commands carry a scope too. Each CLI and terminal-interface command is `any`, `server_host` (vault
setup and unlock, provider and privacy configuration, backup, restore, migrate, the service
process) or `client_only` (host registration and `finishup server …`). A `server_host` command is
refused while a remote target is active, with `requires_server_host`. Observation administration
(`finishup observe …`, `/observe`) is `any`, not `server_host`: it acts on the active root's own
observation store (consent, content profiles, approved-check trust, mappings and the outbox),
which stays on this computer and is the client's authority for a remote target (ADR-051 decision
12), so it is never refused there.

**Targets.** The client talks to one *target*: the ambient local service by default, or a named
local service (its own isolated root, vault and ledger, started on demand). The owner adds targets
with `finishup server add NAME --local` and picks one with `finishup server use`, which writes an
owner-only selection file. That file is the lowest-precedence root source: the isolation variable
and a runtime pin always win, a selection that names a missing root fails closed instead of
falling back, and no host registration records it. The target record also knows the remote kinds
(`local_port`, `ssh`, `https`: a FinishUP service the same owner runs elsewhere). Layer 1 kept
them closed; layer 4 opens `ssh` (`finishup server add NAME ssh://[user@]host[:port]`), and layer 5
opens `https` and `local_port` (`finishup server add NAME https://HOST[:PORT][/BASE]` or `--port
PORT`); `remote_kind_unavailable` now refuses only an address that names none of them.

**The workspace agent.** The service reads the agent's working tree for the task base, the
check-time change, requested-output facts, task inputs, declared tests, reviewer file reads,
observation verification and approved checks. A server on another machine cannot. For a remote
target the client sends a keyed workspace *claim* instead of a path, and a client-side workspace
agent (`client/workspace_agent.py`, eighteen bounded operations cataloged in
`ports/workspace_agent.py`, twenty with level L2's two sync operations from layer 6) answers the
server's `workspace_call`s with the same adapters and fences the local service uses. On the
server, `service/workspace_hub.py` keeps the live agent channels keyed by workspace handle and
correlates each call with its reply, and
`service/workspace_routing.py` wraps every workspace port the service composes: an absolute path
goes to the local adapter unchanged, a `client:` handle goes to the hub, and no local adapter is
ever handed a handle. Evidence obtained that way is labelled `client_attested`, and every
non-local receipt rendering says so in one fixed line. When no agent can be reached the receipt
carries a typed gap; nothing passes silently. Layer 1 ships all of this and tests it in process;
from layer 4 an SSH server reaches it over the network, and from layer 5 an HTTPS server.

**Shared authorization (layer 2,
[ADR-052](adr/ADR-052-shared-authorization-generations-gate-and-consent-envelopes.md)).**
`client/authorization.py` (hook-safe) is the one gate every connection from a remote root passes
before any claim, dial or spawn — zero-network, the disclosure, an open kind
(`OPEN_REMOTE_KINDS`, empty in layers 2 and 3, `{ssh}` in layer 4, `{ssh, https, local_port}` from
layer 5), the consent (layer 3), a key for an HTTPS target (layer 5, checked where the REST client
reads it), then the repository hold — and the authorization
generation an admitted connection watches. `service/client.py` runs the gate in both connect paths
(`_admit_remote`) and keeps the admission in `ServiceClient`, checked before every frame, on reuse
and by a one-second watch; a local connection carries none. `client/repository_hold.py` decides
the hold of a repository whose own grant forbids network egress from the reports
`client/everyday_repository.py` records (dormant until a remote target exists), and the workspace
agent fences held worktrees. `protocol/consent_envelope.py` (SHARED, pure) holds the consent
envelope types, their canonical form and their partial order.

**Server profiles and consent (layer 3, ADR-052 decisions 9 to 12).** `protocol/server_profile.py`
(SHARED, pure, hook-safe) parses and verifies `server-profile` 1.0.0 and builds the envelope of
using a profile at a level; `protocol/server_profile_contract.py` is its schema contract.
`service/server_profile.py` (SERVER) decides what this service offers (levels pinned by the
release, review egress from its own config) and keeps the profile revision it issues at start;
the daemon answers the structural `server_profile` method and admits a remote hello, and every
request that does work, only under that revision (`service/control_protocol.py`,
`service/daemon.py`). `client/server_profile.py` (CLIENT, hook-safe readers) keeps the consented
envelope and the last profile fetched beside a `/2` `target.json` and decides the gate's consent
step (after the kind step); `cli/server.py` asks for the consent on the trusted console once a
kind opens, and `server status` shows it. `client/helper_registrations.py` is the API through
which client processes register the workspaces a target's helper serves (layer 4 runs the
helper); the MCP bridge registers its claimed workspace, and `service/workspace_hub.py` routes a
live call to its own connection's agent and background work to a `background` agent first. In
layer 3 no profile source is registered and no kind is open.

**SSH servers and the helper (layer 4, ADR-052 decisions 13 to 19).** Layer 4 opens `ssh`. Every
part of it is CLIENT and never runs or loads on a hook's path unless an SSH target is in use.

- `client/ssh_discovery.py` runs at `server add` and `server use` (and in the helper's refresh):
  over OpenSSH it finds the server's own `finishup` launcher at fixed install paths, asks it for
  its control endpoint (`service endpoint --json`) and its profile (`service profile --json`), and
  takes the host key OpenSSH verified in that connection as the endpoint identity the consent is
  bound to. An unknown host key is asked about only by OpenSSH on the owner's terminal; a changed
  one is refused (`remote_identity_changed`).
- `client/ssh_transport.py` holds the fixed OpenSSH argv: the relay's master with its stream-local
  forward, the direct style's verified master and its `ssh -W` streams, and the closed
  classification of OpenSSH failures. Every new connection is used only once it verified the host
  key the owner's consent names (OpenSSH's own `DEBUG1` line; a rotated key with `known_hosts`
  updated is refused until the owner agrees again), every command's output is bounded while it is
  read, and a socket path is handed over as written (spaces included) or refused.
- `client/helper.py` (`finishup helper run --target <id>`, hidden, `client_only`) is the one
  background helper per SSH target, started on demand by a client and never by `service run`,
  stopped by `server disconnect|remove|use <other>|set --style` through its owner-only stop epoch
  (never a signal; a pending start is fenced), idle
  15 minutes after its last client. In the relay style (the default) it serves
  `<target root>/run/control.sock`, so hooks, the MCP bridge, the CLI and the terminal interface
  keep dialling a Unix endpoint, and checks every client frame against its own admission before
  forwarding it. In every style it runs one background workspace agent per registered workspace
  (`role: background`), drains captured observations every 30 seconds, and re-fetches the
  server's profile. It admits itself through the shared gate (`authorization.authorize_target`);
  a lapse ends every relayed connection and agent, and zero-network stops it at once.
  `client/helper_status.py` (hook-safe) is what a client needs of it: the lock, the status record
  and its phases, start (with the stop epoch it read) and stop (the epoch, then the lock seen
  free). `client/helper_runtime.py` is the SSH
  `TargetRuntime` and the CLI's one-time registration.
- `service/client.py` dispatches an admitted SSH root on its connection style (the helper's
  endpoint, or `ssh -W`), within one deadline for a hook (design v2 section 8.9), and names a
  transport outage by its closed phase on every surface; never a local service to start.

**HTTPS servers and REST v1 (layer 5, [ADR-053](adr/ADR-053-rest-v1-public-contract.md)).**
Layer 5 opens `https` and `local_port` over REST v1, the one public network contract.

- **The contract** (`rest/contract.py`, SHARED): routes, headers, scopes, the API key shape, the
  claim header and its per-principal namespace, the profile-revision header, the closed
  `rest-error` reasons, the seven `rest-*` documents and the REST API manifest that decides
  compatibility (the core server serves exactly its own release's).
- **The edges** (server host). `rest/app.py` serves the routes over a backend interface
  (`rest/backend.py`) and owns everything both edges share: API keys (`rest/api_keys.py`, hashed
  at rest, with scopes and principals), the unauthenticated budget, the revision and manifest
  checks, operations and agents; `rest/listener.py` is the TLS listener with its bounds and
  `rest/audit.py` the bounded audit. Two backends: `gateway/` (GATEWAY, the default), a separate
  process of the service's user with no vault that re-enters the service over its owner-only
  control socket as ordinary control connections; and `service/rest_native.py` (SERVER), the
  listener inside the service, an owner opt-in that puts the process holding the vault on the
  network. `cli/rest_server.py` runs either (`finishup service rest run`) and manages keys
  (`finishup service api-key`).
- **The client.** `client/rest_client.py` is the one REST client library (TLS by the owner's CA
  file, pin or the system store; no proxies or redirects; bounded answers; the key read off the
  event loop); `client/rest_stream.py` maps control frames to REST requests, so the same mapping
  serves the direct style (under a `ServiceClient`) and the relay style (inside the helper);
  `client/rest_discovery.py` makes the unauthenticated discovery, fetches the profile with the key
  (`GET /v1/server`) and checks a key for `server login`. The first two load on a hook's path only
  for an HTTPS target in the direct style; discovery never does.
- **HTTPS through the helper.** The helper serves every remote kind: for an HTTPS or port target its
  upstream is a REST stream over one warm TLS connection (`RestUpstream` in `client/helper.py`),
  and only it reads the API key in the relay style. `server login` and `server logout` stop it so
  nothing goes on under the old key.

**Level L2, the server copy (layer 6, [ADR-054](adr/ADR-054-level-l2-the-server-copy.md)).**
Built and **released**, and still opt-in at both ends: a server offers L2 only when its owner's
`[server.code_copy]` table (config 1.4.0) enables an offer, and a client sends a copy only after
its owner consents at L2 on the trusted console; otherwise every surface behaves as at L1. The
server pulls; only the target's helper answers.

Reads from the copy, provenance and erasure: `service/workspace_routing.py` serves a claim-bound
task's git and in-root reads (task base, capture, change counts, reviewer reads beneath the root,
task inputs inside it, an observation workspace's changed paths and inspection) from the snapshot
the task is pinned to, through an owner-only checkout the service materializes from verified copy
objects, while outside reads and approved checks stay with the client's workspace agent; an
offline client's reads use the copy as last synced (`stale_copy_read`), and its approved checks
fail `workspace_agent_unavailable`. A task keeps one source for its git reads, and an approved
check whose subject state differs from the pinned snapshot is never a pass
(`code_snapshot_mismatch`). Every routed read is counted per task by where it was answered
(`domain/evidence_provenance.py`), and the receipt of a task that read the copy carries that
account (`evidence_provenance`) and fixed "Workspace evidence" lines in every rendering instead of
level L1's client-attested line. Forgetting a copy (by its owner or on expiry) records a
service-written `content_forgotten` event in each pinned task's ledger, erases the task's
captured-change and review objects, and masks the quoted excerpts in every later projection,
leaving findings and checks and a "content forgotten" marker on the receipt.

- `protocol/server_copy.py` (SHARED, pure): the `git-bundle-1` wire format, its one verifier for the
  client's audit and the server's admission, the snapshot manifest, the provenance tokens and the
  release switch.
- `domain/code_exclusions.py` (SHARED): the names always left out of a copy and how a pattern
  matches.
- `client/code_secrets.py` (CLIENT): the content scan for known secret formats before a file enters
  a copy.
- `client/code_copy_settings.py` (CLIENT): the owner's per-repository choices
  (`config/code-copy.json`: level L1, exclusions, allowed contents).
- `client/code_export.py` (CLIENT, helper only): the sanitized exporter and its FinishUP-owned
  export object database.
- `client/code_sync.py` (CLIENT, helper only): answers the server's two code-sync operations after
  the gate and the consent are checked again.
- `client/code_sync_fence.py` (CLIENT): the lease-bound fence `server remove` raises so no code is
  synced to a target while its copies are forgotten.
- `service/code_store.py` (SERVER): the encrypted copy store (keys under the vault's authority,
  admission, quotas, forget with its tombstone, expiry).
- `service/code_copy.py` (SERVER): the puller that syncs before the task-base and check reads,
  the pins, the evidence tally, the expiry (`days:N`, `task_close`) and the vault-derived copy
  keys.
- `service/code_checkout.py` (SERVER): the owner-only checkout of a copy's snapshot that routed
  reads are served from.
- `domain/evidence_provenance.py` (SHARED): one task's per-evidence account,
  `yoetz.evidence-provenance/1`.
- `application/content_forgetting.py` and `kernel/forgotten_content.py` (SERVER): the
  `content_forgotten` event, the erasure of a task's derived content objects and the masks every
  projection applies after it.
- `cli/server_code.py` (CLIENT): `finishup server code` (`list`, `forget [--all]`, `exclude`,
  `allow add|list|remove`, `level`).

### Topology by target

```
LOCAL (default; unchanged)
  hook / MCP / CLI / TUI ──AF_UNIX, peer-UID check──► <ambient runtime>/control.sock ──► service

NAMED LOCAL (each an ADR-028 persistent instance root)
  selected "work" ──► <state>/servers/t_1a2b3c4d/run/control.sock ──► service #2 (own vault, ledger)
  selected "lab"  ──► <state>/servers/t_9f8e7d6c/run/control.sock ──► service #3

REMOTE (local_port, ssh, https; the owner's own server) — ssh built in layer 4; https and
local_port in layer 5
  client host                                             server host (same owner)

  ssh: control frames over the forwarded owner-only socket (sshd stream-local forwarding)
  relay:  hook / MCP / CLI / TUI ─► <troot>/run/control.sock ─► helper ─► ssh -M -L ═══╗
  direct: hook / MCP / CLI / TUI ─► ssh -W (shared ControlMaster) ═════════════════════╣
  server: service ◄─ control.sock ◄─ sshd (stream-local forward) ◄═════════════════════╝
  helper: background workspace agent per registration, observation drain, profile re-check
  workspace agent ◄══════ workspace_call / workspace_reply frames ══════ workspace hub

  https, local_port: REST v1 to the edge the server owner runs
  hook / MCP / CLI / TUI ─► relay helper (maps frames to REST) ─┐
  hook / MCP / CLI / TUI ─► direct REST client ─────────────────┴═ REST v1 ═► edge
      edge = gateway (separate process, no vault) ─► control.sock ─► service
          or native (a listener inside the service) ─► service
  workspace agent ◄══════ REST v1 (register, poll, reply) ══════ edge ─► workspace hub

  human-control and secret channels: never leave the server host
```

None of the remote path existed in layer 1. Layer 4 builds the SSH part (the helper, both
connection styles and the SSH edge); layer 5 builds the REST part (REST v1, the gateway and native
edges, the one REST client and its mapping, the helper's REST upstream); layer 6 builds level L2's
server copy and releases it. The remote path follows
ADR-051's unified model, delivered in later layers: a *level* says where
the work happens (L0 everything on this computer, the default; L1 the server keeps tasks and
review while this computer's workspace agent answers its reads; L2 the server also keeps a copy of
the code), a *connection style* says how this computer reaches the server (`unix` for local and
named local servers; relay through one background helper per server; direct from each process),
and a *server edge* says how the server is reached (ssh, a separate gateway process, or a native
listener). The server offers; the client decides within the owner's consent and this computer's
privacy policy.

## The six operations

`start`, `publish_work`, `check`, `respond`, `status`, `receipt` — identical request and result
contracts on the CLI and over MCP ([ADR-002](adr/ADR-002-canonical-protocol.md),
[ADR-010](adr/ADR-010-harness-integration-port.md)). Everything else — import/review,
backup/restore/migrate, integration, version, service, MCP serving — is a bounded support surface,
not a seventh operation.

Flow for a typical task:

1. **`start`** opens a task and issues a session and a writer identity.
2. **`publish_work`** records bounded, participant-published facts: plan, obligations, claims,
   actions, results, evidence. On this cooperative path the participant publishes; FinishUP does not
   infer observation or verification from those assertions.
3. **`check`** runs the local policy packs over the recorded state, producing findings with
   an exact coverage vector. If AI-powered review is configured and requested, an advisory
   provenance-labeled pass runs inside the privacy policy and is deterministically fenced.
4. **`respond`** answers a finding: act, supply evidence, revise the claim, dispute, or state an
   unresolved limitation. A response never erases a finding.
5. **`receipt`** projects the honest summary: what was checked, at what coverage, what is still
   open. Available as `json`, `markdown`, or `text`.

With separate workspace observation consent, first-party harness hooks may retain selected visible content as
secret-scanned encrypted objects. The observation coordinator can materialize only eligible tool
output, changed-file, diff, and bounded inspection objects as `observation_captured` immutable
evidence. That path proves retention and byte identity, not correctness, reproduction, or egress
authority; ordinary `publish_work` cannot self-award it.

## External AI-powered evaluator authorities

External review has two closed runtime shapes behind the same privacy gateway. HTTP profiles use a
one-attempt credential handle minted from the FinishUP vault. The Codex subscription profile instead
launches one exact digest-bound Codex app-server process group and gives it a secret-free attempt
authority; Codex alone owns ChatGPT OAuth and the upstream OpenAI body. Both receive only the
approved canonical case after repository-scoped policy authorization, and both terminate in a
privacy receipt.

The Codex process runs from an empty per-attempt directory with a dedicated owner-private home,
scrubbed environment, strict no-tool configuration, an ephemeral thread, and app-server v2 JSONL
over stdio. Account and model readiness happen before case disclosure. The service rejects tool
requests or extra output and must verify process-group cleanup before success. Provenance binds the
observable case/runtime boundary and explicitly says that the upstream body is unavailable; it
does not invent HTTP-level evidence.

## Determinism and honesty rules

These are enforced in code and locked by tests; they are the reason the system is worth trusting.

- **Coverage-bounded language.** "No issue detected at coverage X" is never rendered as "verified".
- **Local-check results depend only on canonical recorded inputs** plus the versioned policy and
  engine identity. Same inputs, same version, same findings.
- **AI-powered output is advisory**, provenance-labeled, and fenced. `semantic_required` never
  erases a completed local-check result: unavailability returns that result as `incomplete_check`
  with an exact gap, not a failure.
- **Nothing user-controlled** — payloads, titles, paths, prompts, model output — reaches SQLite
  structural tables, logs, errors, or MCP text summaries.
- **Every retryable write has an idempotency identity.** A timeout never proves failure.
- **Every network channel is independently authorized.** No profile overrides the never-send set,
  and effective policy loosens only through a reauthenticated decision the user makes: the trusted
  local ceremony, or — for one exact prepared, expiring consent target — the user's explicit
  current-chat instruction relayed by a capable agent through the consent lane (ADR-016), an
  attestation FinishUP cannot independently authenticate.
- **Machine capability is not repository consent.** External LLM admission requires the exact
  repository grant before provider construction or credential minting; a first grant may atomically
  combine a machine-ceiling widening with repository-row creation.

## Storage

One SQLite bundle per task holds structural rows; content-bearing material lives in the encrypted
object store and is referenced by digest. Migrations under `migrations/` are append-only and CI
enforces that ([ADR-003](adr/ADR-003-storage-sqlite-durability.md)). Task lineage and first-class
projects ([ADR-027](adr/ADR-027-task-lineage-and-project-scope.md)) do not change that layout: a
child is another bundle, and lineage or project membership lives in the catalog. The service, not
a client, projects parent rollup and project status. Recovery paths — backup,
restore, migrate, quarantine — are documented in [`docs/runbooks/`](runbooks/).
Observation migration 0008 adds only nullable digest/byte bindings for the secret-scanned inner
content; it adds no plaintext column and leaves older unbound rows readable at weaker coverage.
Migration 0009 rebuilds the observation cursor and envelope tables so their source CHECK admits
every `ObservationSource` member, including the Claude Code and Cursor hook sources, preserving
existing rows and identities.

Catalog migration preserves accepted machine-policy bytes. It may consume only bounded
pre-upgrade route or one first-repository entitlement to clone that authority into a narrower child
row without reapproval; later repositories inherit nothing. Schema decoders for older control
shapes remain readable but cannot bypass the repository/authority-digest gate.

## Harness integration

FinishUP works with any MCP host with no integration, no installed skill, and no configuration: the
host gets the six operations, read-only `read_guidance`, a short always-delivered instruction set,
and the same guidance documents every harness ships, fetchable on demand.

Codex is the first harness with a first-party integration because its skill surface delivers that
guidance natively. The guidance itself is harness-neutral, owned once under [`guidance/`](../guidance/),
and shipped byte-identically everywhere. Integration is a port with Codex as its first adapter
([ADR-010](adr/ADR-010-harness-integration-port.md)) — a fork can make FinishUP first-party on another
harness by adding an adapter and a profile, without touching the core.

Integration buys ergonomics, never a stronger claim. An agent publishing over MCP earns the weakest
honest coverage, and the coverage vector says so exactly.

The accepted packaging design extends this reach without moving any authority
([ADR-023](adr/ADR-023-portable-plugin-carrier-host-activation.md); its skills-only artifact slice
is implemented by issue #150 and later capabilities remain phased under #148). One neutral
`PortablePluginPlan` projects into either a portable
Agent Plugins 1.0.0 artifact, for hosts that consume the universal standard in their own client
plugin root, or a generated host-native projection in a distinct documented root for hosts that do
not. The artifact is a carrier, never an authority: installation, activation, MCP ownership, and
observation stay separately owned sibling capabilities (`PluginArtifactPort`,
`HostActivationPort`, the existing `HarnessMcpPort` and `ObservationPort`), and format
compatibility with the standard earns no support claim, activation claim, or coverage.

`src/finishup/ports/plugin_artifacts.py` owns the neutral plan and lifecycle types.
`src/finishup/adapters/integrations/portable_plugin.py` owns the Agent Plugins 1.0.0 projection,
offline validation, optional exclusive route-bound `mcp.json`, Codex-root preview/status, and
failure-atomic whole-directory migration. It
reads only packaged `skills/portable/`, `guidance/`, and vendored `support/agent-plugins/` bytes.
The existing `codex_plugin.py` remains the native fallback and is not a source for the portable
manifest.

Cursor is the second first-party harness and remains local-only. The adapter at
`adapters/integrations/cursor_integration.py` owns exact IDE/CLI/SDK identity capture, the
Agent Plugins and Cursor-native projections, explicit user-scope lifecycle, MCP source precedence,
live classified MCP process identity for activation mismatch (`cursor_mcp_runtime.py`),
and the pinned `sdk.v1` TypeScript/Python profiles. The lifecycle consumes one exact
`plugin_artifact_apply` pending only after the scoped presence cell selected per platform by
`artifact_presence.py` obtains a fresh OS-authenticated result: `macos_artifact_presence.py`
(Apple LocalAuthentication) on macOS, `linux_artifact_presence.py` (PAM re-authentication through
the trusted foreground console) on Linux and WSL 2, and fail closed elsewhere; this does not
populate the service-wide presence cell. The one service-wide `UserPresencePort` is
`adapters/keys/macos_user_presence.py` (Apple LocalAuthentication, composed only on macOS), and the
service uses it only for the owner receipt view ([ADR-009](adr/ADR-009-data-egress-privacy.md)
round 5). Cursor-native hooks enter through
`hooks cursor-observe`. On the default structural profile, this boundary retains only allowlisted
structural scalars and a one-way changed-path digest. On that profile, it drops prompts, reasoning,
response text, file paths and contents, edits, MCP arguments/results, transcripts, command output,
and email before observation storage. A separately selected ordinary-work profile can also retain
visible tool content under its matching per-host content consent; see the
[Cursor runbook](runbooks/cursor-integration.md#hooks-and-observation) for capture limits and
acceptance coverage. The adapter never reads or mutates Cursor caches. Cursor Cloud is not a
registered local capability.

Claude Code is the third first-party harness, but it is a native dual target rather than an Agent
Plugins client. `adapters/integrations/claude_code_integration.py` generates a strict private local
marketplace and Claude-native plugin from `PortablePluginPlan`, then delegates project installation,
update, enablement, disablement, and qualified removal to the exact Claude executable. Status reads
Claude's project settings/list result and exact cache bytes while keeping enablement distinct from
loaded-session activation. It observes local/project/user/plugin/connector MCP sources without
turning Claude's precedence winner into a FinishUP ownership claim.

Claude-native hooks enter through `hooks claude-observe`. On the default structural profile, only
the exact scoped FinishUP MCP tool names and bounded structural lifecycle facts survive; raw Claude
prompt/transcript/path/tool/result/error content is discarded before storage. A separately selected
ordinary-work profile can also retain visible tool content under its matching per-host content
consent; see the [Claude Code runbook](runbooks/claude-code-integration.md#hooks-and-observation)
for capture limits and acceptance coverage. The `claude_hook` source is carried on local-control schema
`2.2.0`. The initial capability fixture covers only local CLI `2.1.241`, macOS arm64, project scope,
and private marketplace install. Desktop, remote, web/cloud, synced, managed/user/local scope,
Agent SDK, loaded-session/model-use, AI-powered review, privacy-receipt, and workflow-receipt cells
require
their own evidence.
