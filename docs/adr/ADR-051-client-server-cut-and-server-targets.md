# ADR-051 — Client/server cut line, server targets and the workspace agent

**Status:** Proposed for [issue #1308](https://github.com/orgFinishUP/finishup/issues/1308), which
scopes the original request in [issue #903](https://github.com/orgFinishUP/finishup/issues/903).
Rewritten on 2026-11-08 for the **unified client/server model** the maintainer accepted that day
(see *Unified model* and *Maintainer decisions of 2026-11-08* below): the three competing pull
requests become options of one product, delivered as stacked layers. **Layer 1**, the first of
them, carries the shared decisions recorded here; every remote kind stays closed
(`remote_kind_unavailable`) until its own layer opens it. **Layer 2** adds shared authorization —
one gate, authorization generations, consent-envelope types and the repository egress hold —
recorded in [ADR-052](ADR-052-shared-authorization-generations-gate-and-consent-envelopes.md) and
in decision 8 below; it keeps every remote kind closed. **Layer 3** adds the server profile, the
consent binding and the helper's registration API (ADR-052 decisions 9 to 12), still with every
kind closed. **Layer 4** opens the `ssh` kind: the unified background helper, the relay and direct
connection styles, SSH discovery and the host key OpenSSH verified as the endpoint identity
(*Built in layer 4* below; ADR-052 decisions 13 to 19); `https` and `local_port` stay closed until
layer 5. **Layer 5** opens them over REST v1, the public network contract recorded in
[ADR-053](ADR-053-rest-v1-public-contract.md), with the gateway and native server edges, API keys
and the compatibility window (*Built in layer 5* below; ADR-052 decisions 20 to 23). **Layer 6**
builds level L2's server copy and releases it, recorded in
[ADR-054](ADR-054-level-l2-the-server-copy.md) (*Built in layer 6* below). Design
gates: protocol (control
envelopes 2.10.0 and the workspace frames), privacy/egress (the FinishUP server hop), storage
layout (target roots and the selection file), release/packaging (client and server-edge
processes, version lockstep) and the `OPEN_QUESTIONS` flip. Maintainer acknowledgement: on
2026-11-05 the maintainer explicitly requested this scoped work — separate the FinishUP client from
the server inside this repository; let a client use the local server, several local servers
including ones reached on localhost ports, a server on another machine over SSH and web-hosted
servers over HTTPS with an address and an API key. On 2026-11-08 the maintainer accepted the
unified design and asked for its delivery as stacked pull requests. Under the intake rule in
`AGENTS.md`, those explicit requests are the design-gate acknowledgement for this scope; they grant
no runtime, credential, disclosure or destructive-action authority.
**Implemented by (layer 1, the shared foundation):** `tests/unit/architecture/` (boundary map,
crossing ledger and the AST boundary test), `src/finishup/cli/command_scope.py`, the
`src/finishup/client/` package (targets, credentials, `target_runtime`, `workspace_claim`,
`workspace_agent`, `workspace_ref`, `remote_binding`, `server_folders`, `everyday_policy`,
`observation_outbox`, `observation_attestation`, `attribution`), `src/finishup/cli/server.py`,
`active_root()` and the `selection` binding in `src/finishup/config/paths.py`,
`src/finishup/ports/workspace_agent.py`, `src/finishup/adapters/workspace_root.py`,
`src/finishup/service/workspace_hub.py`, `src/finishup/service/workspace_routing.py`,
`src/finishup/application/observation_workspace.py`, the claim path of
`src/finishup/service/control_protocol.py` and `src/finishup/service/daemon.py`, the
control-envelope 2.10.0 schemas and fixtures, and the closed tokens in
`src/finishup/protocol/errors.py` and `src/finishup/protocol/recovery.py`. Later layers add the
modules their own amendments of this ADR name; those of layers 2 to 4 are listed in ADR-052,
layer 5's in ADR-053, and layer 6's in ADR-054.
**Amends:** ADR-001, ADR-008, ADR-009, ADR-018, ADR-026, ADR-028 and ADR-031; each carries a dated
amendment note pointing here, limited to what layer 1 does. **Relates to:** ADR-002 (idempotency
scope), ADR-010 (Cursor roots), ADR-030 (typed recovery directives), ADR-048 (frozen `yoetz`
identifier namespace), issue #903, closed pull request #946 and pull requests #1311, #1312 and
#1313 (the three approaches this model unifies).

## Context

FinishUP runs one persistent per-user service that owns the vault, the ledger, the privacy
authority and all outbound access (ADR-001, ADR-008). Every client — hooks, the MCP bridge, the CLI
and the terminal interface — reaches it over an owner-only Unix-domain endpoint whose path is
derived from one root (ADR-026). Isolated roots and runtime pins (ADR-026, ADR-028) already let
several services run side by side, but nothing lets the owner choose among them, and nothing
reaches a service on another machine.

Issue #903 asks for a thin local client and a server that owns the ledger, vault, checks,
AI-powered review and receipts: HTTPS with an address and an API key (pluggable so OAuth can
replace the key later) or SSH with server-authorized keys and a verified host key; the same wire
contract for both; credentials never exposed to agents, hooks or MCP; the server enforcing the same
method allowlist; receipts that name the producing service; defined behaviour on disconnect; a
decision for every host; schemas and fixtures.

Pull request #946 (closed unmerged on 2026-11-05) recorded one `remote-mode.json` and refused to
connect with `remote_egress_not_authorized`. Its draft ADR took the number 033, which now belongs
to task facts. It is superseded by this ADR because:

- only the *local service* would forward, so a client machine still needed a full vault and
  ledger just to proxy, and two vaults raised the question of which one is locked;
- it was not a client/server split, and it never answered how the network hop is authorized;
- it held one remote record, with no named targets and no several local servers;
- it never reached end to end, so it left the service's reads of the agent's working tree
  unsolved.

This ADR keeps from #946 the endpoint normalization, the refusal of plain HTTP, the same operation
contracts on every transport, a server-enforced method allowlist, receipts that name the producer,
and a decision per host.

The hardest coupling is not the transport. The service reads the agent's working tree directly:
repository identity at handshake, the task change base, the ADR-031 check-time change and its
requested-output probes, task-input snapshots, declared-test pinning, the reviewer's `read_file`,
observation verification and approved checks. Several of these run after the client call has
returned (the detached semantic check, the reviewer loop, the observation sweeper). A server on
another machine cannot read that tree, and a server-side directory that happens to have the same
path is a different tree.

The maintainer's request on 2026-11-05 fixes the outcome: a remote target must work end to end,
including check-time change capture, reviewer file reads, task inputs, approved checks and
observation, with no coverage gap standing in for any of them. Gaps are allowed only as honest,
typed outcomes when the client side cannot be reached.

Three pull requests then built that request three ways, on one shared foundation: #1313 (A, an
edge relay: a local connector per target and a gateway per HTTPS server), #1312 (B, direct dial:
each client process dials SSH or HTTPS itself) and #1311 (C, a server-native REST API with a
long-polling client agent). Their shared decisions were identical; only the topology differed. On
2026-11-08 the maintainer decided that the three are not exclusive: each becomes an option of one
product, chosen by the server's type and the user, and the work is delivered as one unification in
stacked layers (*Maintainer decisions of 2026-11-08*, below). This ADR records the shared
decisions, the vocabulary of the unified model, and what layer 1 builds; each later layer amends it
with the contract it adds. The handshake and server profile, the consent envelope and the server
copy of the code (level L2) are recorded in their own ADR when their layers land.

## Unified model

Three independent axes describe how a client works with a server. The words are fixed here so
every later layer, document and surface uses the same ones.

| Axis | Values | Chosen by |
|---|---|---|
| **Level** — where the work happens | **L0 local**: everything on this computer (the default, unchanged). **L1 code-here**: the server keeps tasks, ledger and review; this computer's workspace agent answers the server's eighteen bounded workspace operations (decision 5). **L2 server-copy**: the server also keeps a synced copy of the repository, which this computer's helper sends it, and reads evidence from it itself; outside reads and approved checks are still answered on this computer (ADR-054). | The user, per server, with a per-repository override, within what the server offers. |
| **Connection style** — how this computer reaches the server | **unix**: the owner-only Unix endpoint of a local or named-local root (today's code path). **relay**: client processes reach the server through one local background helper per server, which holds the key and a warm upstream. **direct**: each client process dials the server itself. | The client, from what the server offers; relay is the default for SSH and HTTPS, direct an advanced option. |
| **Server edge** — how the server is reached | **ssh**: `sshd` forwards a stream-local channel into the owner-only control socket (no API key). **gateway**: a separate same-user process with no vault re-enters the service through its control socket. **native**: a listener inside the service process. | The server's owner. |

One rule holds on every axis: **the server offers, the client decides.** A server can only offer
levels and styles and state its requirements; the client picks within the user's recorded consent
and this computer's privacy policy (zero-network, and the repository egress hold of layer 2). A
server can never make a client send more on its own, and the client may always step down to more
local work. An incompatible level is refused explicitly, never switched silently to another service
or ledger.

Further fixed points of the model:

- **One network protocol.** The public network contract is C's resource-shaped REST API (`/v1`),
  served by either HTTP edge (gateway or native). The control-frame binding over HTTPS that A and B
  built ("HTTPS binding v1") is retired; it was never released. SSH keeps raw control frames over
  the forwarded owner-only socket, which is owner-equivalent and not a public contract.
- **One background helper per remote server** for every connection style: it relays (relay
  style), runs the background workspace agent of each claimed worktree, drains observations,
  caches and re-checks the server's profile, and syncs the code at L2. It replaces A's connector,
  B's MCP-bridge background agent and C's pull agent.
- **Supported combinations.** `local` and named-local servers: unix edge and style, level L0.
  `local_port` and `https` (self-hosted): gateway or native edge, relay (default) or direct,
  levels L1 and L2. `ssh`: ssh edge, relay (default, through an SSH forward) or direct (`ssh -W`),
  levels L1 and L2. An official HTTPS service (implemented in another repository): REST, relay or
  direct, levels as it advertises.

## Delivery in layers

The unification lands as stacked pull requests; each exposes only complete capabilities. "Layer"
names a step of that delivery; "level" (L0, L1, L2) names where work happens, above.

1. **Foundation** (this layer): the shared decisions below, on current `main`.
2. **Shared authorization**: authorization generations, the consent-envelope types, the repository
   egress hold (round 5) before any claim, dial or sync, and the recovery contracts.
3. **Profile and registration**: the server profile, consent bound to every request through a
   profile revision, and the helper's workspace registration API.
4. **Helper and SSH**: the background helper, the relay and direct styles, and `server add ssh://…`
   with its handshake.
5. **REST**: one REST client, the gateway and native edges behind one backend interface, API key
   scopes (decision 9), discovery and the official origin preset, the server conformance kit and
   the compatibility window (decision 10).
6. **L2**: the sanitized code export, encrypted storage on the server, immutable snapshots,
   retention and forget, and per-evidence provenance.
7. **Lifecycle validation** across hosts (Codex, Claude Code, Cursor), surfaces and operating
   systems.

### Built in layer 1, and not yet built

**Built and in use:** the cut line (decision 1), target roots and the selection (decision 2), and
named local servers (`finishup server add NAME --local`), which work end to end like the everyday
server. With no remote target selected — and in layer 1 none can be — every surface behaves byte
for byte as it did before server targets existed.

**Built, exercised in process, dormant on the network:** control envelopes 2.10.0 with the
workspace claim, agent declaration and workspace frames (decision 4); the workspace agent and its
eighteen operations, `service/workspace_hub.py` and `service/workspace_routing.py` (decision 5);
claim-bound sessions; outside-read modes and the client's folder record (decision 5); the
zero-network selection rules (decision 8); hook content and client attestation on a remote target
(decision 12); and the client-attested receipt lines (decision 6). Their tests drive them in
process; no shipped client sends a claim, because no remote root can be selected. One part of
decision 6 is live for every task: a receipt whose session-opening record the service cannot read
is still built, with the provenance-unknown section and its `workspace_provenance` member, since
the service cannot then tell whether the task was claim-bound.

**Closed:** the remote kinds `ssh`, `https` and `local_port` (decision 3). `server add` refuses
them, `server use` refuses a remote record, and `server login` refuses, each with
`remote_kind_unavailable`; a connection or service start for a remote root is refused with
`target_root_is_remote` and sends nothing, and setup refuses such a root at its entry.

**Not yet built:** every remote kind and its runtime; the background helper and both remote
connection styles (layer 4); the server profile, handshake and per-request consent binding
(layer 3); authorization generations and the repository egress hold (layer 2, below); REST, both
HTTP server edges, API key scopes, discovery, the official origin preset and the compatibility
window (layer 5); the server copy and level L2 (layer 6).

### Built in layer 2, and not yet built

**Built, in the connection path of every remote root:** one authorization gate in one order
(zero-network, the disclosure, an open kind, then the repository hold), run before any claim,
dial, spawn or sync, and its record-only form for hooks (ADR-052 decision 1). In layers 2 and 3
it opens no kind, so every remote root is still refused as `target_root_is_remote` exactly as in
layer 1 (layer 4 opens `ssh`).

**Built, exercised in process, dormant on the network:** authorization generations and the
watch every claim-bound connection keeps (`server_authorization_changed`), the credential
generation, consent-envelope types and their partial order (ADR-052), and the repository egress
hold of decision 8 with its fence (decision 5), its phases (decision 6) and its waiting rows
(decision 12). Their tests open a remote kind in process; an architecture test keeps the
release's own set of open kinds empty.

**Dormant until a server elsewhere is recorded** (the owner's answer O3): the session-start read
of a repository's policy and the owner-only record of repositories it keeps. With no remote
target on this computer, every surface behaves as in layer 1.

**Hidden:** `finishup server repositories` (its `add` refuses `remote_kind_unavailable` before the
console; `keep`, `list` and `remove` work).

**Not yet built:** the follow-ups ADR-052 lists for layers 3 to 7.

### Built in layer 3, and not yet built

**Built, live on the server side:** the server profile (`server-profile` 1.0.0) and the
authenticated revision a service issues at start, answered by the structural `server_profile`
operation and the hidden `finishup service profile [--json]`; a service admits a remote client's
claim-bound hello only under its current revision and refuses work on a session bound to an older
one (ADR-052 decision 9 and 10). A local client's hello names no revision and is unchanged.

**Built, exercised in process, dormant on the network:** the consent binding (a `/2` target
record, the consented envelope, the cached profile, the gate's consent step after the kind step,
`server_profile_changed` and `server_level_unavailable` on every surface, the narrowing adjustment
and `server status`'s notice), the open-kind `server add`/`server use` consent flows with SRV-3,
SRV-6, SRV-11, SRV-12 and the add-time outside-read question back from layer 1's closure, the
helper's workspace registration API and the bridge as its first registrant, and the connection and
background agent roles (ADR-052 decisions 10 to 12). No profile source is registered for any kind
and no kind is open, so no consent can be given.

**Not yet built:** the follow-ups ADR-052 decision 8 lists for layers 4 to 7.

### Built in layer 4, and not yet built

**Open:** the `ssh` kind (`client.authorization.OPEN_REMOTE_KINDS == {"ssh"}`; an architecture
test pins exactly that set). The kind flipped in the last code commit of the layer, after every
protection below existed. With no SSH target recorded, every surface behaves as in layer 3: no
helper runs, and a hook imports nothing new (the hook import-diet test covers the helper and SSH
discovery).

**Built, live for an SSH server:**

- `finishup server add NAME ssh://[user@]host[:port] [--remote-root ABS] [--remote-launcher ABS]
  [--outside-reads local|listed]` (decision 3 below), with SSH discovery before the consent: the
  server's own launcher reports its endpoint and its profile over OpenSSH, and the host key
  OpenSSH verified in that very connection is the endpoint identity the consent is bound to
  (decision 7, *SSH add*; ADR-052 decision 17). `server use NAME` fetches the profile again the
  same way and asks for the consent every time.
- The unified background helper, `finishup helper run --target <id>` (hidden, `client_only`), one
  per SSH target, started on demand by the clients that need it and never by `service run`
  (*Topology* below; ADR-052 decisions 13 to 16).
- Two connection styles: **relay** (the default; the helper serves `<target root>/run/control.sock`
  and carries each local connection over one channel of its OpenSSH master's stream-local
  forward) and **direct** (an advanced option; each process opens its own `ssh -W` stream through
  one shared master that verified the consented host key), chosen with `finishup server set NAME --style
  relay|direct` among the styles the server's last profile offers (ADR-052 decision 15).
- The background workspace agent per served registration, the observation drain and the profile
  re-check, all inside the helper and all under its own admission through the shared gate
  (ADR-052 decisions 14, 16 and 17). CLI workflow commands to an SSH server answer their own
  live workspace calls and register the workspace once (a 15-minute lease); the MCP bridge
  registers and renews as in layer 3; hooks never register.
- `server status` (text and `server-target-status` 1.0.0 `target.connection`, amended in place)
  shows the style, the styles offered and the helper's last phase; `server list` and `status` mark
  only HTTPS and port records as not available in this release.
- The five transport outages (`remote_unreachable`, `remote_auth_failed`,
  `remote_identity_changed`, `remote_service_not_running`, `remote_incompatible`) are named on
  every surface like the authorization refusals, each with its own continuation, never a local
  service to start (ADR-052 decision 18).
- Shown in help: `server add`'s `ssh://` address, `--remote-root`, `--remote-launcher` and
  `--outside-reads`; `server set`; `server folders`; `server repositories` (its `add` acts for an
  SSH target); `service profile`.

**Closed:** `https` and `local_port` (decision 3's refusals hold for them unchanged: `server add
https://…` and `--port N` refuse `remote_kind_unavailable` before any prompt, probe or write, the
kind told by the argument's prefix alone; `server use` and `server login` refuse such a record),
and `server login` for every kind. `server logout` refuses an SSH target
(`credential_not_applicable`: OpenSSH authenticates, no key is stored).

**Not yet built:** HTTPS and port servers, `server login`, the REST client, both HTTP server
edges, discovery with the official origin preset and API-key direct disclosure (layer 5); the
server copy, code sync in the helper and level L2 (layer 6). Layer 7 ran the compatibility matrix,
an upgrade over running helpers and bridges, the WAN timing gate and the Linux host rows
([acceptance matrix](../runbooks/acceptance-matrix.md)); every macOS and WSL 2 run is still
missing (owner: the maintainer). The terminal interface's `/server` still adds only
a server on this computer (an SSH server is added with `finishup server add NAME ssh://…` in a
terminal, because OpenSSH's host-key question needs the raw terminal), its `use` of an SSH target
never lets OpenSSH ask, and it does not register its workspace with the helper (its own
connection answers its live calls); those are follow-ups. A host certificate
(`@cert-authority`) is not supported as the endpoint identity and fails closed. Real OpenSSH runs
on Linux only (the capability tests and an end-to-end run against a private `sshd`); PR CI does not
run the capability tests.

### Built in layer 5, and not yet built

The contract is [ADR-053](ADR-053-rest-v1-public-contract.md); the authorization it runs under is
ADR-052 decisions 20 to 23.

**Open:** `https` and `local_port` (`client.authorization.OPEN_REMOTE_KINDS == {"ssh", "https",
"local_port"}`; the architecture test pins exactly that set, and that every open kind has a
transport, a profile source and a runtime). The kinds flipped in the last code commit of the
layer, after every protection existed. With no HTTPS or port target recorded, every surface
behaves as in layer 4, and no listener starts unless a server's owner runs one.

**Built, on the server host:** REST v1 behind one backend interface, served by the edge the
server's owner runs with `finishup service rest run` (the gateway, a separate process without the
vault, by default; the native listener inside the service as an opt-in); API keys hashed at rest
with a scope (decision 9) and a principal, managed with `finishup service api-key
create|list|revoke`; unauthenticated discovery; the REST API manifest and its window (decision
10); a bounded audit; and the server conformance kit.

**Built, live for an HTTPS or port server:**

- `finishup server add NAME https://HOST[:PORT][/BASE] [--ca-file F | --tls-pin sha256:HEX]
  [--key-file F] [--outside-reads local|listed]`, and `--port PORT` for this computer's loopback:
  discovery without a key, then the key (typed hidden on the trusted console, or read once from an
  owner-only file) checked with the server, then the consent of decision 8 (decision 3 below;
  ADR-053 decision 12). `server use NAME` fetches the profile again and asks every time.
- `finishup server add official`, the preset of the official origins (decision 5); none exists
  yet, so it refuses `official_endpoint_unavailable`.
- `finishup server login NAME [--key-file F]` and `server logout NAME`, shown in help (decision 7).
- The same helper and styles as SSH: relay (the default; only the helper reads the API key) and
  direct (each dialing process reads it), `server set --style`, `server connect|disconnect|test`
  and `target.connection` in `server status`; one REST client and one frame-to-REST mapping serve
  both styles.

**Not yet built:** the server copy, code sync and level L2 (layer 6); the WAN timing gate, an
upgrade over running gateways, helpers and bridges, and the host × surface × operating system
acceptance rows, including every macOS and WSL 2 run of the REST edge and of HTTPS targets
(layer 7); OAuth credential sources (decision 7 keeps the interface); adding an HTTPS server from
the terminal interface's `/server`, which adds only a server on this computer (the key is typed in
a terminal); fencing a task read by id per key principal (principals namespace claims only, as
groundwork for multi-owner hosting); a PR CI job for the REST conformance kit; and an official
FinishUP service, built in another repository. Real HTTPS ran on Linux only (the conformance kit
against both edges over real TLS, and an end-to-end run of the CLI).

### Built in layer 6, and not yet built

The record is [ADR-054](ADR-054-level-l2-the-server-copy.md). **Level L2 is released**
(`protocol.server_copy.L2_RELEASED` is `True`; `tests/unit/architecture/test_level_l2_released.py`
names every protection it rests on), and level L1 stays the default byte for byte: a server offers
L2 only when its owner's `[server.code_copy]` table (config 1.4.0) enables an offer, and a client
sends a copy only after its owner consents at L2 on the trusted console.

**Built:** the `git-bundle-1` wire format and its one verifier; the sanitized exporter with its
always-excluded names and content scan; the pull sync, two workspace operations in a new `copy`
family (decision 5's catalogue grows from eighteen operations to twenty) answered only by the
target's helper after the gate runs again; the server's encrypted copy store with its quotas,
forget and expiry (`days:N` and `task_close`); the claim-bound `code_copy` method; consent at L2
with a retention; the owner's per-repository choices; reads served from a pinned snapshot of the
copy, stale reads while the client is offline, and approved checks and outside reads still
answered by the client's agent; the subject-state commitment and `code_snapshot_mismatch`;
per-evidence provenance in every receipt rendering, with the count of fenced reads (O7); the
erasure of the excerpts derived from a forgotten copy, with a "content forgotten" marker; and
`server code forget --all`, `server code allow list|remove` and `server remove` offering to forget
first. Both parts ran over real networks on Linux (gateway and native REST edges over real TLS,
and a private `sshd`; ADR-054 honest limit 14 names what ran and what is covered in process only).

**Not yet built:** the terminal interface's L2 flows (CLI only), any macOS or WSL 2 run, and a
Codex, Claude Code or Cursor session against a server keeping a copy (ADR-054, *Not built*).
Layer 7's lifecycle validation ran on Linux ([acceptance matrix](../runbooks/acceptance-matrix.md)).

## Decisions

### 1. The cut line is an enforced contract, not a package move

- Every module under `src/finishup/` is labelled CLIENT, SERVER, SHARED, WORKSPACE or GATEWAY in
  one boundary map. GATEWAY is reserved for the gateway server edge, a same-user control client of
  the daemon on the server host (`finishup.gateway`); no module carries it in layer 1, and the
  REST layer adds the first. CLIENT covers `cli`, `mcp`,
  `tui`, `service.client`, `service.confidential_client`, the host integration adapters (except the
  observation store the service also opens), the client-side application modules and the new
  `finishup.client` package. SHARED covers `protocol`, `ports`, `domain`, `config`,
  `observability`, `resources`, `version`, the control-protocol framing and the Unix-socket
  adapter. Everything else is SERVER.
- WORKSPACE is the layer of workspace readers, which run wherever the workspace is: in the local
  service for a local root and in the client's workspace agent (decision 5) for a remote one. It
  holds the Git capture, task-input, approved-check, sandbox, inspection, home-project and
  input-summary adapters, the Git subject-state, `rev-parse` and version helpers, the shared
  `adapters/workspace_root.py` rule and the repository check-policy parser
  (`application.observation_check_policy`). CLIENT and SERVER modules may import it; a WORKSPACE
  module may import only WORKSPACE and SHARED modules, so a workspace reader never reaches storage,
  the vault, providers, the service or a client surface, and no ledger entry may excuse one.
  SHARED and GATEWAY modules may not import it.
- An AST test walks every module, including imports inside functions, and fails on any crossing
  not recorded in a ledger. The ledger is seeded with today's crossings, measured by the test
  itself, and may only shrink: a ledger entry that no longer occurs also fails. Each entry carries
  a closed disposition: `server_host_only`, `shared_pure`, `to_rpc` or `client_outbox`. The last is
  the only one a `finishup.client` module may carry, and it names one module: the client's drain
  opens its own root's observation outbox to deliver what that root's hooks captured to a remote
  server, which never opens that root. The import crosses only because the outbox and the
  service's observation store still share `adapters.integrations.observation_local`; it closes
  when the outbox moves out of that module.
- A command-scope registry labels every CLI and terminal-interface command `any`, `server_host`
  or `client_only`. One guard, `require_server_host()`, refuses a `server_host` command while a
  remote target is active, with `requires_server_host`. It fails closed when the active root
  resolves but its `target.json` cannot be read (unsafe mode, or a record it cannot parse): the
  command is refused with the record's own reason (`target_root_unsafe`,
  `target_record_invalid`), because such a root may be a remote target's. A test walks the command
  tree and the interface's command registry and fails on an unlabelled command.
- New client-side code lives in `finishup.client`. Hooks may load target selection, but never
  `httpx` or a client transport module, at import time; the hook import-diet packaging test locks
  that.
- No existing file moves. Moving `cli/`, `mcp/` and `tui/` would rewrite the console-script target
  the Codex RECORD proof depends on, the entry fast paths, the tests that patch connection
  factories by name and the resource mirrors, and change no behaviour. A rename-only change may
  follow later.

### 2. A target is an isolated root, selected by an owner-only file of lowest precedence

- **Roots.** Each target is one root at `<ambient state dir>/servers/t_<8 hex>/` holding
  `target.json` (tag `yoetz.server-target/1`, ADR-048 namespace). The short id keeps every socket
  path beneath the root inside the AF_UNIX limit even under `~/Library/Application Support/`.
  Creating a target refuses a root whose longest socket would not fit (`target_root_too_long`),
  against the platform's usable `sun_path` bytes (107 on Linux, 103 on Darwin), the one bound
  `instance_root_too_long` also uses: a `local` root against the service's
  `run/secret-ingress.sock`, a remote root against the longest socket a client binds there,
  OpenSSH's ControlMaster `run/m` under its 17-byte temporary suffix. A
  `local` target's root is a persistent ADR-028 instance root with its own vault, ledger, config,
  endpoints and on-demand service. A remote target's root holds only client state: startup gates,
  hook memos, the bridge↔hook records, the observation outbox and spool, and, from layer 4, the
  background helper's own state.
- **Selection.** `<ambient config dir>/server-selection.json` (tag `yoetz.server-selection/1`)
  holds one `target_id`. Absent, the ambient service is used exactly as today.
- **Precedence.** A new `active_root()` resolves `FINISHUP_ISOLATED_ROOT` (or its legacy alias),
  then the ADR-028 runtime pin, then the selection file, else ambient. `isolated_root()` keeps
  meaning "explicitly isolated" (variable or pin). Every root that follows the target — state,
  runtime, config, log, cache, bundle — derives from `active_root()`; registrations and launch
  lines stay on `isolated_root()`, and so does the bookkeeping that guards them: the
  host-configuration lock and its project-membership record live in
  `installation_state_dir()` (the explicit root's state, else the everyday one), never in a
  selected target's. An AST test locks the classification of every call site, so a
  selected root is never stamped into a host registration and connecting a host while a target is
  selected does not freeze it onto that target. `isolation_binding()` gains the value
  `selection`, carried by isolation report 1.1.0.
- **Fail closed.** A selection that names a missing, malformed or unsafe root fails with
  `isolation_root_invalid` and never falls back to the ambient service. So does a process's
  remembered selection once its target was removed: every answer still needs the root's
  `target.json`, so an MCP bridge started on a target removed since never reads its missing
  folder as a local root, never starts a service there and never recreates the folder; it
  refuses until its session restarts. `server use` refuses while
  the variable or a pin is in force (`selection_overridden`). `server status` always names the
  source that decided the root.
- **Names.** A target name matches `[a-z0-9][a-z0-9-]{0,15}`; `local` is reserved. A name appears
  in `target.json` and in the owner-facing output of this computer's own server commands: the
  `finishup server` commands (`add`, `use`, `remove`, `list`, `status`, `test`, `connect`,
  `disconnect`, and the hidden `folders` group) and the terminal interface's `/server`. Structural
  errors (closed reason tokens and their fixed refusal text), logs and receipts name a target by
  its id only, never by a name, host, address or path.
- **No new variable or argv token.** The entry fast paths, the Claude Code, Cursor and Codex
  registration classifiers, the Cursor live-process classifier and the configuration variable
  allowlist are untouched.
- **A spawned service serves its spawner's root.** A client that starts its service on demand
  forwards the root it resolved: a resolved root in the isolation variable, as before, and the
  everyday installation as one hidden internal `service run --ambient-root` flag, which makes the
  service read no selection (`config.paths.ignore_server_selection`, applied while options are
  parsed, before the server-host guard). A bridge that resolved the everyday installation and
  later restarts its service therefore never starts a target that a newer selection names. The
  flag names no target and appears in no registration, launch line or classifier.
- **Propagation.** Claude Code hooks and MCP (no environment in the registration) learn the target
  from the selection file. Cursor hooks and MCP, and Codex external and cache MCP, use their
  stamped root when they were connected under explicit isolation, and the selection file
  otherwise. Bare-`PATH` Codex plugin hooks, agent-shell CLI calls and the startup-gate probe
  inherit the environment and otherwise read the selection file. The MCP bridge reads the
  selection once per process and never switches mid-session; hooks follow a new selection at
  once, so `server use` tells the owner to restart open sessions.

### 3. Four target kinds, a closed set; only `local` opens in layer 1

| Kind | Address | Notes | Layer 1 |
|---|---|---|---|
| `local` | none; a named root on this machine | "Several local servers": each named root runs its own service, started on demand. | Works end to end. |
| `local_port` | `https://127.0.0.1:<port>` or `https://[::1]:<port>` | The "localhost ports" kind. Same as `https`, but the origin must be loopback. | Closed until layer 5. |
| `ssh` | `ssh://[user@]host[:port]`, optional `--remote-root` (the server's isolated root) and `--remote-launcher` (absolute path of the server's `finishup`) | Owner-equivalent: the SSH login is the service owner. | Closed until layer 4. |
| `https` | `https://host[:port][/base]` with `--ca-file` or `--tls-pin sha256:…` | No userinfo, query or fragment. Plain `http` is refused. | Closed until layer 5. |

Every kind except `local` is a *remote kind* for consent, the zero-network refusal and the
workspace agent, including `local_port`: a loopback port can forward anywhere. `server add NAME
https://127.0.0.1:<port>` and `https://[::1]:<port>` name `local_port`, as does `--port <port>`
(which names `127.0.0.1`); any other HTTPS address, `localhost` included, is `https`. The record
vocabulary (`target.json` and its fields per kind) keeps all four kinds, so a later layer opens a
kind without a record migration.

**The remote kinds are closed in layer 1** (closed reason `remote_kind_unavailable`, continuation
`server_on_this_computer_required`):

- `finishup server add NAME ssh://…`, `https://…` or `--port N` is refused before any
  trusted-console prompt, zero-network check, probe, dial, key prompt or write; the address is
  parsed only as far as telling its kind needs, and nothing touches the network. The text says
  that this release connects only to FinishUP servers on this computer (the everyday server and
  named local servers, `finishup server add NAME --local`), that SSH, HTTPS and port servers arrive
  in a later release, and that nothing was added. It is one line on stderr, the closed token
  first (`remote_kind_unavailable: …`), with exit 2 and nothing on stdout; `server add` has no
  JSON mode, so a script reads the token before the first colon.
- `finishup server use NAME` on a record of a remote kind (one another build wrote, or a hand
  edit) is refused the same way, and the selection is unchanged.
- A connection or an on-demand start for a remote root keeps the foundation's refusal: a
  retryable `service_unavailable` with phase `target_root_is_remote`; nothing is sent and no
  service starts (decision 6, *No silent fallback*). No remote `TargetRuntime` is registered, so
  `target_runtime` answers a remote kind with `remote_unreachable`, phase `runtime_unavailable`.
  Every host's SessionStart hook and the terminal menu keep that phase (or the zero-network and
  stale-disclosure phases of decision 8) and name it with its directive, never a service still to
  start. The way back follows what named the root: for the saved selection, `finishup server use
  local` and then a new agent session (an open session's MCP bridge keeps the root it started
  with); a stale disclosure cannot be confirmed while the remote kinds are closed, so it points
  there too and says a later release can authorize that server again. When an isolation variable
  or a pinned launcher names the root, `server use` answers `selection_overridden`, so the
  directive is to unset it or use an unpinned launcher (`remote_root_override_clear`). The menu
  refuses an action whose command is `server_host` (provider setup, the harness skill, the setup
  posture, vault unlock and initialization) with the same phase and directive before it asks or
  writes anything, as the command itself is refused.
- Setup refuses such a root at its entry with the same phase and directive (exit 20, stderr
  only): `setup run` in every form, bare `finishup` and the menu's setup wizard, and the terminal
  interface's first run, whether a selection or an isolation variable names the root. It looks
  for no agent, asks nothing and registers or writes nothing (the terminal interface does not even
  read this computer's policy first, since that read records its answer); the connection guard
  stays as well. `setup status`, which writes nothing, and `setup disconnect`, the way out, are not
  refused.
- `server login` is refused with `remote_kind_unavailable`; `server logout` stays the offline way
  out (decision 7). `server login`, `server logout` and the `server folders` group are hidden from
  `--help` and still parse.
- The terminal interface's `/server` add flow offers only a server on this computer (a named local
  server); a remote record shown or chosen there gets the same refusal. `server list` and `server
  status` show an existing remote record as not available in this release, and no setup or menu
  next step suggests adding a remote server.

**Layer 4 opens `ssh`** (`OPEN_REMOTE_KINDS == {"ssh"}`); everything above still holds for `https`
and `local_port`. `server add` tells the kind from the argument's prefix alone, before any prompt:
`ssh://` is `ssh`; `--port N`, `https://127.0.0.1:` and `https://[::1]:` are `local_port`; any
other `https://` is `https`; anything else is refused as a closed kind. For `ssh`, in order and
before anything is written: the selection in force, the name, the address and its options (remote
paths absolute, SRV-11; `--ca-file` and `--tls-pin` refused as `target_tls_invalid`), the name not
taken, this computer's zero-network state (SRV-3), SSH discovery (decision 7, *SSH add*), then the
consent of decision 8 (disclosure 3, level L1, review egress, the outside-read question and the
typed name). The record keeps the endpoint and the absolute launcher the server reported; an
endpoint in the server's login-session runtime folder on an account without linger prints a
warning naming linger or `--remote-root`. The text of `remote_kind_unavailable` now names both
open families: "this release connects to FinishUP servers on this computer (the everyday server
and named local servers, 'finishup server add NAME --local') and over SSH ('finishup server add
NAME ssh://[user@]host[:port]'). HTTPS and port servers arrive in a later release". `server use`
of an SSH target fetches the profile again and asks for the consent on the trusted console; after
`add` and after `use` the line naming a held or kept repository returns (FR-5). `server set NAME
--style relay|direct` and the SSH runtime (`client.helper_runtime.SshTargetRuntime`, registered
for `ssh`) arrive with it: `connect` admits the target through the shared gate and connects as any
client would (the relay starts the helper; the direct style dials and starts the helper for its
background agents), `disconnect` stops the helper through its stop epoch (no pid is signalled; a
pending start is fenced; it succeeds once the helper's lock is seen free) and asks the OpenSSH
master to exit (`ssh -O exit`), and `test` probes over the real transport.

**Layer 5 opens `https` and `local_port`** (`OPEN_REMOTE_KINDS == {"ssh", "https",
"local_port"}`; ADR-053 decision 12). The kind is still told by the argument's prefix alone, and
`remote_kind_unavailable` now refuses only an address that names none of the open kinds
(`http://`, another scheme), with the text "this release connects to FinishUP servers on this
computer (the everyday server and named local servers, 'finishup server add NAME --local'), over
SSH ('finishup server add NAME ssh://[user@]host[:port]') and over HTTPS ('finishup server add
NAME https://host[:port]', or --port PORT on this computer); that address names none of them". For
`https` and `local_port`, in order and before anything is written: the selection in force, the
name, the address and its options (`--remote-root` and `--remote-launcher` are `usage`;
`--ca-file` and `--tls-pin` together are `target_tls_invalid`; a `--ca-file` that is not a file is
`target_path_invalid`), the name not taken, this computer's zero-network state (SRV-3), discovery
without a key, the key and its check with the server, then the consent of decision 8. `server
use` of such a target fetches the profile again with the stored key and asks for the consent on
the trusted console. The helper runtime registered for `ssh` serves both kinds (`connect`
through the helper or the direct REST dial, `disconnect` stops the helper, `test` probes over the
real transport). `server add official` is the official preset (decision 5).

`finishup server add|list|use|status [--json]|test|remove|login|logout|connect|disconnect` manages
targets; each mutating command has its reverse (see *Reverse states*). `connect`, `disconnect` and
`test` dispatch through one small interface, `finishup.client.target_runtime.TargetRuntime`
(`ensure_ready(root)`, `stop(root)`, `probe(root) -> ProbeResult`). Layer 1 ships the `local`
implementation; the layers that open a remote kind register its runtime. Two server-host
commands are added: `finishup service start` (idempotent on-demand start plus status) and
`finishup service endpoint --json` (endpoint, absolute launcher, release, manifest digest, whether
the runtime directory is tied to the login session, and linger state).

### 4. Wire contract: control envelopes 2.10.0

The four control envelopes move to **2.10.0** together through the schema generator and the
resource ripple. Layer 1 ships the whole contract below and its daemon side; its tests open
claim-bound connections in process. No shipped client sends a claim in layer 1: a local or
named-local root binds by locator, as before, and no remote root can be selected.

- **Claim or locator, never both.** The hello gains an optional `workspace_claim`
  `{schema_version: "1.0.0", identity_kind: "git_common_root" | "directory", digest:
  "sha256:<64 hex>", worktree: "sha256:<64 hex>"}`. A hello carries either it or
  `workspace_locator`; both is `workspace_binding_conflict`. The client computes the digest as
  `HMAC-SHA256(claim_salt, "yoetz/workspace-claim/v1\0" ‖ kind ‖ 0x00 ‖ canonical root)`, where
  the canonical root comes from the one shared rule in `adapters/workspace_root.py` and
  `claim_salt` is 32 random bytes kept per target in `target.json`. Every linked worktree of one
  repository therefore claims the same digest. The `worktree` digest tells them apart:
  `HMAC-SHA256(claim_salt, "yoetz/workspace-worktree/v1\0" ‖ worktree top level)`, over the one
  directory the connection's agent serves (its locator). No path crosses the wire for a remote
  target. (Amended 2026-11-06, before 2.10.0 shipped: the first cut had no `worktree`, so linked
  worktrees shared one handle and one worktree's agent could answer another's task.)
- **The server derives, it does not trust.** The daemon commits the claim with the installation MAC
  under the new domain `yoetz/repository-claim/v1` over `kind ‖ digest`, producing
  `RepositoryPrivacyContext(identity_kind="client_claim", workspace_locator=None,
  workspace_handle=...)`. The repository fence, the privacy authority and the consent scope work
  on that commitment unchanged, so linked worktrees share a commitment, as they do locally. The server never resolves a filesystem path for a
  claim-bound connection. The composition flag `ServiceComposition.refuse_workspace_locators`
  (off by default) lets a network edge close any hello that names a locator. A claim on a locked
  service binds no handle and no agent. Because a claim-bound connection's handle is fixed by its
  hello, the claim hello re-opens a soft lock (idle, session lock, suspend) exactly as the
  connection's first request would; a hard lock stays locked, and a locator hello never unlocks
  (amended 2026-11-06 after the real-environment runs).
- **Agent declaration.** The hello gains an optional `workspace_agent` `{schema_version: "1.0.0",
  operations: [...], max_reply_bytes: <int>}`: this connection answers workspace calls for its
  claimed workspace.
- **Hello-result.** It gains a required `workspace_binding: "none" | "local_path" |
  "client_claim"` (absent only from the manifest-mismatch answer, which keeps the frozen pre-2.10
  shape) and an optional `workspace_handle`, carried only with `client_claim` (`client:<16 hex>`,
  the first 16 hex of `SHA-256("yoetz/workspace-handle/v1\0" ‖ claim commitment ‖ 0x00 ‖
  worktree digest)`). Worktrees
  share a commitment, not a handle: a task records its own worktree's handle as its
  `workspace_ref`, so every later read of that task, in a live call or in background work after a
  reconnect, reaches only that worktree's agent. Coverage decisions are derived from
  `workspace_binding`, never from the client's word.
- **New frames.** `workspace_call` (server→client, a new `oneOf` branch of the control result:
  `kind`, `protocol_version: "1.0"`, `call_id`, `service_instance_id`, `service_generation`,
  `operation`, `arguments`, `deadline_ms`) and `workspace_reply` (client→server, a new branch of
  the control request: `kind`, `protocol_version: "1.0"`, `call_id`, `outcome: "ok" |
  "unavailable" | "refused" | "failed"`, `result`, `reason`). The daemon sends server→client
  frames only to connections whose hello declared `workspace_agent`.
- **Claim-bound start.** On a claim-bound connection a `start` that names a workspace must name
  the connection's handle; an absolute path or any other value is refused with
  `workspace_ref_not_portable`, and a handle sent on a connection without a claim is
  `workspace_binding_conflict`. Without this rule the reviewer's workspace root would be a server
  directory that happens to share the path. The MCP bridge, the CLI and the SessionStart
  auto-attach rewrite an absolute `workspace_ref` to the handle before sending. A start may also
  name no workspace, in every mode where it may on one computer (there it reads the connection's
  own locator path; `workspace_ref` and `external_ref` are both or neither, so a client cannot add
  the handle alone). The claim names that same workspace, so any session such a start opens — a
  create, a parent-registered child, a child attached by its attach handle — records the
  connection's handle in its opening event only, and its receipts carry the client-attested block;
  the request's identity is unchanged. (Amended 2026-11-06, before release: the first cut refused
  such a start, and the real-environment runs of all three approaches failed on the first MCP
  `start`.) A claim-bound connection with no handle exists only because the server's vault was not
  ready at hello: it sends no start, whatever its `workspace_ref`, and no observation row (never a
  path) and answers the retryable `vault_locked`, so the client replaces the connection and the
  first call after the unlock gets a handle. The server holds the same line: it never serves such
  a connection as an unbound one, answering every call that needs the ready service
  `vault_locked` (retryable unless a hard lock holds), and it ends the connection once a ready
  generation is published, so a background agent, which sends no such call, connects again and
  gets a handle.
- **What stays identical.** Framing (6 MiB frames, 1 MiB ordinary), all 32 methods and their
  bodies, `rpc_id` multiplexing and cancel, the client-kind gate and the client's exact-set check,
  and idempotency by `(installation_id, request_id)`. The YZH1 human-control and YZS1 secret
  channels are never forwarded or exposed beyond the service host.

### 5. The workspace agent and its eighteen operations

The server reaches the agent's working tree only through a client-side **workspace agent** that
answers bounded `workspace_call`s on a connection that declared it. This is level L1 of the
unified model. Layer 1 ships the agent, the hub and the routing and tests them in process; no
network reaches them yet. The outside-read modes and the client's folder record below govern
remote kinds only, so they are dormant in layer 1, where the `server folders` group is hidden from
`--help`.

- **One catalog.** `ports/workspace_agent.py` is the single source of truth for each operation's
  name, argument codec, result codec, argument byte bound and result byte bound; every result
  stays under the 6 MiB frame. Bytes travel as base64 strings inside canonical JSON, and every
  codec round-trips exactly. The eighteen operations:
  - **Git:** `read_task_base`, `capture`, `capture_metadata`, `probe_requested_paths`,
    `count_change_lines`, `classify_undeclared_references`;
  - **reads:** `read_outside_inputs`, `snapshot_outside_inputs`, `read_declared_test`,
    `read_text_beneath`, `list_beneath`, `lstat_candidates`;
  - **observation:** `open_workspace` (returns an opaque remote handle), `load_check_policy`,
    `subject_state_capture`, `list_changed_paths`, `inspect`, `run_approved_check`.
  - **copy** (layer 6, [ADR-054](ADR-054-level-l2-the-server-copy.md) decision 4):
    `code_sync_prepare` and `code_sync_read`, level L2's pull sync, declared only by the target's
    helper; twenty operations in all.
- **Real adapters, existing fences.** The agent runs each operation against the same local
  adapters the service uses today, with all their fences: owner-UID checks, ignore rules, link
  refusal, object verification, size and time bounds, the approved-check sandbox. Two
  confinements are added: an operation's workspace must be the agent's own claimed root, and an
  outside read goes only where this client's owner admitted it (next item) and never past the
  existing exclusions. The server names the claimed workspace by its handle, never by its path: a
  read root or an exclusion may be the handle, and a declared-test location may be
  `client:<16 hex>/<relative>`; the agent maps them to its own root and refuses any other handle
  (`workspace_not_claimed`). No agent and no claim is ever made for the filesystem root (`/`), as
  hooks and MCP roots never bind it: a CLI or bridge started there names no workspace. An outside
  read never enters the claimed workspace through an outside root, nor the client's protected
  directories — its own FinishUP directories and the everyday installation's under both
  application names — whatever the server excludes. Where a local service's own caller narrowed
  an operation, the agent narrows it itself: `inspect` excerpts only the workspace's own changed
  paths (never an ignored, unchanged, `.git` or credential-named file), and `lstat_candidates`
  answers only for a candidate the local outside-input rule would look at (no hidden,
  credential-named or system path, and beneath a path an owner may admit). The agent refuses unknown operations and
  never runs a command that did not come from the repository's owner-approved
  `.finishup/checks.toml` (`check_not_approved`): the policy must approve the exact argv, and the
  owner must have trusted that policy's raw digest in this client's own observation store, checked
  on every call, so a misbehaving server cannot run an untrusted or edited policy. HOME decisions are made by the agent on the
  client, never by the server's own home directory. Every non-`ok` reply carries one closed reason,
  and change capture's own reasons keep their exact `ChangeCaptureUnavailable` tokens.
- **Outside admission is the client's own fact** (amended 2026-11-06 by maintainer decision, after
  the review of the three pull requests found that the agent admitted any root the server named
  by its shape alone; amended again the same day by maintainer decision D2, which made it a
  per-target mode, and by D2b, which gave every remote kind the same choice, asked at `server
  add`). What a server may read outside the claimed worktree is recorded on the client, per
  server target, as approved-check trust is (decision 12), and is the owner's to set. Each remote
  target has an **outside-read mode**, and every remote kind (`local_port`, `ssh`, `https`)
  offers the same two, with the same behaviour:
  - **`local`**: the agent answers the server's outside reads exactly as a local FinishUP service
    would answer them. The server's own admitted-root policy decides which roots it reads; the
    adapters' fences and the agent's own exclusions below still hold, and there is no client
    folder check, so an input beneath a root the server's policy names is never refused on the
    client. A refusal happens only where a local service would refuse too (a root of a shape no
    owner could admit). A read rooted in FinishUP's own directories is not refused but answers
    nothing, as a local service's read, which excludes those directories, answers nothing there.
  - **`listed`**: the server reads outside the worktree only beneath folders the owner listed
    for that target, as described below; anything else is refused.

  Either mode limits only what the server reads. The content chunks the client's hooks capture
  reach every remote server unchanged, a `listed`-mode one too, even where they name or hold
  files outside its listed folders (decision 12, maintainer decision of 2026-11-07).

  **The client's list admits task inputs, in both modes** (maintainer decision, 2026-11-07,
  closing open question 1 below). `finishup server folders add NAME FOLDER`, run on the client at
  the trusted console, also admits FOLDER as a task-input root for that server's claim-bound
  sessions, whatever the server's own input-root policy names. The record is never sent to the
  server. For a claim-bound session the server asks the agent for the task's outside inputs
  whenever the recipe carries task inputs, even when its own policy admits no root
  (`ready_composition._outside_inputs`, and at task start `input_snapshot_scope` with
  `client_record`), and the agent reads an input beneath a folder of its record under that
  folder: in `local` mode beside the server's own admitted roots, which still apply as for a
  local service; in `listed` mode alone, since only the record admits there. The answer of
  `read_outside_inputs` and `snapshot_outside_inputs` says which of the server's values a listed
  folder covers (`listed`, indices only, for a value the outside-input candidate rule would look
  at, never which folder), and the server leaves the decision on such an input to the agent: a
  covered value is never counted as `outside_inputs_not_admitted`, and every other value is
  decided by the server's own policy exactly as before. An input the agent read beneath a root
  the server's policy does not admit is marked `client_listed` by the server, from its own
  policy and never from the agent's word, and is bound to no policy root for egress, because the
  server's policy cannot revoke a folder it never admitted: the owner removes it on the client,
  and that applies from the agent's next read (a review the server already prepared may still
  send what it read). A kept copy (#1118) beneath such a folder is sent only while the agent says
  a listed folder still covers it. The server's other privacy controls still apply on the server:
  whether the recipe carries task inputs at all, which categories and data classes may reach
  AI-powered review and through which channel, ceilings, preview and redaction. The server learns
  of the record only the folder beneath which a file it was let read lies (that file's `root`)
  and whether a path it named lies beneath one. The reviewer's own follow-up reads outside the
  worktree are still offered only beneath the server's own roots; a client-admitted input reaches
  review through the check-time read. Every local or unclaimed session is unchanged.

  There is no default per kind. `finishup server add` asks the owner which mode a new remote
  target gets, on the trusted foreground console as part of its typed confirmation: after the
  disclosure it asks what the server may read outside the owner's projects, with one plain line
  for each mode, and requires an explicit answer (`local` or `listed`; Enter alone or another
  word asks again, a few times, and then, or at end of input or an interrupt, nothing is added,
  `outside_reads_not_chosen`); the typed target name then authorizes both. `--outside-reads
  local|listed` answers the question up front, and still needs the trusted console and the typed
  name, as every remote `add` does; the console shows the mode it authorizes. When the owner
  chooses `local`, answered or by the flag, the console shows, before the typed name, the same
  notice `server folders mode NAME local` shows of what that mode lets the server read, a
  rule-breaking server included; it adds no prompt. The answer is
  recorded in the client record. Where it cannot be written, the target is still added, in
  `listed` mode, and `add` says so and how to choose again. The one exception is an official
  FinishUP endpoint: an `https` target whose base URL matches a canonical origin in the reviewed,
  release-pinned constant `client.server_folders.OFFICIAL_ENDPOINT_ORIGINS` (scheme, host, port,
  443 by default, and path prefix) is not asked and is `local` (source `official_endpoint`), so
  the official trusted service reads as much as a local one. Layer 5 replaced layer 1's exact
  hostname list, `OFFICIAL_ENDPOINT_HOSTS`, with these origins (ADR-053 decision 9). The match
  applies only while the target trusts the system certificate store: a target added with
  `--ca-file` or `--tls-pin` never counts as official, and is asked; the server's own claim to be
  official never counts. Its `local` is not recorded, so it follows the reviewed list; an explicit
  `--outside-reads` is recorded as the owner's own. The constant is empty, because no official
  hosted endpoint exists yet; the maintainer fills it in when one does. `finishup server add
  official` is the preset that fills in the first listed origin's URL; with the list empty it
  refuses `official_endpoint_unavailable` before anything is asked. A record with no mode (no
  release wrote one; a record whose mode could not be written) reads as `listed`, the fail-closed
  value (source `not_chosen`), and `server status`, `server folders list` and the terminal's
  `/server` status say how to choose. Once chosen, nothing asks again: hooks, agent tools (MCP),
  the CLI and the terminal interface read the record, and the agent reads it at every call.

  `finishup server folders mode NAME local|listed` changes the mode later. `local` widens what
  the server reads, so it needs the trusted foreground console and the owner typing the target
  name after a notice of what that mode lets the server read, a rule-breaking server included;
  `listed` narrows it and is the way back, needing neither. A recorded `local` is the owner's own
  choice, kept whatever the reviewed list of official endpoints later says, so recording it
  always takes the console and the typed name, an official endpoint's included; where no trusted
  console can ask (an agent's shell), `mode NAME local` on an official endpoint records nothing,
  says that it is already `local` as an official server, and leaves it following the list.
  `server add` prints the mode it recorded and the one command that changes it, and `server
  folders list`, `server status` and the terminal's `/server` status show the mode and where it
  came from (`owner`, `official_endpoint`, `not_chosen`, or `unreadable`); `server status --json`
  carries the same, with the listed folders, as `target.outside_reads` of `server-target-status`
  1.0.0 (null for a target that is not remote). The terminal interface's `/server` add flow
  offers only a server on this computer (decision 3), so it asks no outside-read question and
  offers no official service: a server elsewhere, an official one included, is added with
  `finishup server add` in a terminal.

  The folders are the owner's: `finishup server folders add NAME FOLDER` needs the
  trusted foreground console and the owner typing the target name, after a notice that the folder
  also admits a task's files in `local` mode, even where the server's own policy admits no folder;
  it records FOLDER canonicalized
  by the local service's own input-root rule (an existing directory named by its absolute,
  normalized, link-free path of plain parts; never a part starting with a dot, the filesystem
  root, or `/boot`, `/dev`, `/etc`, `/proc`, `/run`, `/sys`, `/var/run`, `/private/etc` or
  `/private/var/run` or beneath them), and never the home directory, a folder that holds it, or
  one in its private trees (`Library`, `AppData`, `snap`); any other folder, `/usr/lib` included,
  may be listed. `server folders remove NAME FOLDER|--all` is
  the way out; like a change of mode, it applies from the workspace agent's next read, and a read
  already in progress may still return files from that folder (a review the server already
  prepared may still send what it read there). Listing or removing a folder keeps the mode; a
  folder listed in `local` mode admits a task's files there too, and is all the server reads
  outside in `listed` mode, and `add`, `list`, `remove` and `status` say so, as does the
  `local`-mode notice shown before the typed name.
  `add` checks the home
  rules before it asks, so the owner never consents to a folder that is then refused. The record
  is owner-only (`<target root>/config/folders.json`, `yoetz.server-folders/1`, with an optional
  `mode`) and never sent to the server. Each agent is bound, when it is built, to the record of
  the target its connection's claim was made for (the target in use then, whose claim salt must
  be the claim's, or a target root its caller names); a later change of the process's selection
  never switches it to another target's record, and an agent built without a record is `listed`
  with no folder rather than guess a target, or take the mode of the target in use, from the
  selection, which may name another server. The agent reads that record off the event loop on
  every outside read, so a change of mode or folders applies from its next read (one already in
  progress finishes under the record it started with). A record that cannot be read fails closed
  to `listed` with no folder, whatever mode it held; `remove NAME --all` replaces it with an
  empty record in `listed` mode, the state it already stood for, so clearing it never widens
  what the server reads. `server status`, `server folders list` and the terminal's `/server`
  status say that the record is damaged or not private, what the server reads meanwhile, and
  that one repair with the target's own name and where to run it (this computer); `list` shows
  that state rather than refusing, and a change (`add`, `remove FOLDER`, `mode`) refuses with
  the same repair and says to run the command again (amended 2026-11-07). In both modes a read root the server names must have the shape an
  owner may admit, and nothing in FinishUP's own directories is ever read: every outside read
  excludes them. In `local` mode that exclusion is all, as for a local service, so a read rooted
  there answers nothing and is not refused. In `listed` mode a reviewer read or listing rooted
  there is `root_not_admitted` even beneath a listed folder, a deliberate stricter-than-local rule
  for reviewer reads alone that changes nothing the server sees, since a refused reviewer read
  reads as absent there (below); a task-input root there is excluded, not refused, once the
  listed-folder rule admits its paths. In `listed` mode what the read
  reaches must also lie inside the claimed worktree or at or beneath a listed folder. For a
  single-root read (`read_text_beneath`, `list_beneath`) that is the root, or the path beneath it
  the read names; anything else that exists is `root_not_admitted`. For a task-input read
  (`read_outside_inputs`, `snapshot_outside_inputs`) it is each path the task names beneath a
  named root, judged one at a time (amended 2026-11-07, refusal-guide review): a path the owner
  did not list is left unread and the rest of the read goes on, and the answer carries, beside
  the files, the indices of the server's own values it left unread (`unlisted`; indices only,
  never a path the server did not send). The values judged are first narrowed to those the local
  read would look for: its window of 16, less the words the spaces of a quoted spaced value cut
  out when that whole value names something beneath a named root (issue #1102), decided before
  any value is left out, so leaving a spaced value unread never lets one of its words be read
  under the task's name. The server freezes how many inputs were left out as the check-time
  change's `outside_inputs_not_listed` count and discloses the closed code
  `outside_reads_not_listed`, whose fixed sentence names both ways out and where to run them
  (the count reaches the diagnostics as its own `semantic_outside_reads_not_listed` record, and,
  since open question 2 closed, the check (check-recorded 1.7.0) and the receipt's gap
  (receipt-document 1.4.0), whose line says how many); so a listed-mode input costs
  only that input, never the whole check-time change, and is never passed over in silence. A
  kept copy (#1118) whose folder the owner no longer lists is not sent, as a copy whose root the
  owner no longer admits is not: the current read that compares it names it `unlisted` too,
  whatever its file is now (review of #1313). The server holds the copy, so neither whether the
  file still exists nor whether a local read would still read it (deleted, hard-linked, opened to
  other accounts or replaced by a link since) decides it: in `listed` mode
  `snapshot_outside_inputs` names `unlisted` every value at or beneath a named root that no
  listed folder admits, looking at nothing on the client, so the answer tells the server no more
  than `listed` does, beside the mode. Such a copy is counted among those kept back, since
  listing its folder again, or `local` mode, sends it. Nor is it offered to the reviewer's
  `read_file` (its `s` root): when a review is prepared, the server asks the agent once, reading
  no bytes, which kept copies its owner no longer lists, and offers only the rest; an agent that
  cannot say gets no `s` root at all, so no copy is offered on the server's word alone (a review
  already prepared may still send what it read).
  Listed mode refuses or skips only what exists (same amendment), kept copies aside (above): a
  path the read reaches that does not exist reads as nothing, as it does locally, and is never
  counted, so a stray path in a task statement costs nothing. Whether a path exists is answered only for one the local
  outside-input candidate rule would look at (no hidden component, not credential-named, in no
  system or protected directory), so the server learns no more than `lstat_candidates` already
  tells it. What exists counts only where a local read would read it (review of #1313): a task
  input left unread (never a kept copy, above) is reported `unlisted` only when the local read's
  own trusted metadata walk
  (`task_input_read.outside_inputs_readable`: its home-private, hidden and credential-named
  refusals, its directory and file trust tests, a single link, an owner's, writable by no other
  account) would read a file for it, and a declared test is `root_not_admitted` only when the
  local `read_declared_test`'s fences and walk would open it (`declared_test_readable`); any
  other reads as nothing in both modes, as locally, because no folder the owner lists and no
  mode would let it be read. Neither looks at content, so a declared test that is not text the
  local read returns (binary, empty, over 1 MiB) is still counted, and an empty task input
  counts though it gives the review nothing: a known over-count, never a hidden omission. Unlike
  existence, that answer tells the server more than `lstat_candidates` does (a path's type,
  permission bits and times): for a path it named that the owner did not list, one bit, whether a
  local read would read it, which also depends on the file's link count and owner, on the owners
  of the directories on the way, on the home directory's private trees and, for a directory, on
  whether it holds at least one file the local read would read among those it lists. Never a
  name, a size or content. A known limit, kept so that a count never sends the owner to a step
  that would read nothing there. A named root beneath which the task names nothing is left unopened, and one that
  holds a listed folder is walked only to the values beneath that folder. Beneath the server's own
  roots the client's record narrows them in `listed` mode, and a folder narrower than the server's
  root admits what lies beneath that folder alone; a listed folder beneath none of the server's
  roots admits its task inputs on its own (the client's list, above). Both ways out are the owner's, on the client: list the folder, or,
  for a server they trust, switch it to `local` mode. Listing covers files outside the worktree
  only: a declared test inside it that Git ignores or cannot answer for is read in `listed` mode
  under no listing, the worktree's own folder included, so the fixed sentence names `local` mode,
  or no longer ignoring the test, as the only ways to have it read. A declared test is read in `local` mode
  exactly as a local service reads the test its own agent declared (#1220): inside the claimed
  worktree or outside it, whether or not Git ignores it or can answer for it, with FinishUP's
  own directories excluded and no other rule (same amendment). In `listed` mode a declared test
  inside the claimed worktree is read under Git's ignore rule (next item), and one outside it
  only beneath a listed folder; an existing one beyond that is `root_not_admitted`, never read on
  the server's word, the reviewer is not offered it, and the server discloses
  `outside_reads_not_listed` for it (frozen into the job's case object as the count
  `declared_tests_not_listed`, so a recovered job builds the same case). One read outside the
  worktree in `listed` mode is an outside read, which excludes the claimed workspace by identity
  and case-folded spelling, so another spelling of the workspace beneath that folder never skips
  Git's ignore rule. Both comparisons use the spelling the local read walks: a first component
  that is a link root owns (macOS `/tmp`, `/var`) counts as its target, so such a spelling never
  falsely refuses.
- **Ignore rules on the agent** (amended 2026-11-06, same review; narrowed 2026-11-07). The
  server's reviewer broker asks the agent whether Git ignores a workspace path before it reads
  it; a server that skipped that question received an ignored file's bytes. The agent now asks
  Git itself before a workspace file read (`read_text_beneath` on the handle), and returns bytes
  only when Git answers that the path is not ignored, the very answer the broker requires
  (`ignored is not False` refuses, locally and remotely), so a local service has the same rule.
  Where Git cannot answer for a path, the read is nothing too: a linked worktree, whose `.git`
  file the change capture refuses as `unsafe_root`; a path inside a submodule, which the
  repository's own Git does not answer for; no repository at all (`not_git`); a home-private
  path. An honest reviewer read costs nothing, since the broker refuses those reads itself. A
  declared test is held to the rule only in `listed` mode: a local service reads a declared test
  whether or not Git ignores it (#1220), so `local` mode does too, and there no declared test is
  skipped that a local service would offer. In `listed` mode a declared test that is
  Git-ignored, or that Git cannot answer for, is refused and disclosed as above. A listing
  (`list_beneath`) returns names only and is not asked about; the broker filters its entries.
- **Honest limit: what a server that breaks the protocol can still obtain.** The agent cannot tell
  an honest server's question from any other. Within the claimed worktree, such a server can
  obtain any file the adapters' fences pass and Git answers is not ignored, whether or not a task
  names it, and the names, never the bytes, of every entry the fences pass in a directory
  listing, ignored ones and those Git cannot answer for included; in `local` mode it can also
  obtain, as a declared test, a file the fences pass that Git ignores or cannot answer for, as a
  local service's declared-test read could. In `listed` mode, beneath a folder the owner listed
  for it, it can obtain any file that is not hidden, not credential-named and in no system or
  protected directory, and list the names in its directories. In `local` mode it can do so
  beneath any root of a shape an owner could admit, anywhere on this machine, within the same
  fences (the home directory's private trees included), as a local service's reads could; that is
  why `local` is the owner's typed choice, at `server add` or later, for a server they trust as
  they trust FinishUP on this computer, and never a default for any kind (an official FinishUP
  endpoint alone is `local` without the question). Anywhere on this machine, it can learn the
  metadata (existence, type, size and times, never content) of a path the local outside-input
  candidate rule would look at (`lstat_candidates`), which the server's outside-input hint needs,
  and in `listed` mode whether such a path exists from whether a read of it is refused or left
  unread; in either mode, whether a path it names lies beneath a folder the owner listed, and
  the folder itself as the root of a file it was let read there. The owner lists only folders
  they would let that server see. A task input or declared
  test that listed mode kept from the server reaches the receipt as `outside_reads_not_listed`;
  a refused reviewer read reads as absent on the server, which in practice names the same
  task-named path the check-time read already disclosed. Nothing on the client tells the owner
  which folder was asked for; such a hint is later work.
- **The hub.** `service/workspace_hub.py` keeps live agent channels keyed by workspace handle; a
  connection that declared the agent registers at handshake and unregisters on close.
  `WorkspaceAgentHub.call(handle, operation, arguments, *, timeout_seconds)` sends a
  `workspace_call` under that session's write lock and awaits the correlated reply. With no channel
  it waits a bounded time for one — 5 seconds inside a live control call, 30 seconds for
  background work such as the detached review and recovered jobs (work a call left running is
  background from the moment the call returns) — then raises the typed
  `WorkspaceAgentUnavailable`, whose reason is closed. Each call is bounded by the catalog's call
  deadline, and by the deadline of the control call it serves, whose cancellation or timeout
  cancels it at once (a call blocked in a worker thread included); the agent is told only the
  time left once the call holds a slot, and the reply is awaited that long after the frame is
  written. A frame is never cut off part-way: the write is shielded, and a connection whose write
  a timeout or cancellation interrupted is ended rather than written on again. A channel serves
  at most four calls at once, and pending argument bytes are bounded. A dropped channel fails its
  pending calls, except that a read whose channel dropped is sent once
  more to another live channel of the same handle (never an approved check, which may already have
  run); a pending call keeps its connection out of idle close; a reply on a connection that
  declared no agent closes it. The hub logs closed tokens only. Every channel under one handle
  serves the same worktree: a connection whose claim names another worktree is closed rather than
  admitted under a handle that already has a live channel (`workspace_agent_worktree_conflict`),
  and a live control call prefers the agent its own connection offered. With no channel for a
  task's handle the call fails `no_agent`; another worktree's agent never answers it.
- **Routing.** `service/workspace_routing.py` wraps every workspace port and callable the service
  composes. An absolute-path workspace goes to the existing local adapter unchanged; a
  `client:<16 hex>` handle goes to the hub, and no local adapter is ever handed it. Callers that
  ran synchronously on the event loop — the reviewer broker's file reads, declared-test pinning,
  the observation verification steps and the post-run hash — move to a worker thread at their call
  sites, with no other behaviour change. A composition built without the hub fails a claim-bound
  read as unavailable (`hub_unavailable`), never as a local read. A reviewer's agent reads and
  its ignored-path probes give the agent's answer no more time than the read's own stop leaves
  (within the reviewer's per-read budget), and a listing's probes go in batches, none sent once
  that stop has passed. The wait for an agent connection keeps its own bound (5 s live, 30 s
  background), so such a read can end past its stop; one answered after its stop is discarded
  and ends the review `deadline`, where a local one would, and one that finds no agent in that
  wait ends it `workspace_agent_unavailable`. An approved check
  run by the agent ends within its call's deadline less a reply reserve; the transport caps a
  call at 300 s, so on a remote target an approval longer than about 285 s is cut there and
  records `timeout` rather than losing its result.
- **The client side.** A connection to a remote root sends a `ClientWorkspaceBinding` (the claim,
  and optionally the agent) in place of its locator. `binding_for_active_root(locator, *,
  serve_workspace)` builds it from the active target's `claim_salt` and returns none for a local
  root, so every connection style decides the same way. A client that serves an agent answers at
  most four workspace calls at once in daemon worker threads, which never keep a finished process
  open; a client without one still rejects a `workspace_call` as a malformed frame, so a local
  connection is unchanged.
- **Observation over claims.** Observation verification and approved checks for a `client:`
  locator route through the hub, and the client drains the outbox and spool it captured for a
  remote root over its own claim-bound connection (`ClientObservationDrain`; from layer 4 the
  background helper holds the long-lived drain). A hook pass's own drain and `finishup
  observe drain` claim their workspace the same way on a remote root, or on one whose record
  cannot be read: they name the workspace to the connect seam, which claims it, and never open
  an unbound connection there. A hook pass that knows no workspace, like `observe drain` for any
  workspace but the one it names (the current folder's by default), sends nothing there and leaves
  the rows pending for the background drain (amended 2026-11-06 after the real-environment runs,
  where an unbound drain was refused or its rows quarantined). `observation_ingest` is allowed on
  a claim-bound connection, and the server's sweeper reads only its own state directory, so it
  never touches a client root. Decision 12 says whose consent and keys govern such an ingest.
- **Local stays local.** Local targets never declare an agent, so the default path is unchanged.

**Held repositories are fenced** (layer 2, decision 8's repository hold). The agent of a
connection to a server elsewhere also fences, on every call, the recorded worktrees of every other
repository held from that same target or kept on this computer, exactly like FinishUP's own
directories; a held worktree that is or contains the claimed workspace is not fenced, and one
nested inside it is governed by the claimed repository's grant. An agent whose own connection's
authorization lapsed answers every call `workspace_unavailable` (ADR-052).

### 6. Honest outcomes

- **Provenance.** Every piece of workspace evidence obtained through the hub is labelled
  `client_attested`. The fixed line is "Workspace evidence was read on the client machine by the
  FinishUP workspace agent and attested over the connection; the server did not read the
  repository itself." Two renderers carry it, and neither puts anything user-controlled beside it:
  - The service ends the text and markdown receipt of a claim-bound task (its session opened with
    a `client:` handle, a durable fact a replay reads alike; a session opened on a claim-bound
    connection by a start naming no workspace — a create, a parent-registered child, a delegated
    child attached by its attach handle — opens with that connection's handle too, recorded in the
    opening event only, never in the request's identity) with a "Workspace evidence" section:
    the fixed line, then `Served by FinishUP service <service_instance_id> (connection:
    client_claim).` The stored receipt document is unchanged. The service
    finds the opening event by its schema name and reads it before the receipt stages or appends
    anything. Owner decision D4: a receipt never refuses because of this lookup; it says clearly
    what happened, why, and whether a retry can help. When the read fails, whatever the failure
    (an environmental fault, a malformed record, the ledger's own classified refusal; each is
    recorded as one bounded diagnostic an operator can find), or the opening event cannot say
    whether the task is claim-bound, the receipt is built and its "Workspace evidence" section
    holds three fixed lines instead. The first two are the same for every cause: "Provenance
    unknown: the record of how this task's session was opened could not be read from the
    server's ledger." (what happened) and "Why it matters: FinishUP cannot confirm whether this
    task's workspace evidence was read on the client machine." (why). The third says whether a
    retry can help, because telling a user to restart for a record no restart reads is
    misleading, and it says only what is true of the cause the service found (decision D4b): each
    cause has its own closed reason and its own fixed third line, so no line claims of one cause
    what holds only for another. A passing cause ends "What to do: run receipt again. If this
    persists, restart the server's FinishUP service (`finishup service restart` on the server
    host), then run receipt again." It is a failed read, or a decodable opening event whose
    payload object the ledger could not read for a reason that can pass (an environmental fault)
    when it recovered the task (the recovered ledger keeps the event as present with no payload,
    keeps that gap for as long as it holds the task, and reads the object again when the service
    opens the task afresh). A failed read is always passing: nothing tells a passing fault from a
    lasting one there, and calling it lasting would claim more than is known. Each lasting cause
    ends with its own "Why it lasts:" line and gives no retry or restart advice. The envelope state
    decides first, because it holds whatever the event's version: a logically redacted opening says "the record was redacted, so it will not
    become readable again and this task's receipts will keep saying so. Running receipt again or
    restarting the service will not change this.", an erased one the same with "erased", and one
    whose key is unavailable says "the server does not have the key that decrypts the record, so
    running receipt again or restarting the service will not read it, and this task's receipts
    will keep saying so while that key is unavailable." An opening of a version the service
    cannot decode (whether or not its payload object read) says "the record is in a format this
    FinishUP version cannot decode, so running receipt again or restarting the service will not
    read it, and this task's receipts will keep saying so until the server runs a FinishUP
    version that knows this format.": an upgrade to such a version is the one change that makes
    it read, so its line never says the record will not become readable again. Last, a payload
    object the object store refused as missing or failing verification is not the passing case:
    the store reports that as its deterministic `object_verification_failed`, apart from an
    environmental fault, the ledger keeps that structural fact, and opening the task again reads
    the same bytes. Such an opening says "the server's stored copy of the record is missing or
    fails its integrity check, so running receipt again or restarting the service will not read
    it, and this task's receipts will keep saying so for as long as that copy is missing or fails
    the check."
    The section is never dropped and never says the evidence was read on the client. Either
    section is rendered inside the receipt text's 32,768-character
    bound, its room reserved before the other sections are placed, so a long receipt has those
    sections shortened and still ends with the whole section: appended after the bound, it made a
    receipt near the bound fail validation on every delivery, which is a refusal in effect.
    Every receipt format, JSON included, also carries the result member
    `workspace_provenance` (receipt-result 1.5.0; 1.4.0 shipped in v0.3.0 and is never amended):
    `status` `unknown`, the closed `reason` naming the cause (`session_opening_unreadable` for the
    passing one; `session_opening_copy_unverifiable`, `session_opening_redacted`,
    `session_opening_erased`, `session_opening_key_unavailable` and
    `session_opening_format_unknown` for the lasting ones),
    and `notice`, that reason's same three lines; each reason admits only its own notice, and the
    member is absent whenever the binding was read. The `reason` token is carried only by 1.5.0,
    which is not released, so telling the causes apart by token changed no released schema: 1.5.0
    is amended in place, and a client can choose its rendering from the token rather than from
    words. A receipt the service pages
    for an agent delivers the member whole at the head of its first page. A refusal would shut a
    task out of receipts — a task that is not claim-bound got a correct one before — for as long
    as the fault lasts, and for good when the object is gone. Every receipt and every replay
    reads the opening event again, so once the read succeeds (a transient fault clears, or the
    service reopens the task after it drops an idle task or restarts, and the object reads) the
    same receipt renders the binding the event records; a lasting cause keeps its section, and
    says so, through every retry and restart, for as long as its own line says.
  - The client ends every human status and receipt rendering of a claim-bound connection — CLI
    text, the MCP status and receipt text, the terminal interface's task views and receipt — with
    the fixed line (unless the rendered text already carries it) and `This client reached FinishUP
    service <service_instance_id> (transport: <token>).` A receipt whose service text carries the
    provenance-unknown line, or whose result carries `workspace_provenance`, keeps only the
    second: the client's line is a fact about its
    connection, the service's is about the task's own opening event, and the client does not
    overrule the service by saying the evidence was read on its machine. Every delivery page of a
    receipt the service paged for an agent (the first from `receipt`, the rest from `status`
    continuations) keeps only the second too: the receipt's section is cut into fragments with
    the rest of its text and lands on at most one page, so no page can show which statement it
    holds, and the agent reads it whole before the set is actionable-complete. A JSON receipt, or
    one whose text the service withheld, has no section of its own, so the client's human
    rendering shows the same fixed section from `workspace_provenance`: the CLI after the
    receipt's other lines, the terminal interface after the document, and the MCP text carries
    the member in its canonical copy. The id is the one the hello-result named.
    The token is a closed set supplied by whoever builds the connection: `unix` (the default, a
    service's local control endpoint), `connector` (a local relay that carries the connection on),
    `ssh` (an SSH channel the client process opened) or `https` (HTTPS the client process speaks).
    In the unified model's words, `connector` is the relay style and `ssh` and `https` the direct
    style; in layer 1 every connection is `unix`, so a client never prints these lines.
    The connection's lines never enter the MCP structured result, CLI JSON output or a local
    connection's output. Per host, that decides who sees them: Claude Code reads the text
    channel and Cursor the text copy, so their agents do; Codex outside code mode hands its model
    only the serialized structured result, so a Codex agent sees neither line on `status` or a
    receipt, and no page of a paged receipt names the service (a text or markdown receipt's own
    workspace-evidence section in `human_text` still says where the evidence was read). That gap
    is accepted rather than closed with a structured member: the lines are connection facts the
    service's result does not carry, and the owner's own `finishup` views show them. Recorded per
    host in the integration runbooks.
- **Typed gaps when no agent is reachable.** An operation that ends `workspace_agent_unavailable`
  fires the existing gap for what it would have read, and the new reason
  `workspace_agent_unavailable` joins the check-time change unavailable reasons
  (`check_time_change_unavailable_workspace_agent_unavailable`, with its own fixed sentence). A
  review whose file read finds the agent gone ends `workspace_agent_unavailable` and records an
  unavailable result of failure class `transport`, never a judgment. A missing reply is never a
  pass, and an unknown change state fails closed for no-material-work. A read the agent refused
  (or an operation it never offered) is named apart: the check-time change records
  `workspace_agent_refused` (`check_time_change_unavailable_workspace_agent_refused`, its own
  fixed sentence), while `workspace_agent_unavailable`'s sentence covers an agent that was not
  connected, too slow or failed; a refused reviewer read reads as nothing. A reviewer read whose
  time ran out, on the client or while the server waited for the client's answer, ends the
  review `deadline` on every transport, as a slow local read does, and one the
  agent did not serve for any other reason (busy, failed, an answer too large to carry) ends it
  `workspace_agent_unavailable`: a read the agent never made is never shown as an empty listing
  or an absent file. Since listed mode
  leaves an unlisted input unread instead of refusing the read (decision 5, amended 2026-11-07),
  a check-time refusal is now a request the agent does not answer (a handle it did not claim, an
  unknown operation or argument, a root no owner could admit), in practice two releases that do
  not match; its sentence says so and that the same release belongs on both computers, the client
  included. The unavailable sentence names `finishup server status NAME` on the client and that
  checking again can help. (Amended 2026-11-08 for layer 1: both sentences named `finishup server
  connect NAME`, whose remote meaning was one approach's connector; how a client reconnects its
  agent is the helper's, from layer 4.) Files listed mode kept from review are the
  disclosure `outside_reads_not_listed` (decision 5), never a check-time change gap: the rest of
  the change still reaches review.
- **No silent fallback.** A remote root never spawns or supersedes a local service and never
  falls back to the ambient one; a service refuses to run in a root whose target is remote
  (`target_root_is_remote`). The daemon refuses at composition, before anything is created, when
  the root's `target.json` names a remote kind or cannot be read (it reads only the kind, through
  the shared `config.paths.server_target_kind`), and an on-demand start refuses to spawn a local
  service for such a root at once instead of waiting out its start budget. Writes fail closed and stay retryable through the existing
  reconnect, operation-status probe and `request_id` replay. There is no local write queue: a
  queued write would let a receipt describe work the server never recorded.
- **No replay across targets.** Idempotency is scoped by installation (ADR-002 decision 4). A
  `request_id` sent to one target is never replayed against another. Since a running MCP bridge
  follows a changed selection (ADR-052, O1), a request already sent over a connection that ended
  with `server_authorization_changed` is never resent by the bridge, and its outcome is reported
  unknown; a reconnect replays only on the target the bridge's admission binds to the selection
  on disk.
- **No user-controlled text.** Target names, hosts, addresses and paths never appear in errors,
  logs, hook output, MCP text or receipts. Remedy text lives once in `protocol/recovery.py`, and
  local remedy text keeps its exact bytes.

- **The authorization phases** (layer 2, ADR-052). A connection to a server elsewhere refused by
  the shared gate or ended by its authorization's watch is a retryable `service_unavailable` with
  one of six phases — `zero_network_remote_selected`, `target_reauthorization_required`,
  `target_root_is_remote`, `repository_egress_held`, `repository_egress_kept`,
  `server_authorization_changed` — each with its own continuation, rendered alike by the CLI, MCP,
  hooks, the terminal interface and the menu. The first five refuse a connection before anything
  is sent over it, and say so; an open connection that ends, whatever changed, is
  `server_authorization_changed`, which says FinishUP stopped sending over it and that what the
  server received stays there. A task whose agent's authorization lapsed records
  the existing `workspace_agent_unavailable` gap; no receipt field is added.

### 7. Credentials are pluggable and never on an agent-facing surface

- `finishup.client.credentials.CredentialSource` is the interface, so OAuth can replace an API key
  later. `KeyringOrFileCredential` stores the key in the OS credential store under service
  `yoetz.server-credential.v1`, account = target id, and falls back to the existing owner-only
  file store at `<target root>/config/credential` where no platform store can take it: none is
  usable, the macOS keychain is missing or locked, or the one there refuses the write (locked,
  denied). On macOS the keychain is asked first, without any user interaction, whether a default
  keychain exists and is unlocked (`SecKeychainCopyDefault`, `SecKeychainGetStatus`): writing to a
  missing keychain shows a dialog ("A keychain cannot be found to store ...") and waits, and a
  locked one asks to be unlocked, which no `server add` or `server login` may wait on (an SSH
  session has nobody to answer). Any failure of that check means the file. Only a key the file
  cannot keep either is refused (`credential_store_unavailable`).
  `target.json` records which store took the key, and every read follows that record. A key the
  platform store held before stays there when the file takes the new one (that store is not asked
  again while it refuses): the next key it takes replaces it, and `logout` and `remove` tidy it
  when it can be used.
- **Layer 1.** No remote kind can be added, so there is no key to store: `server login` is
  refused with `remote_kind_unavailable` (decision 3) before any prompt, and both `login` and
  `logout` are hidden from `--help`. `server logout` stays the offline way out: it deletes a key
  that a record written by another build holds, never touching the network, and `server remove`
  deletes it with the root. The rest of this decision is the contract the layers that open the
  HTTPS kinds (layer 5) implement; the store and its reverse paths are already built. **Layer 5
  builds it** (ADR-053 decision 12; ADR-052 decision 23): `server add` of an HTTPS or port target
  stores the key it checked, and `server login` and `server logout` are shown in help.
- `server login` reads the key from a masked prompt or, for automation, from a `--key-file`
  (owner-only, read once); `server logout` deletes it; `server remove` deletes it with the root.
  The store the key is recorded in decides: a store it is not recorded in is only tidied, best
  effort, so a locked platform store never blocks the logout of a key kept in a file, nor the
  removal of an SSH target (which holds no key, so no store is asked). When the recorded platform
  store cannot be used (locked, or not loadable in this session, such as a desktop keyring reached
  over SSH), `logout` refuses (`credential_store_unavailable`, the key stays, and the refusal says
  so) and `remove` still removes the target and names the entry it left there, by target id.
- `server login` checks the key with the server before storing it, alike for every connection
  style (maintainer decision of 2026-11-07: every remote kind behaves the same; refusal is the last
  resort; say what happened, why, and the fix; not built in layer 1). A key the server refuses
  (`remote_auth_failed`), a server whose certificate does not match the recorded trust
  (`remote_identity_changed`, refused inside the TLS handshake before the key is sent) or that
  runs another release (`remote_incompatible`) stores nothing, and the message says why, that
  nothing was stored, and the fix. A server that cannot be reached keeps the key, and the command
  says it is not verified yet, that it is checked on the first connection, and that `server test
  NAME` checks it once the server is up.
- The credential never appears in argv, the environment, `target.json`, a host registration, a
  log, hook output, an MCP frame or JSON output.
- SSH keys, `ssh-agent` and `known_hosts` stay with OpenSSH. FinishUP stores no SSH key, never asks
  for a password, and runs OpenSSH with `BatchMode=yes` and `StrictHostKeyChecking=yes`, except
  for the one probe of `server add` below.
- *SSH add*, alike for every connection style (the same maintainer decision of 2026-11-07; built
  with the SSH kind in layer 4, where it becomes part of the handshake). After the
  owner's typed confirmation on the trusted console, `server add ssh://…` asks the server where
  its service listens over one `ssh` that lets OpenSSH ask, on that same terminal, to confirm a
  host key this computer does not know yet (`StrictHostKeyChecking=ask`, no master, no
  `BatchMode`), so a first add never fails until the owner has run `ssh` by hand. Password and
  keyboard-interactive login stay off for that probe, so the host key is the only question and
  the add proves the key authentication every later connection needs. The owner's answer is
  OpenSSH's own `known_hosts` entry, the pin every later connection checks with
  `StrictHostKeyChecking=yes`; a key that changed is never asked about
  (`remote_identity_changed`). The command says beforehand that OpenSSH may ask and to compare
  the fingerprint with the server's own. A key the owner declines, or does not confirm, is
  refused (`remote_host_key_unconfirmed`), nothing is added, and the message names the question
  to answer. Without that console the add never gets this far: the typed confirmation before it
  is refused as `trusted_console_required`, before any `ssh` runs.
  **As built in layer 4** (design v2 section 2.1; ADR-052 decision 17), discovery comes *before*
  the consent, because the consent shows what the server's profile offers, and every probe runs
  strict first. `client.ssh_discovery` finds the launcher (`--remote-launcher`, or the first
  executable of `$HOME/.local/bin/finishup`, `/opt/homebrew/bin/finishup`,
  `/usr/local/bin/finishup`, `/usr/bin/finishup`, never a bare name resolved through the remote
  `PATH`; none is `remote_launcher_not_found`), then runs `[env FINISHUP_ISOLATED_ROOT=<remote
  root>] <launcher> service endpoint --json` (another schema manifest is `remote_incompatible`) and
  `… service profile --json` (which starts the server's service on demand). Each probe is `ssh -v
  -o ControlPath=none -o ControlMaster=no -o BatchMode=yes -o StrictHostKeyChecking=yes -T`. Only
  when OpenSSH says it does not know the host key, and the trusted console is present, does
  FinishUP print "This computer does not know the server's SSH host key yet, so OpenSSH asks you to
  confirm it here: compare the fingerprint with the server's own before you answer yes." and run
  that probe once more with `StrictHostKeyChecking=ask` (password and keyboard-interactive off).
  Declined or unanswered is `remote_host_key_unconfirmed` (nothing added); a changed key is
  `remote_identity_changed` at once and never asked about (RE-7); an unknown key with no trusted
  console is `trusted_console_required`. A known key without a console runs discovery and is then
  refused `trusted_console_required` at the consent, before anything is recorded. FinishUP never
  writes `known_hosts` itself: the owner's answer to OpenSSH is the pin. `server use` fetches the
  profile the same way on the owner's terminal; the terminal interface never lets OpenSSH ask.
- Which client process reads the credential follows the connection style: in the relay style
  only the background helper reads it; in the direct style the helper and each dialing process do
  (hooks, the MCP bridge and CLI commands; `server set --style direct` says so), an ADR-008
  amendment made with the layer that ships that style (layer 5 for HTTPS), and logging out bumps a
  credential generation every direct process checks before its next request. Any process
  running as the same user can read the credential store or the file, as it can read today's
  auto-unlock custody; the claim is that no surface an agent reaches reveals or switches it.
  For SSH (layer 4) there is no FinishUP credential at all: OpenSSH reads the owner's keys and
  agent, in the helper's master (relay) or in each dialing process's `ssh -W` child (direct), and
  in the probes of `add`, `use` and the helper's profile refresh (ADR-008 amendment, layer 4). A
  key that needs a passphrase must be loaded in the agent: `BatchMode=yes` asks nothing, so an
  unloaded key is `remote_auth_failed`. Changing the style is therefore not an authorization
  change and bumps no generation.

### 8. Consent per remote target, on the trusted console

Layer 1 status: every rule of this decision guards a remote target, and none can be added or
selected (decision 3), so the consent confirmation is never reached and the zero-network refusals
are dormant. Layer 2 runs these refusals inside one shared gate (ADR-052) and adds the repository
egress hold (the subsection at the end of this decision); both stay dormant while no remote kind
is open. Two parts act already: the owner-only record of what this computer's everyday service
last reported (*Remember*, below) is kept up to date, and the last line of defence still refuses
a remote record that something other than `server use` selected. The unified model binds consent
to the server's offer: a consent envelope compared by an explicit partial order (layer 2) and a
profile revision carried on every request (layer 3, ADR-052 decision 10, built and dormant while
no kind is open) add to the disclosure-version check below (now version 3, naming the level and
the server's review egress); the trusted-console rule stays, and `server use` of a remote target
asks every time. Layer 4 opens `ssh`, so for an SSH server every rule of this decision acts: the
consent is given, the zero-network refusals and the repository hold refuse before any claim, dial
or helper start, and the helper is the client-owned process the zero-network rule below names.

- `server add` and `server use` for a remote kind need the trusted foreground console, a versioned
  disclosure and the owner typing the target name. At `server add` the same confirmation first
  asks what the server may read outside the owner's projects (decision 5), unless
  `--outside-reads` answered it or the target is an official endpoint; `server use` does not ask
  it again. `target.json` records `authorized_at` and `disclosure_version`; a new disclosure
  version requires a fresh confirmation before use.
  `targets.require_current_authorization` enforces it at every hop decision
  (`is_remote_active_root`, `binding_for_active_root`, `server connect`), with or without a
  workspace, and refuses with `target_reauthorization_required`; `server status`, `list`, `test`,
  `remove` and `logout` stay usable so the owner can see and remove a stale target.
- The disclosure says what leaves the machine: task statements, published work, evidence, check,
  respond and receipt traffic, the workspace claim (a keyed digest, not a path), observation rows,
  and the workspace evidence the server asks the workspace agent for — the task base and
  check-time change, requested-output facts, reviewer file reads, task inputs, declared tests,
  observation inspection and approved-check results, each within its existing bound. It names the
  native content observation rows carry (decision 12): from Codex under observation consent, and
  from Claude Code or Cursor under an enabled content profile, prompts, agent messages and tool
  inputs and outputs, which can name paths and hold the contents of files the agent read outside
  the project and outside listed folders; the server keeps them as a local service would. It says
  what does not leave: the workspace's absolute path as its name, credentials, and the
  human-control and secret channels. It says that the server's own privacy policy decides any
  AI-powered review egress from there. Disclosure 2 (2026-11-07) added the observation content
  sentences; a target confirmed under disclosure 1 is refused `target_reauthorization_required`
  until the owner confirms again, so no content reaches a server whose disclosure did not name
  it.
- Agents cannot select or add a remote target: there is no MCP tool for it, and the CLI refuses
  without a trusted console.
- The hop is refused in the zero-network state, for every remote kind (`local_port` included).
  This computer's own FinishUP decides: when its everyday installation was set up (its vault was
  initialized), its running service's effective machine-scope policy decides
  (`privacy_get_effective` for the installation's machine scope; the question names no
  repository), and a policy that does not permit network egress refuses the hop. When that
  policy cannot be read (the service is stopped, locked or does not answer, or the installation's
  identity cannot be read), what this computer last reported decides (below): last reported
  zero-network refuses as `zero_network_in_force`, saying when; anything else refuses with
  `network_policy_unreadable`, never allows the hop. (Amended 2026-11-06 again, from the
  real-environment run: the check first read `privacy_get_setup` on a connection that names no
  repository, which the service refuses, so every remote hop from a set-up computer was refused.)
  A computer whose everyday FinishUP was never set up has no policy of its own, so this check
  does not refuse it: the selected server's own policy governs the work sent to it. (Amended
  2026-11-06: the earlier text also read a never-written `[privacy]` table and exempted
  `local_port`.) `server status --json` (`server-target-status` 1.0.0) carries the state below as
  `zero_network_selection`: the item the zero-network check reports (its `reason`,
  `zero_network_remote_selected` or `zero_network_selection_unreadable`, `target_id`, `kind`,
  `detail`, and `policy_read` with `last_reported_at`; generated ids, closed tokens and a
  fixed-shape time only), or null when the check reports nothing.
- **Zero-network and a remote target are never in force together** (maintainer decision,
  2026-11-07: "Remember but also make it so if user uses remote server it can't be zero
  network", replacing the 2026-11-06 decision that surfaced the state and let the owner keep the
  target). FinishUP never switches servers on its own. `cli/zero_network_selection.py` reads the
  selection file afresh (never the process memo); a process whose root an isolation variable or
  pin decides keeps its own policy and is left alone throughout.
  - *Remember.* Whenever this computer's everyday service reports its machine-scope policy to a
    client command on this computer (the zero-network check, `privacy show` and the menu's
    privacy view, setup's update-policy read, and the read after every privacy change made here),
    the client records an owner-only marker, `client/everyday_policy.py`:
    `<ambient state dir>/servers/everyday-policy.json` (`yoetz.everyday-network-policy/1`, exactly
    `zero_network` and `reported_at`), beside the server registry and outside the vault, written
    atomically and never through a link. A marker that cannot be read (damaged, not owner-only, a
    link, oversized) counts as no record: nothing claims the state from it, no connection is
    refused on it, and the next report replaces it. Deleting FinishUP's folders removes it, and the
    zero-network check removes it once the everyday installation no longer exists (`no_policy`).
  - *A change that would make this computer zero-network while a remote target is selected*
    (a machine-scope candidate that does not permit network egress, while the selection on disk
    names, or may name, a remote target) is decided before anything is sent
    (`guard_policy_change`; every path that proposes or tightens this computer's policy: the
    privacy setup ceremony and its credential-heuristic, conversation and input-root changes,
    `privacy propose|tighten`, `finishup setup`, `finishup ai`, the menu's wizard, the terminal
    interface's privacy flows, and the relayed elevated grant), and again before the approval of a
    pending proposal is sent, since a remote target may have been selected after the proposal was
    made (`privacy_control`: the interactive ceremony after the owner answers approve, `privacy
    decide-policy` and the questionnaire's decision included; a supplied, relayed decision is
    refused). The decision's own preview, the exact diff approved, decides
    (`preview_forbids_network`: `global`/`network_egress` turned off in the machine ceiling of a
    compound proposal, or in a single-scope proposal, whose preview does not name its scope and so
    counts as this computer's). On the trusted foreground
    console it names the target by id and kind and offers exactly two choices: `1` switch to this
    computer's everyday FinishUP (`finishup server use local`) and make the change, or `2` cancel
    the change and keep the target. Enter, end of input, Ctrl-C and any other answer cancel. The
    choice is read on the calling event loop's thread, never in a worker, with Python's default
    SIGINT handler in place of the loop runner's for the read, so Ctrl-C answers it at once.
    Without that console, for a machine-readable answer (`--json`, including the setting
    commands, which set `machine_readable_answer()` around the change), or for a decision relayed
    from an agent chat, the change is refused before it is applied: stderr carries
    `zero_network_remote_selected: …` (or `zero_network_selection_unreadable: …`), why, and the
    one remedy, `finishup server use local`, then the same change again; nothing is sent. After
    every committed change the policy is read again and remembered; if a remote target was
    selected meanwhile, stderr says so with the same token.
  - *The last line of defence.* `targets.require_current_authorization`, which every hop
    decision already calls (the connect seams in `service/client.py`, `binding_for_active_root`,
    `server connect`), refuses any remote target while the marker says zero-network, before the
    disclosure check, with the closed reason `zero_network_remote_selected`. It is a remote
    connection phase (`REMOTE_CONNECTION_PHASES`) with the continuation
    `zero_network_local_server_required`, so the CLI, MCP, hooks and the terminal interface say
    why and the remedy for a process whose selection predates the change, and nothing is
    started or sent for it. The check reads the marker only, never the service, so hooks keep
    their budgets. A command that acts on one remote target names the refusal for that target
    (`cli.server.zero_network_connection_refusal`): the selected target, or any target while the
    selection cannot be read, is `zero_network_remote_selected` with `finishup server use local`;
    any other remote target is `zero_network_in_force`, saying when this computer last reported
    the state and that its privacy policy must change first (`finishup privacy setup`), since
    switching would change nothing. `server login` refuses its key check, `server connect` its
    connection, and `server status` and `server test` probe nothing (probe outcome `not_probed`
    with that reason and the time this computer reported the state, `last_reported_at`, "nothing
    was sent", never "did not answer"). A client-owned process
    that holds connections to a remote target open, or connects again on its own, enforces the
    same marker itself, because it would otherwise keep sending after the change: it checks
    before every connection it opens or relays and at least once a second while it runs, and on
    finding the marker it closes what it holds, sends nothing more (no last delivery of captured
    observations), and names `zero_network_remote_selected`. Layer 1 runs no such process; the
    background helper of layer 4 and every long-lived client of the direct style are such
    processes.

  **Where the choice can arise.** While a remote target is selected, a fresh process does not
  set this computer's policy: every `server_host` privacy command (the privacy ceremonies,
  `decide-policy`, the credential-heuristic, conversation and input-root commands, `ai`,
  `elevated-bootstrap`, the terminal interface's `/privacy`) is refused with
  `requires_server_host`, and the `any`-scoped `privacy tighten|propose` and `setup run` act on
  the selected target's own policy (below), which this rule leaves alone. The choice therefore
  arises when the process making the change resolved this computer's server before the selection
  changed (the selection memo is per process): an open terminal interface or menu, or a privacy
  step or setup run already under way when `server use` ran elsewhere.

  The item stays visible while the state lasts: `server status` (stderr, and with `--json` also
  the document's `zero_network_selection`, from the same policy read) and `server list`, `setup
  status` (stderr), `setup status --next` (a `server_selection` fact with its pinned
  continuation, which is then also the top-level next step), the setup wizard's next steps, the menu home, and the terminal interface's header
  and `/server` (read at start, after a privacy ceremony, and on `/server`; the header drops it
  once the selection file changes). They read the live policy first and, while it cannot be read,
  the marker, worded "this computer last reported", with when. A selection that cannot be read is
  reported as `zero_network_selection_unreadable` with its closed reason (`selection_invalid`,
  `target_root_unsafe`, `target_record_invalid`) and `finishup server use local` as the way back,
  never as "no server".

  **Switching stops the traffic it names.** The choice's `1`, `finishup server use local` and the
  terminal interface's `/server` "Use local" all run `cli.server.use_target`, which clears the
  selection and then stops what this client runs for the remote target it left, through that
  target's runtime exactly as `server disconnect` does, never by pattern (`use` of another target
  does the same for the one it leaves). From layer 4 that is the target's background helper: it
  makes its last bounded delivery of what the hooks already captured for that server (none once
  this computer last reported zero-network), closes its background workspace agents, so a server
  job already under way can no longer read files here, and exits before the command returns; the
  choice's `1` switches before the change is made, so that delivery still precedes the
  zero-network policy. In layer 1 no runtime is registered for a remote kind, so this client ran
  nothing for such a target and the switch has nothing to stop or report. Every surface that
  switches says so by generated id and kind. When a stop does not finish within its wait the
  selection is still cleared, and the command says so on stderr with `finishup server disconnect`
  as the way to finish it. Until open agent sessions restart, a running MCP bridge keeps a server
  on this computer it started with; a bridge connected to a server elsewhere ends that connection
  once the selection changes and follows the new selection on its next request (the owner's
  answer O1, ADR-052). A selection that cannot be read names no target, so switching away
  from it stops nothing (`finishup server disconnect NAME` stops a target's connection).

  **Honest limits:** a connection already open when the policy changes ends at its next check
  (within about a second, layer 2's watch; a request already under way may finish); after
  switching, an open agent session on a server elsewhere follows the new selection (O1), while
  one that started on a server on this computer keeps it until it restarts; after an
  upgrade from a release without the marker, nothing is remembered until this computer's policy
  is next reported. Agents cannot change the policy or the selection, so no MCP tool surfaces or
  answers the choice.
- **Which server's policy a command changes is said before and after** (maintainer principle "be
  clear on what happened", 2026-11-06). While a remote target is selected, `privacy tighten`,
  `privacy propose` and the privacy step of `setup run` (the trusted questionnaire, which the
  menu's setup and the terminal interface's first run also run) change the target's policy, not
  this computer's everyday one. `cli/policy_server.py` names the target of the process's resolved
  root (`active_target_record()`, not the selection read afresh: a process on this computer's
  server changes this computer's policy and says nothing here), for the remote kinds only, by
  `target_id` and `kind`, never the name the owner typed. Each path prints a fixed line before
  anything is sent (`Privacy policy changes here apply to the selected FinishUP server t_… (kind),
  not to this computer's everyday FinishUP.`) and one in its result: the change applied
  (`tightening_applied`, or a configured questionnaire), waits for a decision on the server host
  (`decision_required`), was not changed, or was not confirmed (the command failed after it may
  have reached the server; `privacy show` shows the policy). The lines are the same with and
  without `--json`: the `tighten|propose` result document is the released control result body,
  so it keeps its shape and the lines go to stderr; the questionnaire prints them with its own
  output, the setup summary's privacy lines end with `(on the FinishUP server t_… (kind))`, and
  the terminal interface repeats the result line once the handed-over terminal returns. No output
  schema involved is unreleased, so no field was added. `privacy decide-policy` stays
  `server_host`: on this computer it is refused with `requires_server_host`, whose line names the
  target, because a trusted decision runs only on the server host (decisions 7 and 11). For the
  same reason the questionnaire on a remote target no longer opens the local decision ceremony
  for a widening (it could only fail, the human-control channel never leaving the server host): it
  reports the waiting proposal (`outcome` `cancelled`, its `proposal_id` and the server's
  `expires_at`, `reason` `requires_server_host`). A named local target is this computer's own
  server host and is not named; a target record that cannot be read is left to the connection,
  which refuses it.

  *Amended 2026-11-06 (review):* a waiting proposal must be one the owner can act on, following
  "be clear on what happened, why, and that a retry can help". Every surface that reports one
  (the `privacy propose` stderr line, the questionnaire, the setup summary, the terminal
  interface) prints the same sentence: the change waits and the policy has not changed, because a
  trusted decision runs only on the server host; run `finishup privacy decide-policy <proposal
  id>` there before `<expiry, rounded down to the minute> UTC`; after that it expires unchanged
  and making the change again here proposes it anew. The id and the expiry come from the
  server's `decision_required` answer and are printed only in their closed shapes (`ppr_<uuid>`,
  `YYYY-MM-DDTHH:MM:SS.mmmZ`); anything else is left out and the line says to make the change
  again. The proposal lives `PrivacyPolicyApplication.proposal_ttl_seconds` (300 s); nothing on
  the server host lists policy proposals (`privacy_pending_list` carries disclosures only, a
  released body), so the printed id is how the owner finds it. On a remote target setup's next
  steps never name `finishup --privacy` or `finishup --set` (both `server_host`): the privacy step
  is that decide-policy continuation for a waiting proposal, otherwise "rerun `finishup setup
  run` here", and the API-key step says both run only on that server's host. Every caller that
  prints a result after the questionnaire (setup run, the provider step `setup run --host` runs,
  the terminal interface's four hand-overs) reads the server once before it and keeps that value,
  so the result names the server the change was made on even if the selection changes during the
  questionnaire (the zero-network choice above can switch it, in a process on this computer's own
  server).
- **Honest limit.** This is a trusted-console decision, not a vault-reauthenticated ceremony,
  because a client machine may have no vault.

#### A repository whose policy on this computer allows no network use

Maintainer decision of 2026-11-07 (round 4), specified in the round-5 design on issue #1308 with
the maintainer's addendum of the same day and the critic review the addendum made binding; built
in layer 2 on the shared gate (ADR-052). While a server on another machine, a port or the web is
selected, a repository whose own privacy grant on this computer composes to no network egress is
**held** from it: nothing FinishUP reads or claims for that repository is sent there until the
owner decides. Interpretation:

1. *Held* means this computer's everyday FinishUP reported, live or last, that the repository's
   grant is `granted` and its composed policy does not permit network egress, while the machine
   row permits it (machine-wide zero-network is refused earlier, as above), for a remote target
   with no current choice for that repository. A repository with no grant inherits the machine row
   and is never held; named local servers are out of scope.
2. *Unknown is not held:* no report, an unreadable one, a failed read, an isolation variable or
   pin, or a computer never set up.
3. *Held is retryable*, never a refusal of the task: `repository_egress_held` (continuation
   `repository_send_decision_required`: the agent asks the user once; only the user runs `finishup
   server repositories add` on the trusted console and types the server's name; on a decline it
   runs `finishup server repositories keep` and does not ask again). A kept repository is
   `repository_egress_kept` (`repository_kept_on_this_computer`: continue without FinishUP for it,
   never ask again).
4. *One decision for every remote kind.*

**Detection and order.** The hold is the gate's last step (ADR-052 decision 1): after the record,
zero-network, the disclosure and an open kind, and before any claim, dial, start or sync. The
repository's root is resolved once (its one Git read); its key is `sha256` over the shared
repository identity, so every linked worktree shares it.

**Records.** `<ambient state dir>/servers/everyday-repositories.json`
(`yoetz.everyday-repository-policy/1`, owner-only, atomic): per repository key, whether it allows
network use, when the current no-network stretch began (`no_network_since`), when it was reported
and up to eight worktrees; at most 256 entries and 256 KiB, permitted entries evicted first, a
bound the writer keeps as the reader does. An update that still would not fit is not written (the
record keeps what it said, so no held entry is dropped for its size), and
`everyday-repositories-overflow.json` (`yoetz.everyday-repository-overflow/1`, the time) records it
until an update fits; `server repositories list` says so. It is written by a
live read at session start (at most 0.5 s, once per repository per day or when older than the last
machine report, in a fresh context on its own event loop, before any attach, status or drain), by
every privacy ceremony and `provider status` from what the service already answered, and after a
change here (a decision whose repository is not known re-reads every permitted entry within 3 s and
forgets the ones it cannot). While the machine row forbids network use a repository's own grant
cannot be told apart, so its entry is forgotten. **Dormant until a server elsewhere is recorded**
(O3): with no remote target record on this computer none of this reads or writes anything, and
there is no report from before the first one; removing the last one deletes the record.
`<target root>/config/repositories.json` (`yoetz.server-repositories/1`) keeps the owner's choices
for that target — `send` (allowed anyway, under disclosure version 1) or `keep` — each bound to the
`no_network_since` it was made in, so a grant that leaves no-network and returns asks again
(`grant_changed`); machine-row changes and target edits do not lapse a choice.

**Fence and own hold.** The workspace agent of any other repository's connection to the same target
fences the held repositories' recorded worktrees from outside reads, listed folders, outside read
roots and `lstat_candidates`, read per call (decision 5). Metadata and existence answers compare
the candidate's spelling and, since `lstat` follows every link but the last, its resolved spelling
and the device and inode of every directory above it, so a symlinked or bind-mounted component
never reaches a fenced worktree. A held worktree that is, or contains, the
claimed workspace is not fenced (that would empty its own reads), and a repository nested inside the
claimed one is governed by the claimed repository's own grant (critic gap 7). An agent whose own
connection's authorization lapsed — its repository held or kept among the causes — answers every
call `workspace_unavailable`.

**Texts.** Every host (Codex, Claude Code, Cursor) receives one byte-identical session-start text
per state (`repository_hold.hook_context`): the attach form substitutes for the "call start"
advice instead of being prepended (critic gap 8), an unconsented form names no observations, and a
mapped form serves resume and compact. CLI, MCP, the terminal interface and the menu render the
phases as every authorization refusal (ADR-052). `server repositories add|keep|list|remove`,
`server status` (`target.repositories`) and the terminal interface's `/server` item show and change
the choices; the group is hidden and `add` refuses `remote_kind_unavailable` while no kind is open
(O4). No surface recommends `add` then: `server status`, `server repositories list` and `keep`
show what works (`keep`, `remove`) and say that sending a held repository anyway arrives in a later
release, and the line after a privacy change names no hold while an earlier gate step refuses the
server. From layer 4 the group is shown and `add` acts for an SSH target on the trusted console;
it still refuses before the console for a kind that is closed.

**Honest limits.**

1. Before layer 4 no server elsewhere could be used, so nothing was held; from layer 4 the hold
   acts for an SSH server.
2. Unknown is not held: a grant never reported since this release (or since the first server
   elsewhere was recorded) is not held until it is reported.
3. Past 256 entries the oldest are evicted; an evicted held entry becomes unknown. Past 256 KiB
   (long worktree paths) entries that allow network use are evicted first; a report that still
   does not fit is not recorded, so its repository stays unknown until one fits, and no held
   entry is dropped for its size.
4. A request already under way may finish; open connections end within about a second. "Nothing
   more", never "never sent"; what the server received stays there.
5. Fencing covers recorded worktrees only (at most eight per repository). A fenced read is
   counted only on the receipt of a level-L2 task, whose evidence account carries it (O7;
   ADR-054 decision 14); a level-L1 task's receipt does not count it.
6. Connections that name no repository are not held.
7. A same-user process can edit either record; the trusted console stops agents from using
   FinishUP's own commands, not same-user file writes. A hand edit does end open connections
   (ADR-052's generation).
8. After an allow, the observations recorded while held are sent, without the content captured
   while held.
9. A choice survives machine-row changes and lapses only when the repository's no-network stretch
   is broken or the report is lost; a no → yes → no change the client never saw keeps the choice
   (critic gap 12). Binding the choice to the service's authority digest was rejected because it
   lapses on unrelated machine changes.
10. Per-prompt cues are unchanged; each refused call is cheap and carries the directive.
11. Under required startup a held repository keeps tools blocked until the owner decides, switches
    to this computer's server, or returns startup to optional.
12. **Hook content from other folders is still sent** (the addendum's answer 2): the hold covers
    what FinishUP itself reads and claims for the repository, not what an agent in another folder
    reads and its hooks capture.
13. A repository nested inside another is governed by the outer repository's grant.
14. Processes older than this release keep its rules until they restart.

### 9. Scopes, not self-declared client kinds, bound a key

Not built in layer 1: no server edge existed. **Built in layer 5** (ADR-053 decisions 3 and 6):
both HTTP server edges, gateway and native, enforce these scopes around the REST routes; an
out-of-scope call is answered with the control protocol's own `method_forbidden` result and never
dispatched, and `server_profile` is never a REST call (it is `GET /v1/server`). Each key also
carries a principal: a REST claim is namespaced by it, an SSH claim is not, so an HTTPS client and
an SSH client of the same repository reach different task namespaces.

An HTTPS or `local_port` key carries a scope, `agent` or `operator`, that the server-side edge
enforces as a method allow-list; the daemon's client-kind gate stays as a second layer.

| Scope | Methods |
|---|---|
| `agent` | The six workflow methods, `service_status`, and `observation_ingest` on a claim-bound connection: what hooks, the MCP bridge, the closure gate and the startup-gate probe use. |
| `operator` | `agent` plus `project`, `review`, `import_codex_jsonl`, `observation_status`, the read and tighten privacy methods (`privacy_get_setup`, `privacy_get_effective`, `privacy_pending_list`, `privacy_receipts_list`, `privacy_receipts_get`, `privacy_propose_policy`, `privacy_tighten_policy`) and `service_lock`. |
| Never over HTTPS | `service_stop`; `backup_*`, `restore_*`, `migrate_*` and `integration_*` (they name server paths); `observation_pause`, `observation_resume`, `observation_revoke`; the human-control and secret channels. |

A hello that carries `workspace_locator` is refused at an HTTP edge (the composition flag
`refuse_workspace_locators`, decision 4, built in layer 1). As built in layer 5, REST names no
path at all: the client's mapping never sends a hello that names a `workspace_locator`, a start
needs a claim (`workspace_claim_required`) and a `workspace_ref` must be a `client:` handle
(`frame_invalid`), so neither REST edge needs the flag. The owner receipt view needs
a ceremony bound to its own connection on the service host, so a remote `receipt` returns the
ordinary view. An SSH target is owner-equivalent and allows every method, as locally; scoped SSH
through a forced command is later work.

### 10. Version lockstep

The client and the server run the same release. The handshake already requires an exact
`schema_manifest_digest` match; a mismatch on a remote target is `remote_incompatible`, whose text
names both releases (release versions are not user-controlled). A remote service is never
superseded by a client. On 2026-11-08 the maintainer decided the compatibility window (U18):
self-hosted servers keep this lockstep, and the REST layer adds a public API compatibility
manifest, capability negotiation and cross-version conformance tests, so that a server, the
official service in particular, can serve a window of client releases. Until then lockstep is the
rule. **Built in layer 5** (ADR-053 decision 5): the REST API manifest (a digest over the REST
schemas' transitive closure) is named on every `/v1` request and listed by discovery; a server
refuses one it does not serve (`api_manifest_unsupported`, which the client names
`remote_incompatible`). The core server serves exactly its own, a window of one, so self-hosted
servers keep lockstep on the public contract while two releases with a byte-identical REST
contract interoperate; a server that serves more must pass each window's frozen vectors, which the
conformance kit replays. Over SSH the control hello keeps the full schema-manifest lockstep.

### 11. What stays on the server host

Vault setup, unlock and passphrase changes, provider and AI-powered review configuration, privacy
ceremonies, elevated bootstrap, backup, restore and migrate run on the server host. Observation
store administration (`observe …`, `/observe`) acts on the active root's own observation store,
which on a remote target is the client's store and its authority (decision 12), so it runs on the
client. Over SSH, `finishup service start|stop|restart|status|lock|unlock|diagnostics`
can run there through `ssh -t`, whose remote pseudo-terminal passes the trusted-console check.
On the client every `server_host` command is refused with `requires_server_host`, whose remedy
says to run it on the server host (through `ssh -t` for an SSH target; by the server's operator for
an HTTPS target). The guard is built in layer 1; it refuses only while a remote root is active,
which in layer 1 only a record selected outside `server use` can make (decision 1 fails it closed
for a root whose record cannot be read).

### 12. Observation on a remote target

For a remote target the hooks run on the client, the owner granted observation consent there, and
the rows were captured there. The server holds none of it and must not borrow it. Layer 1 builds
the whole decision, the hook-content rule included, and tests the server side in process; with no
remote target selectable, a client's hooks deliver to a local or named-local service exactly as
before.

- **The client is the authority.** The client's observation store under the target root (consent,
  content-capture profiles, selection, approved-check policy trust, the observation key that
  computes every session and workspace commitment), its lifecycle mappings and its outbox and
  spool stay on the client. The `observe` commands and `/observe` administer that store, so they
  are labelled `any`. The observation key never leaves the client.
- **Client attestation.** On a claim-bound connection each `observation_ingest` body carries
  `client_attestation` (control-request 2.10.0): `schema_version`, `consent`
  (`active`, `paused` or `revoked`), `granted_at`, `content_capture_profiles`,
  `authority_generation` (the client's content-capture fence), `check_policy_digest` (the one
  policy digest the owner trusted there, or null) and `route` (the FinishUP task, session and
  writer the client's mapping names for the host session, or null). The client builds it from its
  own store and mapping when it sends the row (hook pass, `observe drain` and the background
  drain alike), and replaces any workspace-locator content with the connection's handle, so the
  workspace path itself never leaves the client.
- **Captured content travels as a local service receives it** (maintainer decision of
  2026-11-07, "Send to every server", closing open question 3). Every other content chunk
  (prompts, agent messages, tool inputs and outputs from Codex under observation consent, and from
  Claude Code or Cursor under an enabled content profile) is sent unchanged to every remote
  server, whatever its outside-read mode, so with a content profile on the server holds what a
  service on the client would: "local mode is as local" holds for observation too. Those chunks
  can name absolute paths and hold the contents of files the agent read outside the project and
  outside the target's listed folders, so a `listed`-mode server receives them too: its
  outside-read mode (decision 5) limits only what the server reads, never what the client's hooks
  deliver. That is honest only because it is disclosed before consent: the server disclosure
  (decision 8, disclosure 2) names it, and a target confirmed under disclosure 1 sends nothing
  until the owner confirms again. Withholding content chunks on claim-bound connections, for
  every server or only for a `listed`-mode one, was not chosen: the server would then hold less
  than a local service for the same consent, and the owner already controls the content with the
  client's own consent and content profiles.
- **Accepted as `client_attested`, never verified.** The server cannot recompute a commitment made
  under the client's key, so on a claim-bound connection it accepts the envelope's session
  commitment and the attested consent, profiles, fence, trust and route as client-attested. It
  records them keyed to the claimed worktree in a separate claim store, `<state
  dir>/observation-claims/<16 hex of the handle>/` (an ordinary observation store and
  lifecycle-mapping directory holding only that worktree's workspace, under a key the server
  generates), and runs the unchanged observation coordinator over it with the handle as the
  workspace. The handle names one worktree, so linked worktrees of one repository keep separate
  consent, revocation, content fence and approved-check trust, as the client keeps them: consent
  for one worktree never covers another. Its own observation store, mappings and consent are
  never read or written for a claim.
- **What the server still decides.** Only the connection's own claim is touched. The attested
  route must name a task whose route was opened on a connection carrying the same claim (its
  route commitment is the claim commitment); any other route is refused with `consent_missing`
  before anything is written. A route naming a session its task has since replaced (a recovery
  `start` elsewhere, or the server's own lifecycle recovery, while the client's mapping still names
  the old session) is judged by the task's current route, and the coordinator then follows
  `session_superseded` to the successor and keeps it in the claim's mapping, as it does locally.
  The server's own observation switch and vault gate apply.
  Verification opens the claimed workspace by its handle through the workspace agent (decision 5)
  and never through a stored locator.
- **Refusals keep their closed reasons.** A claim-bound ingest without an attestation is refused
  with `consent_missing`, before anything is read or written; an attestation without a route is
  `mapping_missing` (retryable, as locally); a paused or revoked consent is refused exactly as a
  local one is. When too many claims are busy at once the row is refused `service_unavailable`
  (retryable). An attestation on a connection that carries no claim is a malformed request
  (`frame_invalid`). A locator-bound or unbound connection keeps today's checks byte for byte:
  commitment against the server's key, consent and mapping from the server's own store.
- **Consent changes travel with the next row.** A pause, resume or revoke on the client is mirrored
  into the claim store when the next row arrives; a revoke runs the service's own revocation for
  that claim (task stores deactivate their locator and trust rows), and later rows are refused.
  Rows the server already accepted stay accepted, as for a local revoke.
- **Honest receipts.** Text and markdown receipts of a claim-bound task whose coverage includes
  hook-observed evidence add one fixed line after the workspace-evidence line: "Hook observations
  were captured on the client machine under its own observation consent and delivered over the
  connection; the server did not verify that consent or the session commitments." A JSON
  receipt has no trailer, so a claim-bound client's rendering of it (the CLI's, the terminal
  interface's and the MCP text) adds the same line after the connection's workspace-evidence line,
  never on a receipt page or beside an unknown provenance; raw JSON output carries none. A JSON
  receipt an agent receives in pages, or reads as Codex's structured result outside code mode,
  therefore carries neither line, and PRIVACY.md and the servers guide promise the lines only
  where they appear. Logs carry the `client_attested` label and closed tokens only.
- **Limits.** Advice the service prepares for hooks to deliver stays in the claim store and does
  not yet reach a remote client's hooks. After a server restart a claim's pending verification
  resumes when that claim delivers its next row. The server's check barrier reconciles only its
  own store's capture handoffs, and a claim-bound `check` that asks to await observations reports
  that wait `unavailable`: the rows wait in the client's outbox, which the server cannot read.
  The CLI renders that state on a claim-bound connection with its own fixed line
  (`CLAIM_BOUND_AWAIT_UNAVAILABLE_LINE`: the server cannot wait for observations still on this
  computer; run `finishup observe drain` in the project folder first, then check again without
  `--await-observations`, since a check that asks to wait reports `unavailable` again), never the
  local "local outbox not readable" cause.
  A claim store outlives the rows that fed it: when the client stops sending (a revoke after its
  outbox drained, `server remove`, a client that is gone), the mirrored consent, trusted policy
  digest, session bindings and mappings stay in `<state dir>/observation-claims/` on the server,
  and the server's own revocation for that claim does not run. No FinishUP command lists or clears
  claim stores yet, on either machine; only deleting the server's whole FinishUP state removes
  them, and that destroys its vault, ledgers and every task, so it is no way to clear one claim
  and the servers guide does not offer it. They authorize nothing on their own: every
  claim-bound row carries a fresh attestation that is mirrored before it is ingested (a revoked
  or paused consent then refuses it as locally), and an approved check runs only when the
  client's own trust admits it (`check_not_approved` otherwise). An operator surface (server-host scope, through the service: list each claim's
  consent state, clear one) and a revoke sent on `server remove` while connected are the
  follow-up; both need a control method of their own. Follow-up owner: issue #903, the remote
  service request this ADR scopes, until a dedicated issue is filed.

- **Held rows wait** (layer 2, decision 8's repository hold). Observations of a held or kept
  repository wait in this computer's outbox; both drain sites record the phase and leave the rows
  pending. After an allow they are delivered, without the content captured while the repository
  was held, as the `server repositories add` disclosure says.

## Topology

Layer 1 has one topology, the unix style. Every hook, MCP bridge, CLI and terminal process dials
`<root>/run/control.sock` of the everyday root or of a named local root, with the owner-only
checks and peer-UID authentication of ADR-008; the service never opens a network socket. A remote
root has no endpoint to dial: the connect seam refuses it before any dial (`target_root_is_remote`,
decision 6).

The remote topology arrives with layers 4 and 5, in the shape the maintainer accepted on
2026-11-08 (*Unified model*). Each of those layers amends this section with its exact contract;
the list below is the direction, and *Layer 4, as built* and *Layer 5, as built* after it are the
contracts of the SSH and REST parts.

- **Background helper** (layer 4). One hidden, `client_only` process per remote target, started
  on demand (never by `service run`), exiting 15 minutes after its last client, stopped by `server
  disconnect`, `logout`, `remove` and a `server use` that leaves the target, and reaped by its
  parent. In the relay style it serves `<troot>/run/control.sock`, so agent-facing processes keep
  dialling a Unix endpoint, and its upstream is an SSH forward or REST. In every style it runs the
  background workspace agent of each claimed worktree, the observation drain, the profile
  re-check and, at L2, the code sync. It grows out of approach A's connector, whose lifecycle
  fixes become its regression tests.
- **Direct style** (layers 4 and 5). Each client process dials the server itself: `ssh -W` for
  SSH (from approach B) and the one REST client for HTTPS (from approach C).
- **SSH edge** (layer 4). `sshd` forwards a stream-local channel into the server's owner-only
  control socket; raw control frames, owner-equivalent, no API key.
- **HTTP edges** (layer 5). REST v1 behind one backend interface with two implementations: the
  **gateway**, a separate same-user process with no vault that re-enters the service over its
  control socket (approaches A and B's key hashing, scopes, `Origin` refusal, session caps and
  bounded audit, re-hosted around the REST routes), and the **native** edge, a listener inside the
  service process (approach C; the maintainer owns the security review of a vault-holding process
  on the network, recorded as an ADR-008 amendment with that layer). The server's owner picks the
  edge; a client sees only REST.

**Layer 4, as built (SSH).** One helper per SSH target root (`state/helper.lock`, stamped with
pid, release and schema-manifest digest), started on demand: in the relay style by any client
that finds nothing answering on `<troot>/run/control.sock` (a hook within its own deadline), in
the direct style by the MCP bridge and CLI commands after they register a workspace, and by
`server connect`. It exits 15 minutes after its last relayed client connection when it serves no
registration, and is stopped by `server disconnect`, `remove`, a `server use` that leaves the
target and `server set --style` (the target's owner-only stop epoch moves and the helper stops on
its next tick, then a wait until its lock is seen free; no process is ever signalled, never by
pattern; a helper spawned before the stop exits without serving; one that does not stop is
`target_still_connected`). `server logout` does not apply to SSH. The spawner reaps its own child
on a daemon thread; a spawner that exits first leaves it to the system, so reaping never depends
on the short-lived starter. A helper stamped by an older release of this client (or by another
build of this release, by a client of the build installed now) is replaced through the stop
epoch, a newer one never (ADR-052). A client dialling while
the helper ends its idle exit starts its successor; any other stop has no successor in that
client's wait.

- **Relay** (default). The helper binds `<troot>/run/control.sock` with the service's owner-only
  fences and peer-UID check and keeps one OpenSSH master: `ssh -M -S <troot>/run/m -N -T -o
  BatchMode=yes -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes -o
  StreamLocalBindMask=0177 -o StreamLocalBindUnlink=yes -o ServerAliveInterval=15 -o
  ServerAliveCountMax=3 -o LogLevel=DEBUG1 -p PORT -L <troot>/run/upstream.sock:<remote
  control.sock> [user@]host`, used only once it verified the host key the owner's consent names
  (ADR-052 decision 20). Each local connection is one channel of that forward. A hello naming a
  `workspace_locator` or no `server_profile` revision is never forwarded; every later client frame
  is checked against the helper's admission before it is forwarded; frames from the server pass
  unparsed. When the server's service is not running, the helper runs the server's own
  `<launcher> service start` over the master, at most once per 30 seconds and only for a client's
  connection, never for a background agent.
- **Direct** (advanced). Each dialing process opens `ssh -S <troot>/run/m -o ControlMaster=no -o
  BatchMode=yes -o StrictHostKeyChecking=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3
  -o LogLevel=DEBUG1 -p PORT -W <remote control.sock> [user@]host` through the target's master
  (`ssh -M -S <troot>/run/m -o ControlPersist=15m -N …`, started, verified and recorded under a
  lock by whichever process needs it first; ADR-052 decision 20) and is an ordinary
  `ServiceClient` (gate before the dial, the authorization before every frame and on its watch).
  A stopped server service is started once through the launcher, on that client's demand. The
  helper still runs, for the background agents, the drain and the refresh. `server disconnect`
  ends the master with `ssh -O exit`.
- **Both.** FinishUP's own environment variables are removed from every `ssh` child; the helper
  runs with a fixed, scrubbed environment (`SSH_AUTH_SOCK` kept for the owner's agent). Its
  records are owner-only and hold closed tokens, generated ids, integers and times only:
  `state/helper-status.json`, `config/connection-style.json`, `state/helper-epoch`,
  `state/ssh-master.json` and its lock, `state/profile-refresh-requested` and `log/helper.stderr`
  (INTERFACES, *SSH servers and the helper*). Socket paths may hold spaces (the default root on
  macOS); one holding `:`, `%` or `$` is refused, at `server add` as `ssh_path_unusable`. From
  layer 6 the helper also answers level L2's code-sync calls for a target consented at L2
  (ADR-054).
- **SSH edge.** `sshd` on the server must allow stream-local forwarding; it connects to the
  server's owner-only control socket as the login user, so the service's peer-UID check passes
  unchanged and the SSH login is the service owner (ADR-008 amendment, layer 4).

**Layer 5, as built (REST; ADR-053).** HTTPS and port targets use the same helper, started and
stopped as above, and also stopped by `server login` and `server logout` (A-CRED-STALE).

- **Relay** (default). The helper serves `<troot>/run/control.sock` as for SSH; its upstream is one
  warm TLS transport to the server's REST v1 edge, and each local connection is mapped frame by
  frame to REST requests. Only the helper reads the API key. It never starts the server's
  service: the server's edge does, for a client's request.
- **Direct** (advanced). Each dialing process reads the key and runs an ordinary `ServiceClient`
  over its own REST mapping (the gate before the dial, the authorization before every frame and
  on its watch).
- **Server edges.** `finishup service rest run --listen HOST:PORT (--tls-cert F --tls-key F |
  --behind-proxy) [--edge gateway|native]` on the server host, in the foreground under the
  owner's supervisor. The gateway (the default) holds no vault and re-enters the service over its
  owner-only control socket as ordinary control connections; the native edge runs the service
  with the listener inside it (the owner's security review; ADR-008 amendment, layer 5). An API
  key with a scope and a principal authenticates every `/v1` request; discovery is the one
  unauthenticated route.
- **Records.** No new client record: the key is in the platform credential store or
  `<target root>/config/credential` (decision 7), and the helper keeps the records it keeps for
  SSH, without `run/upstream.sock` and `run/m`. The server keeps `<state dir>/rest/api-keys.json`
  and `<log dir>/rest-audit.jsonl`.


## Reverse states

In layer 1 only `local` targets can be added, so the rows for keys and outside reads apply to a
remote record another build wrote; their ways out stay usable for it (`server logout`, `server
folders remove`, `server remove`), and their ways in are refused or reach nothing until a remote
kind opens. From layer 4 every row but the `server login` row acts for an SSH target; that row
stays HTTPS-only (an SSH target holds no key, and `server logout` refuses it as
`credential_not_applicable`). From layer 5 every row acts for an HTTPS or port target, the
`server login` row included; the server host's own rows (API keys, the REST edge) are in ADR-053.

| Way in | Way out | Way to see it |
|---|---|---|
| `server add NAME …` | `server remove NAME [--select-local]` (under the registry lock: clears a selection that names it first, so no new hook dials it, then disconnects, deletes the credential, disconnects again for a connection a running MCP bridge started meanwhile, and disposes of the root; refuses the selected target unless `--select-local`, and keeps the root while a connection does not stop; that refusal keeps and prints the switch to the everyday server, and a key deleted before the last stop stays deleted, recorded as gone and named in the refusal; a folder something changed while it was deleted refuses `target_partly_removed`, which says how to finish); `server remove ID` deletes a leftover folder that an interrupted add or remove left without a record | `server list` (names each leftover by id) |
| `server use NAME` | `server use local` (removes the selection file; ambient resolution returns with no residue; a remote target it leaves is stopped as `server disconnect` stops it) | `server status` (names the deciding source) |
| `server login NAME` (refused with `remote_kind_unavailable` in layer 1; from layer 5 for an HTTPS or port target, the key checked with the server first; it moves the credential generation and stops the helper) | `server logout NAME` (offline; deletes a stored key, never touches the network; from layer 5 it also moves the credential generation and stops the helper) | `server status` (credential present or absent, never the value) |
| `server add NAME …` for a remote kind records the outside-read mode the owner answered (or `--outside-reads`; an official endpoint is `local` unrecorded) | `server folders mode NAME local` or `listed` changes it; `server remove NAME` removes it with the target | `server add` output, `server folders list NAME`, `server status [--json]`, `/server` status |
| `server folders mode NAME local` (trusted console and typed name whenever it records `local`, an official endpoint's included; without the console an official endpoint's `local` is left unrecorded) | `server folders mode NAME listed` (applies from the workspace agent's next read; a read already in progress may finish) | `server folders list NAME`, `server status [--json]`, `/server` status |
| `server folders add NAME FOLDER` (trusted console) | `server folders remove NAME FOLDER` or `--all` (also clears a damaged record, to an empty one in `listed` mode; applies from the workspace agent's next read, in either mode, and a read already in progress may still return files, and a review the server already prepared may still send what it read) | `server folders list NAME`, `server status [--json]`, `/server` status |
| `server connect [NAME]` | `server disconnect [NAME]` (stops only what that root's runtime stamped; never by name or pattern) | `server status`, `server test` |
| This computer's everyday service reports its machine-scope policy (the zero-network check, `privacy show`, a privacy change here): the owner-only marker of what it last reported (decision 8) | the next report replaces it; deleting FinishUP's folders removes it; the zero-network check removes it once the everyday installation no longer exists | `server status [--json]` (`policy_read`, `last_reported_at`), `server list`, `setup status --next`, the menu home, `/server` and the header |
| Layer 2, once a server elsewhere is recorded: this computer's FinishUP reports a repository's policy (a session start, a privacy ceremony or change here, `provider status`): the owner-only repository report (decision 8) | the next report replaces it; a report whose folders are all gone is forgotten by `server repositories list`; removing the last server elsewhere deletes the record; deleting FinishUP's folders removes it | `server repositories list`, `server status [NAME] [--json]` (`target.repositories`) |
| Layer 2: `server repositories add` (trusted console; acts for an SSH target from layer 4, refused `remote_kind_unavailable` for a kind still closed) or `keep` | `server repositories remove [NAME] [--repository FOLDER]` or `--all` (also repairs a damaged record) | `server repositories list`, `server status [NAME] [--json]`, `/server` and the header |
| Layer 4: a client starts an SSH target's helper on demand (relay: any connecting client; direct: a registrant, `server connect`) | `server disconnect`, `server remove`, a `server use` that leaves the target, `server set --style` (the stop epoch; no signal, never by pattern); its idle exit 15 minutes after its last client | `server status [--json]` (`target.connection.helper`: running, last phase and reason) |
| Layer 4: `server set NAME --style direct` (a style the server's last profile offers) | `server set NAME --style relay` (both stop the helper and the master first) | `server status [--json]` (`target.connection.style`, `styles_offered`) |
| Layer 4: the owner confirms an unknown SSH host key when OpenSSH asks at `server add` or `server use` (OpenSSH writes the owner's `known_hosts`; FinishUP never does) | OpenSSH's own tools remove the pin (for example `ssh-keygen -R`); `server remove` removes FinishUP's record of the identity with the root | `server status` (consent), and `remote_identity_changed` on a key that no longer matches |

Deleting a target's root removes every client-side artifact of that target except an API key
kept in the platform credential store (service `yoetz.server-credential.v1`, account = target id),
which lives outside the root: `server remove` and `server logout` delete it, deleting the folder
does not. A target's connection keeps running until `server disconnect` or `server remove` stops
it, or it exits once idle. The ambient installation is never touched by a target operation.

## Consequences

- With no remote target selected — in layer 1, always — every surface behaves byte for byte as
  before server targets existed. The only local deltas are the new `server` commands, named local
  servers, and the control-schema version and digest, which every envelope bump already moves.
- Layer 1 sends nothing over a network that `main` did not send: the remote kinds are refused
  before any prompt or probe, and a remote root is refused before any dial.
- The consequences below hold for an SSH server from layer 4, and for HTTPS and port servers from
  layer 5.
- Remote evidence is `client_attested`: the ADR-031 fences run on the client, inside the workspace
  agent, and the server cannot check them independently. Receipts say so in one fixed line.
- Remote round trips cost hook budget. No budget is relaxed; `server test` measures the round trip
  against the hook budgets and warns when a required startup gate would likely deny.
- Upgrades are lockstep: over SSH every refusal names both releases. Over REST, compatibility is
  the API manifest (a window of one in the core server, decision 10); discovery names no release,
  so a server that does not serve this client's manifest is `remote_incompatible` without naming
  one.
- This computer's zero-network policy and a remote target are never in force together
  (decision 8, maintainer decision of 2026-11-07, replacing the 2026-11-06 choice to surface the
  state and let the owner keep the target). Adding or selecting a remote target is refused in that
  state; a change into it while a remote target is selected asks the owner on the trusted console
  to switch to this computer's everyday FinishUP or cancel, and is refused without that console;
  and every connection to a remote target is refused while this computer last reported the state.
  To know it while this computer's service is stopped or locked, the client remembers each report
  of this computer's policy in an owner-only marker outside the vault. The connection check costs
  a file read, not a round trip.
- Every path on this computer that changes a remote target's privacy policy names the target
  (id and kind) before and after (decision 8). A widening proposed there waits on the server host
  for its decision; setup's privacy step reports it as waiting instead of failing on a local
  ceremony it cannot reach, names the proposal id and its expiry (about five minutes) with the
  exact `privacy decide-policy` command for that host, and setup's next steps say the same rather
  than naming `--privacy` or `--set`. The server host offers no list of policy proposals, so a
  proposal whose id was lost is retried by making the change again once it expires.
- A Linux server whose runtime directory belongs to the login session loses its sockets at the
  last logout; `service endpoint --json` reports this, and the server needs linger or its own
  isolated root.
- A human-passphrase vault on a server stays locked after a restart until the owner unlocks it on
  the server; auto-unlock custody (ADR-008, 2026-10-19) is the unattended path.
- That custody also re-opens a soft lock (idle, session lock, suspend) when a request arrives,
  a claim hello included (decision 4). The re-open is one service-owned attempt: a hello at its
  5-second handshake deadline stops waiting for it but never interrupts it. A lock outranks it:
  an explicit or session lock cancels the attempt first and records its own reason. The attempt's
  own 30-second deadline, the on-demand cold-start budget for the same unlock and activation,
  returns a stalled one to the soft lock for a later request to retry. The staged-slot reconcile
  after the vault opens is hygiene: it runs beside activation, outside that deadline and a
  lock's cancel, so it never relocks the open vault, and the next attempt waits for it before
  reading. A passphrase rotation does not open while it runs, because it discards a staged
  rotation entry it finds and the helper stages its replacement once the rotation opened: the
  open waits up to the 5-second handshake budget for it, and only a store that does not answer
  by then gets a refusal, which the helper reports as a credential-store check still running,
  safe to retry. The generated rotation, which stages before it opens, stays a known limit
  (INTERFACES; issue #1319). While a
  credential-store call an attempt gave up on (the scoped-entry read or that
  reconcile) is still blocked in its worker thread, no attempt starts another, so a credential
  store that never answers holds one thread. The deadline bounds only what the attempt awaits: an
  `os_keyring` root-key read on the event loop, or an activation step that joins its worker
  thread, still runs to its end (2026-11-06, after review).
- Out of scope: multi-user or team hosting (principal namespacing is groundwork only); building a
  FinishUP-operated service in this repository (the core only connects to one, maintainer decision
  U8); ledger sync or migration between targets; an offline write queue; a plain-TCP control
  channel; unlock, consent or the owner view over the network; MCP over HTTP to hosts; native
  launchd or systemd installers; native Windows (WSL 2 follows Linux); a per-repository server file,
  which would let a repository redirect its own ledger traffic.

## Alternatives considered

**The three ways of doing the separation, unified.** Each was built as a complete pull request
on top of the shared decisions above, for the maintainer to choose one. On 2026-11-08 the
maintainer chose none alone: the three become options of one model (U1), and the build starts
from A and ports B's and C's pieces in (U15).

| Approach | Shape | Strengths | Costs | Fate in the unified model |
|---|---|---|---|---|
| A — edge relay (#1313) | Clients keep dialling the target root's Unix endpoint. A vault-less per-target connector behind it relays to the server: OpenSSH stream-local forwarding for SSH, and a binding of the control frames to HTTPS, served by a same-user gateway on the server, for HTTPS and localhost ports. | Agent-facing processes and registrations are untouched; one process holds the credential; connections stay warm across short-lived hooks. | A client-side process to supervise; a gateway process on the server. | The connector becomes the background helper and the relay style (the default); the gateway's hardening becomes the gateway edge, serving REST; the frame binding is retired. |
| B — client SDK, direct dial (#1312) | Each client process selects a transport from the target record — Unix, SSH (`ssh -W` over a persistent master) or HTTPS against the same gateway as A — in place of the hardcoded Unix connect. | No local relay process; transports are in-process. | The credential is read by each client process (an ADR-008 amendment); hooks load a transport lazily; each process opens its own channel. | Becomes the direct style, an advanced option; its MCP-bridge background agent and `server connect --agent` give way to the helper. |
| C — server-native network API (#1311) | The daemon gets an optional network listener with a resource-shaped REST API; a dedicated client-side agent process long-polls for workspace calls; SSH tunnels HTTP to that listener. | One network protocol for every remote kind; no gateway or connector process. | TLS and HTTP parsing move into the process that holds the vault, which amends ADR-008 invariant 6 at its root; a second, resource-shaped public API to keep. | Its REST API becomes the public network contract (U9) and the only HTTP protocol (U21); its listener becomes the native edge, an owner opt-in; its pull agent gives way to the helper. |

**Retired before release.** The HTTPS binding of the control frames (A and B), so that one
schema set, one conformance kit and one client library serve HTTP; keeping it beside REST would
have meant two HTTP protocols and two conformance surfaces. B's background agent in the MCP
bridge and C's `finishup agent run`, both replaced by the one helper, which also serves users who
only run the CLI.

**Rejected.**

- *The local service forwards (#946).* It needs a full local vault and ledger just to proxy, and
  gives no real split.
- *The server offers MCP over HTTP to hosts.* It loses the bridge↔hook records, Cursor roots
  (ADR-010), the availability latch, the publish guard and timeout recovery, and host support for
  remote MCP with headers is undocumented.
- *Remote targets as a preview with closed coverage gaps for every workspace read.* The maintainer
  required full plug-and-play instead.
- *Ship workspace evidence ahead of the call.* Infeasible for reviewer reads, where the model picks
  the paths, and for work that runs after the call returns.
- *A sixth ADR-009 channel under service policy.* It does not fit a client machine that has no
  local service.
- *A new environment variable or argv token for the target.* It breaks the registration
  classifiers, the entry fast paths and the configuration allowlist, and misses bare-`PATH` Codex
  hooks and agent-shell CLI calls.
- *A sticky per-session target record for hooks.* Another store on the hook hot path, and it can
  drift from the bridge.
- *A per-repository server file.* A repository could redirect its own ledger traffic.

## Open questions for the maintainer

1. **Task-input folders that exist only on the client** (recorded 2026-11-07, refusal-guide
   review; **closed 2026-11-07 by maintainer decision, "client list admits them"**). A server's
   task-input roots came only from its own privacy policy, set with `finishup privacy input-roots
   add <folder>`, a `server_host` command, so a folder that exists only on the owner's computer
   could not be admitted for a server on another machine, in either outside-read mode. Decision:
   `finishup server folders add NAME FOLDER`, run on the client at the trusted console, also
   admits FOLDER as a task-input root for that server's claim-bound sessions, in both modes; the
   record is never sent to the server; in `local` mode the server's own admitted roots still
   apply as for a local service, and in `listed` mode only the record admits outside reads; the
   server's other privacy controls still apply on the server; and a claim-bound session defers
   to the agent the decision on inputs the server's policy does not cover, every other session
   unchanged. Implemented as decision 5's "The client's list admits task inputs" paragraph. The
   `task_input_outside_not_admitted` sentence and its MCP short form, the terminal interface's
   privacy line, `privacy input-roots`' help and its `requires_server_host` line now name
   `finishup server folders add NAME FOLDER` on the client machine as a remote server's way in.
2. **How many files listed mode kept back, on the receipt** (recorded 2026-11-07, refusal-guide
   review; **closed 2026-11-07 by maintainer decision, "add the count now"**). The count was
   frozen (the check change's `outside_inputs_not_listed`, the case object's
   `declared_tests_not_listed`) and reached only the diagnostics, because every receipt-document
   schema (1.0.0 to 1.3.0) shipped in v0.3.0. Decision: the receipt says how many task inputs
   and declared tests listed mode kept back. Implemented without amending a released file: the
   evaluation carries the bounded counts (`OutsideReadsKeptBack`, each 0 to 64, at least one not
   zero, clamped) beside its `outside_reads_not_listed` code; the check records them on the new
   check-recorded 1.7.0 (1.6.0 plus the optional `outside_reads_kept_back`, chosen exactly when
   it is present, so every other check keeps its bytes), because a receipt is built from the
   ledger alone; the receipt's live `outside_reads_not_listed` gap carries them as `kept_back`
   on the new receipt-document 1.4.0 (1.3.0 plus that optional member, admitted only beside
   that code on a live gap), which the version manifest now names; receipt-result 1.5.0, still
   unreleased, was amended in place to carry receipt-document 1.4.0. The gap's detail opens with
   one fixed line, "N task inputs and M declared tests outside the folders this server may read
   were kept back.", then the owner's two ways out, so the JSON, markdown and text receipts, the
   CLI receipt (which also prints the line for a JSON receipt), the terminal interface (which
   shows either) and the MCP receipt all say the number. An MCP receipt, paged or not, reaches
   the agent as the receipt itself on both channels (its canonical JSON on the text channel; a
   delivery page's with the handle first), so the number travels in the gap's `detail` and
   `kept_back` for a JSON receipt and in `human_text` for markdown or text, and a paged receipt
   reassembles to it; the compact MCP receipt summary, which also carries the line as a required
   part, is only the fallback when that canonical copy cannot be encoded. A check result (the
   CLI's check output and the MCP check summary) still names the code without a number: its
   schema is unchanged.
3. **Hook content on a remote server** (recorded 2026-11-07, observation review; **closed
   2026-11-07 by maintainer decision, "Send to every server"**). Over a claim-bound connection
   the client's hooks send the native content chunks they captured (prompts, agent messages, tool
   inputs and outputs, which can name absolute paths and hold files the agent read outside the
   project and outside listed folders) unchanged; only the workspace locator is replaced by the
   connection's handle. The alternatives were to withhold content chunks on claim-bound
   connections until the owner consents to content for that server, or to withhold from a
   `listed`-mode server, whose owner chose to limit what it reads outside the project
   (decision 5), the content that names or holds files outside its listed folders. Decision: the
   chunks are sent unchanged to every remote server, whatever its outside-read mode, and the
   owner is told before confirming: disclosure 2 names them, and a target confirmed under
   disclosure 1 sends nothing until the owner confirms again. A `listed`-mode server therefore
   also receives content that can name or hold files outside its listed folders, because the
   outside-read mode limits only what the server reads, not what the client's hooks deliver; the
   owner keeps that content on the client with the client's own observation consent and content
   profiles. Implemented as decision 12's "Captured content travels as a local service receives
   it" paragraph and decision 8's disclosure; PRIVACY.md, the servers guide and INTERFACES say
   the same.

## Founder questions answered by the maintainer (2026-11-05)

1. **How complete must a remote target be?** Full plug and play: check-time change capture,
   reviewer file reads, task inputs, approved checks and observation work end to end through the
   workspace agent. Gaps appear only as honest, typed outcomes when no agent is reachable.
2. **What does "several local servers on different ports" mean?** Both named local roots, each
   with its own service, and HTTPS servers reached on localhost ports (the `local_port` kind).
3. **How is the separation delivered?** Three pull requests, one per way of doing the separation,
   each complete and mergeable on its own; every decision other than the topology is identical in
   all three. *Superseded on 2026-11-08* (U1, U15, U16): one unification, in which the three ways
   become options, delivered as stacked pull requests (*Delivery in layers*).

The "REST API" question is answered by the 2026-11-08 decisions: approach C's resource-shaped REST
API is the public network contract (U9) and the only HTTP protocol (U21); approaches A and B's
binding of the control frames to HTTPS is retired. The remaining proposals of this ADR — the
classification of the network hop (decision 8), strict route on remote targets (ADR-018
amendment), SSH as owner-equivalent (decision 9) and version lockstep with its compatibility
window (decision 10) — stand as Proposed until the layer that uses each lands.

## Maintainer decisions of 2026-11-08

The maintainer accepted the unified design on 2026-11-08. The decisions this ADR depends on:

| # | Decision |
|---|---|
| U1 | The three approaches are not exclusive; all become options in one product, chosen by the server's type and the user's choice. |
| U2 | Pre-packaged profiles: the default stays full local (today's behaviour, byte for byte); adding an SSH or web server runs a handshake in which the client learns what the server offers and configures itself to conform. |
| U3, U4 | Levels of how much is on the server are a per-server setting with a per-repository override; a new level keeps a copy of the code on the server (L2). |
| U5 | Consent is asked when a connection starts, according to what the server needs, and asked again when a later handshake widens it. |
| U6, U10, U19, U20 | At L2 code reaches the server as git data the client sends; the copy holds git-visible files minus secrets (patterns plus a content scan, each held-out file named on the receipt); forgetting deletes the copy and the excerpts derived from it. |
| U7 | Approved checks run on the user's computer. |
| U8, U9 | This repository builds the core only; the core can connect to a specific official URL. The public network contract is C's REST API. |
| U11 | Retention: on a self-hosted server the user chooses; on an official service the service's policy offers the options. |
| U12 | One background helper per server for every connection style. |
| U13 | The server side offers both HTTP edges (separate gateway process, built-in listener); the server owner picks; the maintainer owns the security review of the built-in listener. |
| U14 | The repository egress hold (round 5) is included (layer 2). |
| U15, U16, U17 | The build starts from approach A and ports B and C in; delivery is stacked pull requests; everything is designed now and implemented as one unification. |
| U18 | Compatibility window (decision 10). |
| U21 | Relay is the default style for SSH and HTTPS, direct an advanced option; REST is the only HTTP protocol and the frame binding is retired. |

Questions left to the layers that use them, each decided in this ADR's amendment or the new ADR of
that layer: reversing a repository-level override; downgrading from L2 to L1 and what happens to
the copy; interrupted uploads, links, hard links and case collisions in an export, hostile packs,
exclusion-policy changes and key rotation during an upload; and older helpers and MCP bridges
still running across an upgrade. Acceptance is recorded per host (Codex, Claude Code, Cursor) ×
surface (CLI, MCP, hooks, terminal interface, receipts) × operating system (macOS, Linux, WSL 2)
in layer 7.
