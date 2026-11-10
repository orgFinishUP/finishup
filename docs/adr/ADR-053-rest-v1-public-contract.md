# ADR-053 — REST v1: the public network contract, its two server edges and the one client

**Status:** Accepted for [issue #1308](https://github.com/orgFinishUP/finishup/issues/1308), layer 5
of the unified client/server model ([ADR-051](ADR-051-client-server-cut-and-server-targets.md),
*Delivery in layers*): the REST v1 public contract, the gateway and native server edges behind one
backend interface, API keys with scopes and principals, HTTPS discovery and the official origin
preset, the compatibility window, the one REST client library with its frame-to-REST mapping, and
the opening of the `https` and `local_port` kinds. It is the decision record design v2 names for
the public network contract; the authorization every connection runs under stays in
[ADR-052](ADR-052-shared-authorization-generations-gate-and-consent-envelopes.md), whose decisions
20 to 23 record what layer 5 adds there. Design gates: protocol (a public network contract and
seven new schemas), privacy/egress (HTTPS as a second network edge, and the unauthenticated
discovery exception), storage (the server's API key file and its audit) and release/packaging
(starlette, uvicorn and h11 as direct dependencies, all three already in the lock through `mcp`).
Maintainer acknowledgement: the maintainer accepted the unified design on 2026-11-08 (U8, U9, U13,
U18 and U21 in ADR-051) and asked for its delivery as stacked pull requests; under the intake rule
in `AGENTS.md` that explicit request is the design-gate acknowledgement for this scope. It grants
no runtime, credential, disclosure or destructive-action authority.
**Implemented by:** the `src/finishup/rest/` package (`contract.py`, the wire contract both sides
share; `contract_models.py`, its schema contracts; `api_keys.py`, `backend.py`, `app.py`,
`listener.py`, `audit.py`), `src/finishup/gateway/` (`backend.py`, `run.py`),
`src/finishup/service/rest_native.py`, `src/finishup/cli/rest_server.py` (`service api-key` and
`service rest run`), `src/finishup/client/rest_client.py`, `src/finishup/client/rest_stream.py`,
`src/finishup/client/rest_discovery.py`, `RestUpstream` in `src/finishup/client/helper.py`, the
REST dial in `src/finishup/service/client.py`, the HTTPS `server add`, `login` and `logout` flows
and the official preset in `src/finishup/cli/server.py` and `src/finishup/client/server_folders.py`,
the `rest-*` schemas under `schemas/service/` with `fixtures/service/rest.case.json` and
`fixtures/service/rest-api-manifests.case.json`, and the conformance kit in
`tests/conformance/rest/`.
**Amends:** ADR-051 (decisions 3, 5, 7, 9 and 10, *Topology*, *Built in layer 5*), ADR-052 (gate
steps 4 and 6; decisions 20 to 23) and ADR-008 (the REST edges, the discovery exception and who
reads an API key). **Relates to:** ADR-002 (an operation id is the control rpc id), ADR-030 (the
unknown-outcome continuation of a call whose answer is lost) and pull requests #1311 (C, whose REST
API this is), #1313 (A, whose gateway hardening and HTTPS client fixes are ported) and #1312 (B).

## Context

Layers 1 to 4 kept `https` and `local_port` closed. Design v2 (U9) makes approach C's
resource-shaped REST API the one public network contract, served by either HTTP edge the server
owner runs (U13): a separate gateway process without the vault (approach A's hardening) or a
listener inside the service (approach C). Approaches A and B had bound the raw control frames to
HTTPS; that binding was never released and is retired (U21), so one schema set, one conformance kit
and one client library serve HTTP. SSH keeps raw control frames over the forwarded owner-only
socket (ADR-052 decision 15), which is owner-equivalent and not a public contract.

Everything a client already does over a control connection (the hello and its claim, calls,
cancels, pushed workspace calls and their replies, the consented profile revision on every request)
has to cross REST without a second authorization model: the gate, the generations and the
per-frame checks of ADR-052 hold unchanged. A server reached over HTTP also needs what the
owner-only socket gave for free: an authenticated caller with bounded authority, a compatibility
rule for releases that are not in lockstep (U18), and a way for an official hosted service (built
in another repository, U8) to prove that it speaks the contract.

## Decisions

### 1. One HTTP protocol, served by either edge

REST v1 (path `/v1`, major `1`) is the only HTTP protocol (design v2 section 1.1). Bodies and
answers are canonical JSON; every answer carries `cache-control: no-store`; a server never
redirects (no trailing-slash redirect) and a client never follows a `3xx` (`remote_incompatible`).
A call's body is the method's existing control request body and its answer the existing
control-result body, byte for byte, so no workflow contract is redefined. `rest.contract` (SHARED,
standard library and `finishup.protocol` only) holds everything both sides must agree on: the
routes, header names, scopes and their method lists, the key token shape, the claim header and its
principal namespace, the revision header, the closed `rest-error` reasons and every REST document.
A client imports nothing else of `finishup.rest`.

### 2. Routes and headers

Every route is relative to the target's base URL, its path prefix included.

| Route | Auth | Answer |
|---|---|---|
| `GET /.well-known/finishup` | none | `rest-discovery` 1.0.0: `product: finishup`, `rest_majors: ["1"]`, `api_manifests`, `auth: ["api_key"]`, `profile_endpoint: "/v1/server"`, `official: false`. No release, instance id or key. |
| `GET /v1/server` | key | `server-profile` 1.0.0 (ADR-052 decision 9) with the caller's `key: {id, scope, principal}` and `edges: ["rest-1"]` |
| `GET /v1/session` | key, revision | `rest-session` 1.0.0: the service status, the workspace binding and handle for the request's claim, the revision admitted |
| `POST /v1/{method}` | key, revision | the control-result body byte for byte with `finishup-outcome: ok` or `error`; `202` with `rest-operation` and `location: /v1/operations/{id}` while the call still runs after `wait_ms` (at most 25,000) |
| `GET /v1/operations/{id}` | key, revision | a long-poll of that operation, answered as the call |
| `DELETE /v1/operations/{id}` | key | `204` (cancel) |
| `POST /v1/agents` | key, revision, claim | `201` `rest-agent` 1.0.0: the agent id, the handle it answers for, a 60-second lease |
| `GET /v1/agents/{id}/work` | key, revision | `rest-agent-work` 1.0.0: the agent's pending `workspace_call` frames, oldest first |
| `POST /v1/agents/{id}/replies` | key, revision | `202` (one `workspace_reply`) |
| `DELETE /v1/agents/{id}` | key | `204` |

Request headers (lowercase): `authorization: Bearer fuk_<12 hex>_<43 base64url>`;
`finishup-api-manifest` (every `/v1` request, decision 5); `finishup-server-profile:
<issuer>.<revision>.<sha256:hex>` (every `/v1` request but `GET /v1/server` and the two `DELETE`
routes, which are reverse paths); `finishup-workspace-claim:
<git_common_root|directory>:sha256:<hex>:sha256:<hex>`; `finishup-client-kind` (absent is `cli`);
`finishup-service-instance` and `finishup-service-generation` (on calls, from the session);
`finishup-operation-id` (the control rpc id, idempotent per key); `finishup-deadline-ms`;
`finishup-route-profile`; `finishup-host-profile`; `finishup-agent` (on a call: the agent the
calling connection registered, layer-5 review). Response headers: `finishup-outcome`,
`finishup-operation-id`, `finishup-service-instance`, `finishup-service-generation`,
`finishup-workspace-handle` and `location`.

### 3. The order of checks, and the refusals

On every request, first refusal wins:

1. an `Origin` header is present: `origin_forbidden` (browsers and DNS rebinding);
2. the unauthenticated budget, for discovery (whatever its method) and for every refusal of a
   request no key authenticated, whatever its reason (a duplicated `authorization` header's
   `header_invalid` included): token buckets per peer address (20, refilled 5 per second) and in
   total (200, refilled 50 per second); over either, `rate_limited` and nothing more is read;
3. the bearer key: `api_key_invalid`, `api_key_revoked`, `api_key_expired`, or
   `server_keys_unusable` while the server's key file cannot be used;
4. the client's API manifest: `header_invalid` when absent, `api_manifest_unsupported` when this
   server does not serve it;
5. the consented profile revision: `header_invalid` when absent, `server_profile_changed` when it is
   not the revision the service issues now, before any work (ADR-052 decisions 10 and 21). The
   routes ask the backend (`RestBackend.admit`: the native edge compares the issued revision, the
   gateway sends a hello naming only that revision) **before they read a body** (a call, an
   agent's registration, a reply), so a stale call is never answered `202` or read whole; the
   session, the dispatch and the registration check again where the work is done;
6. the key's scope as a method allow-list: an out-of-scope call is answered with the control
   protocol's own `method_forbidden` result and never dispatched;
7. the claim, namespaced by the key's principal (decision 6) before the backend sees it;
8. the per-key caps: 32 pending operations (`operation_limit`) and 16 agents (`agent_limit`); a
   registration holds its agent slot from before it reaches the backend until it is registered or
   fails, so concurrent registrations never pass the cap.

A call naming `finishup-agent` is sent to that agent first, as a control connection's call goes to
the agent its own hello declared (design v2 section 8.5): the agent must be the caller's own, live,
and registered for the call's claim and revision (`agent_unknown`, or `server_profile_changed`
for another revision). The native edge dispatches the call under that agent's hub channel
(`live_call_scope`); the gateway writes it on the agent's own control connection and reads its
result there. That connection is shared by the agent's calls, so a `DELETE` that reaches it after
the service answered the call is harmless: the control session admits a cancel naming one of its
recently answered calls (it remembers the newest 256) as a no-op and never interrupts an answer it
is writing, so the agent and its other calls go on; a cancel naming no call of the connection is
still `correlation_mismatch` (layer-5 review, second round). Once a call's frame reached the
service, a result that cannot be read (no answer to the cancel in time, the connection lost) is
`request_timeout` (outcome unknown), never `request_cancelled`. An agent's handle is let go when the agent is ended (`DELETE`, its lease, its
key, the service's side).

A start needs a claim (`workspace_claim_required`) and a `workspace_ref` must be a `client:` handle
(`frame_invalid`): no path on the client is ever named over the network. A transport or
authentication refusal is a `rest-error` document with its closed reason; a dispatched call's own
outcome (a workflow error, `vault_locked`, `method_forbidden`) is the control-result body, never
one of these.

| Status | `rest-error` reasons |
|---|---|
| 400 | `frame_invalid`, `header_invalid` |
| 401 | `api_key_invalid`, `api_key_revoked`, `api_key_expired` |
| 403 | `origin_forbidden`, `workspace_claim_required` |
| 404 | `route_unknown`, `operation_unknown`, `agent_unknown` |
| 405 | `method_not_allowed` |
| 409 | `server_profile_changed` |
| 412 | `api_manifest_unsupported` |
| 413 | `frame_too_large` |
| 429 | `operation_limit`, `agent_limit`, `rate_limited` |
| 500 | `internal_failure` |
| 503 | `service_unavailable`, `server_keys_unusable`, `workspace_agent_unavailable` |

Operation ids are idempotent per key and admitted at most once: an id already admitted answers with
that operation; a finished operation's answer stays retrievable for 120 seconds (at most 64 per key
and 1,024 in all, 64 MiB of answers); an id whose answer was dropped stays spent for 15 minutes,
so a late duplicate is `operation_unknown`, never dispatched again.

### 4. Documents and schemas

Seven documents, all 1.0.0, generated under `schemas/service/` from `rest.contract_models` through
the schema generator and the resource ripple: `rest-error`, `rest-discovery`, `rest-session`,
`rest-operation`, `rest-agent`, `rest-agent-declaration` (the `POST /v1/agents` body: the
operations the agent answers, its largest reply and its `role`, `connection` or `background`) and
`rest-agent-work`, whose every call is exactly the control wire's `workspace_call` frame (its
schema is that branch of `control-result` 2.10.0, and the parser validates each call the same way,
so a server can never hand a client an undefined call; layer-5 review). They carry the new artifact
role `network-control`. `rest.contract` is the runtime parser (no pydantic on the client's path); a
conformance test keeps parser and schemas agreeing on the golden vectors in
`fixtures/service/rest.case.json`, with rejections (a non-empty work and three malformed ones
included). No document
carries a path, a host name, an owner-typed label or a key. A receipt's frozen version slice
(64 entries, bound by receipt-document 1.0.0 to 1.4.0 and receipt-result 1.5.0) leaves the `rest-*`
family out: those documents describe no operation a receipt records, while the version manifest
still lists them.

### 5. The REST API manifest and the compatibility window (U18; design v2 question Q5)

A release's **REST API manifest** is `sha256` over `yoetz/rest-api-manifest/v1` NUL and the
canonical list of `[path, sha256]` of every schema in the transitive `$ref` closure of the REST
root schemas (control-request and control-result 2.10.0, the seven `rest-*` documents,
`server-profile` and `service-status`), read from the packaged schema manifest. Two releases with
the same API manifest speak a byte-identical public contract.

- Discovery lists the manifests a server serves; every `/v1` request names the client's own in
  `finishup-api-manifest`; a server refuses one it does not serve with `412
  api_manifest_unsupported` before any work, and the client names it `remote_incompatible`. A
  client also requires its own among those discovery lists before it asks for a key.
- **The core server serves exactly its own (a window of one).** Self-hosted servers keep release
  lockstep on the public contract; two releases whose REST contract is byte-identical
  interoperate.
- A server, the official service in particular, may serve several manifests, and must then pass
  the frozen vectors of each: `fixtures/service/rest-api-manifests.case.json` records, per REST
  contract version, its manifest digest and its request and response vectors; a test pins this
  release's digest, so a REST schema change cannot land without a new entry, and the conformance
  kit replays the vectors of every manifest a server advertises (cross-version conformance).
- Over SSH the control hello keeps the full schema-manifest lockstep (ADR-051 decision 10). Over
  REST the mapping writes the client's own schema manifest into the hello result it builds:
  compatibility there is the API manifest.

### 6. Scopes and principals

An API key carries a scope that the edge enforces as a method allow-list (ADR-051 decision 9); the
daemon's client-kind gate stays as a second layer.

| Scope | Methods |
|---|---|
| `agent` | `start`, `publish_work`, `check`, `respond`, `status`, `receipt`, `service_status`, and `observation_ingest` on a request with a claim |
| `operator` | `agent` plus `project`, `review`, `import_codex_jsonl`, `observation_status`, `privacy_get_setup`, `privacy_get_effective`, `privacy_pending_list`, `privacy_receipts_list`, `privacy_receipts_get`, `privacy_propose_policy`, `privacy_tighten_policy` and `service_lock` |
| never over the network | `service_stop`; `backup_*`, `restore_*`, `migrate_*` and `integration_*`; `observation_pause`, `observation_resume`, `observation_revoke`; `server_profile` (it is `GET /v1/server`); the human-control and secret channels |

Each key has a **principal** (`p_<16 hex>`). A REST claim is namespaced by its key's principal
(`yoetz/claim-principal/v1`) before any backend sees it, identically on both edges; an SSH-control
claim is not namespaced (SSH is owner-equivalent). So an HTTPS client and an SSH client of the
same repository reach different task namespaces on the same server, and two keys with different
principals never claim each other's workspaces. A rotated key keeps its predecessor's principal.
This is groundwork for multi-owner hosting (design v2 question Q7), not that hosting itself (see
*Honest limits*).

### 7. API keys

The server keeps its keys in its own state, `<state dir>/rest/api-keys.json`
(`yoetz.rest-api-keys/1`, owner-only canonical JSON, edited under an exclusive `flock` and renamed
into place): per key its id (12 hex), the owner's label, its scope, its principal, when it was
created, when it expires and when it was revoked, a random salt and `sha256(salt ‖ secret)`,
compared in constant time. The key itself (`fuk_<id>_<secret>`) is never stored. At most 256 keys.
Either edge re-reads the file when it changes: a revoked key fails its next request and its
agents end.

Server-host commands (scope `server_host`):

- `finishup service api-key create (--label L --scope agent|operator | --rotate KEY_ID)
  [--expires-in-days N] [--output-file F]` shows the key exactly once, on the trusted console, or
  writes it to a **new** owner-only (0600) file `F` (never over an existing file). The output file
  is made first; a new key that could not reach its owner (not shown, not written) is revoked at
  once, so no active key is left that nobody holds. `--rotate` keeps the rotated key's principal,
  label and scope, leaves the old key valid until it is revoked, and says to log its clients in
  with the new key and then revoke the old one.
- `finishup service api-key list [--json]` shows each key's id, label, scope, principal, state and
  times, never a secret.
- `finishup service api-key revoke KEY_ID` is `create`'s reverse.

Refusals (closed tokens, fixed remedy text, nothing echoed): `api_keys_damaged`, `api_keys_unsafe`,
`api_key_unknown`, `api_key_label_invalid`, `api_key_scope_invalid`, `api_key_expiry_invalid`,
`api_key_limit`, `api_key_output_exists`, `trusted_console_required`, `api_key_not_shown` and
`api_key_output_failed`.

### 8. Two edges behind one backend interface (U13, design v2 section 8.4)

`rest.app` owns everything the edges share: authentication, the unauthenticated budget, scopes, the
principal namespace, the revision and API-manifest checks, the operations table (idempotent ids,
long-polls, cancellation, retained answers) and the agents table (leases, queues). A backend
(`rest.backend.RestBackend`) owns only how a request reaches the service; every backend method
takes the claim already namespaced and the consented revision, and refuses a revision that is not
the server's current one before anything is keyed, registered or dispatched.

`finishup service rest run --listen HOST:PORT (--tls-cert F --tls-key F | --behind-proxy) [--edge
gateway|native]` (`server_host`) runs one edge in the foreground; the owner's supervisor runs it,
and Ctrl-C or SIGTERM stops it. Nothing starts a listener on its own.

- **Gateway** (the default; `finishup.gateway`, side GATEWAY: SHARED modules and
  `service.client` only). A separate process of the service's own user with no vault, no
  installation MAC and no storage or policy authority. Every REST request re-enters the service
  over its owner-only control socket as an ordinary, peer-authenticated control connection
  (`gateway.backend.ControlSocketBackend`): a session is a hello naming the request's claim and
  revision; a call is its own claim-bound connection bound to that revision, its cancel written on
  that connection after its call frame, never before; an agent is one long-lived claim-bound
  connection whose hello declares the agent. A dropped connection ends that agent (its next poll is
  `agent_unknown`), so the gateway follows a service restart or a new generation. The service is
  started on demand for a client's request, never for a `background` agent.
- **Native** (`--edge native`; `service.rest_native.NativeBackend`). The command runs this root's
  service itself in the foreground with the listener in its event loop: the owner's opt-in. The
  process that holds the vault is then on the network, and its security review is the owner's
  (U13; ADR-008 amendment, layer 5). A claim is keyed with the installation MAC exactly as a
  claim-bound hello is; a claim the service cannot key now (a locked vault) makes its calls answer
  `vault_locked`, never served unbound. The native service does not stop for idleness while it
  listens (idle relock is unchanged). A service already running refuses it
  (`service_already_running`: stop it first, or use the gateway beside it).

Listener rules, the same for both (`rest.listener`): TLS 1.2 or later, and the key file must be the
owner's own and owner-only (`rest_tls_unusable`); plain HTTP only with `--behind-proxy`, only on a
loopback address, for a TLS-terminating proxy on the same host (`rest_tls_required`,
`rest_proxy_not_loopback`); `--listen` takes an IP address or `localhost` and a port, 0 picking a
free one (`rest_listen_invalid`); an address that cannot be bound is `rest_listener_unavailable`;
another `--edge` is `rest_edge_invalid`. Open connections are capped at 256 in all and 64 per peer
address, shrunk to a quarter of the process's descriptor budget, and a connection over a cap is
closed before TLS; a connection completes TLS and a request head within 10 seconds and a body
within 120 seconds (a long-poll being answered has no such bound). No access log, no `Server` or
`Date` header, no trust in forwarded-for headers.

**The audit.** `<log dir>/rest-audit.jsonl`: owner-only canonical JSON lines of closed tokens (the
time, the edge, the event, the route, the status or refusal reason, the key id once a key
authenticated, and for a call its control method, outcome and duration), never a body, a header
value, a key, a label, a path, a host or an address. It is renamed to `rest-audit.jsonl.1` at
8 MiB, and an unauthenticated refusal is written at most once per reason per 60 seconds, with a
`suppressed` count of those not written, so a client without a key cannot grow the server's disk.

### 9. Discovery and the official origins (design v2 sections 2.1, 2.4 and 8.8)

**Discovery** is one bounded `GET /.well-known/finishup` over a TLS connection the owner's trust
already verified, with no credential, made by `server add` before the key is asked for (ADR-008's
narrow exception). The client reads at most 4 KiB, parses strictly, and requires `product:
finishup`, major `1`, `api_key`, its own API manifest and exactly the fixed same-origin profile
route `/v1/server`; anything else is `remote_incompatible`, and the key is never asked for. The
server's `official` claim is never counted, and the disclosure uses only this release's own words,
never the server's prose.

**Official origins.** `client.server_folders.OFFICIAL_ENDPOINT_ORIGINS` (a tuple of
`OfficialOrigin`: scheme `https`, host, port, 443 by default, and path prefix) replaces layer 1's
`OFFICIAL_ENDPOINT_HOSTS`. It is release-pinned, reviewed by the maintainer and **empty**: no
official FinishUP service exists yet. A target is official only when its kind is `https`, its base
URL matches a listed origin (scheme, lowercase host, port, and a path at or beneath the prefix) and
it trusts the system certificate store (no `--ca-file` or `--tls-pin`). Being official gives three
things: `finishup server add official` (name `official`, no address) fills in the URL of the first
listed origin, and with the list empty it refuses `official_endpoint_unavailable` before anything
is asked; the outside-read default `local` while the owner recorded no mode (a mode the owner
recorded survives any change to the list; ADR-051 decision 5); and the label "FinishUP official
service". It never skips the consent.

### 10. The one REST client library (design v2 section 8.4)

`client.rest_client.RestTransport` carries every request this computer sends over HTTPS: the
direct style's connections, the helper's relay and its background agents, discovery and profile
fetches.

- **TLS as the owner recorded it.** `--tls-pin sha256:<hex>` checks the `sha256` of the leaf
  certificate's DER right after the handshake, before any request byte, and replaces chain and
  host-name validation, as the owner chose; `--ca-file F` trusts that CA only, with the host name
  checked; otherwise this computer's system store (Python's default verify paths). A CA file that
  cannot be read, or holds no PEM certificate, sends nothing. The CA file is read once per
  transport (`load_trust`): those bytes are both the TLS context and the identity the transport
  reports (layer-5 review).
- **No proxies and no redirects.** Proxy variables are ignored and a `3xx` is never followed
  (`remote_incompatible`), so the hop goes only where the record says and no credential is carried
  elsewhere.
- **Bounded answers.** A body past the largest control frame plus 64 KiB is refused unread.
- **The key** is read off the event loop, one read at a time (A-KEYRING-LOOP), on a daemon thread
  of its own (never the loop's default executor, so a blocked read holds neither the loop's
  shutdown nor the process's exit), from where the record says it lives now (A-CRED-STALE); a store
  that does not answer within the caller's budget is `remote_auth_failed` for that attempt. At most
  one read is outstanding in a process: a caller that comes while one runs (a locked keyring's
  prompt, say) waits for it to end within its own budget and then reads afresh, or fails
  `remote_auth_failed`; it never starts a thread of its own, so abandoned reads never accumulate
  (layer-5 review, second round). A target with no key is `remote_auth_failed` before any
  byte is sent: that is ADR-052's gate step 6, made where the key is read (ADR-052 decision 20).
- **Closed failures**, never naming a host, URL or body: the TLS identity refused
  (`remote_identity_changed`), no connection or a timeout (`remote_unreachable`), the key refused
  (`remote_auth_failed`), not a FinishUP REST v1 server of this contract (`remote_incompatible`:
  404, 412, a `3xx`, a document this release refuses), no service answering there
  (`remote_service_not_running`, 503).
- **The endpoint identity** the consent binds to is what this client's own trust observed, never
  what the server says: `tls_pin` with the pin, `tls_ca_file` with the `sha256` of the CA file's
  bytes as loaded into the TLS context, or `tls_system_ca`. Every connection made on the owner's
  behalf after the consent (the helper's upstream, the direct style, the helper's profile refresh,
  a `login` check: `RestTransport.for_target(consented=True)`) compares that identity with the
  consented envelope's before any byte is sent: a CA file replaced since is
  `remote_identity_changed` until the owner agrees again with `finishup server use NAME`. Only the
  owner's own `server add` and `server use` fetch a profile unbound, and the identity they record is
  the one their transport loaded.
- **The profile** (`GET /v1/server`) counts only when it is a `server-profile` this release reads
  that names the key that was sent; anything else is `remote_incompatible`.

### 11. The frame-to-REST mapping (design v2 section 8.4)

`client.rest_stream.RestControlStream` is a control stream: a `ServiceClient` reads and writes
ordinary control frames on it (the direct style), and the helper pumps a local connection's frames
through it (the relay style), so **one mapping serves both** and every check of the control path
(the gate before the dial, the authorization before every frame and on its watch, the helper's
per-frame check) holds over REST unchanged. States: `await_hello` → `opening` → `open` →
(`ended`) → `closing` → `closed`.

- **Hello and claim.** The first client frame must be a `control-hello`; one naming a
  `workspace_locator` is never sent anywhere (a path on this computer never leaves it). Otherwise
  `GET /v1/session` with the hello's claim, consented revision and client kind; its answer becomes
  the hello result the service would give. A refusal ends the stream unanswered and names its phase:
  `server_profile_changed` (409), `remote_auth_failed` (401), `remote_incompatible` (404, 412, a
  refused document), `remote_service_not_running` (503), or the transport's phase. A hello that
  declares an agent registers it (`POST /v1/agents`) and starts one work long-poll; every call then
  names that agent (`finishup-agent`).
- **Pushed workspace calls.** Each call a poll returns is written to the client as its
  `workspace_call` frame, in order; each `workspace_reply` the client writes is
  `POST /v1/agents/{id}/replies`. `agent_unknown` (its lease ran out, the service restarted, its
  key was revoked) ends the stream, as a dropped control connection does, and the client connects
  again.
- **Calls.** The operation id is the frame's `rpc_id`; `POST /v1/{method}` carries the claim, the
  revision, the client kind, the service instance and generation, the deadline and the route and
  host profiles; a `202` is long-polled until it answers; `operation_limit` (never dispatched) is
  retried with growing waits within the call's deadline; a `409` is the call's
  `server_profile_changed` error result.
- **Cancellation order.** A cancel always follows its call's `POST`. A `DELETE` sent before the
  server admitted the call changes nothing (`operation_unknown`): whatever order the two answers
  come back in, it is sent again once the `POST` was answered while the call runs (so is one that
  was not answered, at most three times). A call answered done drops its cancel; one still running
  goes on to its own `request_cancelled` result.
- **Reconnect and unknown outcomes.** A `POST` whose answer was lost is sent again with the same
  operation id, at most three times (the server answers the operation it already admitted). When a
  call's outcome cannot be learned (its answer is gone, `operation_unknown`, or the server stayed
  unreachable after it may have been admitted), its result is `request_timeout`: the outcome is
  unknown, the ADR-030 continuation says to repeat it under its original identity, and the stream
  ends. The workflow `request_id` in every body is untouched, so it stays the kernel's idempotency
  key across a helper's or a bridge's restart; the operation id is stable across HTTP retries
  within one stream.
- **Deadlines.** A call's `deadline_ms` is one absolute deadline for all it sends and waits for:
  each request's own bound, each wait between retries and each long-poll's `wait_ms` end with it,
  and no `POST` is sent again after it (the call's result is then `request_timeout`, outcome
  unknown). A request's bound is absolute too: the connect, the TLS handshake, sending the body and
  every piece of the answer together, never a bound per phase (a request given none still ends
  within its connect and read bounds plus 30 seconds), and the call's requests and retries run
  under one outer timeout at the deadline, whatever a transport does with its own bound (layer-5
  review, second round). The caller's own deadline (a hook's, ADR-052 decision 19) still spans
  the whole connection.
- **Authorization before every request.** The stream asks its `may_send` (the direct style: the
  connection's repository-bound admission) and every check `bind` added before each request, the
  agent's registration, every retry and every poll included; once one refuses, nothing more is
  sent. The helper binds each relayed stream to the admission it was opened under and to the
  repository its client named for it: a client that claims a workspace through the helper first
  writes, on that local connection only, the repository key its own admission is bound to (the
  relay binding: `0xFF`, `yoetz-relay/1`, the key; never forwarded, and a claim without it is never
  relayed), and the relay asks that admission bound to that key (`for_repository`) before every
  frame and every request its stream makes on its own. A hold is decided by the repository's key,
  never by the worktrees the everyday record still lists (it keeps eight per repository), so the
  stream's own retries and polls stop on a lapse or a hold without waiting for the client's next
  frame or watch (layer-5 review, second round). A stream a `ServiceClient` dials itself (the
  direct style, the helper's direct-style agents) is bound the same way to its connection's own
  repository-bound authorization.
- **Close (A-STOP-DELETE).** Courtesy `DELETE`s for the agent and for calls still running, bounded
  at one second in all, and never sent once nothing may be sent (this computer is zero-network, or
  the admission lapsed: a `logout` or `login` moves the credential generation); that is asked after
  the close awaited its running requests' cancellation, right before the `DELETE`s, so a logout
  landing meanwhile sends nothing under the key the stream holds; the server ends an agent whose
  polls stop and forgets answers on its own.

Nothing in the mapping logs or raises a host, URL, path or body. "Identical fault vectors" are
tested over direct REST, relay REST and SSH control alike.

### 12. HTTPS and port targets on the client

`OPEN_REMOTE_KINDS == {"ssh", "https", "local_port"}` (an architecture test pins it, and that every
open kind has a transport, a profile source and a runtime). The kinds flipped in the last code
commit of the layer, after every protection existed. `remote_kind_unavailable` now refuses only an
address that names none of the open kinds (`http://`, another scheme).

- **`finishup server add NAME https://HOST[:PORT][/BASE] [--ca-file F | --tls-pin sha256:HEX]
  [--key-file F] [--outside-reads local|listed]`**, and `server add NAME --port PORT [...]` for
  `local_port`. `https://127.0.0.1:P` and `https://[::1]:P` name `local_port`; any other HTTPS
  address, `https://localhost:P` included, is `https`. In order, before anything is written: the
  selection in force, the name, the address and its options (`--key-file` with SSH is
  `credential_not_applicable`; `--ca-file` and `--tls-pin` together are `target_tls_invalid`), the
  name not taken, zero-network (SRV-3); then discovery without a key (decision 9); then the key,
  from `--key-file` (an owner-only file read once) or typed hidden on the trusted console ("API key
  for this server (input hidden): "); then `GET /v1/server` with it (a refused key adds nothing,
  `remote_auth_failed`); then the disclosure, the outside-read question (not for an official
  target) and the typed name; then, under the registry lock, the record, the consent, the key (the
  platform credential store, else an owner-only file) and a credential generation. A server that
  cannot be reached adds nothing: no consent can be given without its profile.
- **`finishup server add official`**: decision 9.
- **`finishup server login NAME [--key-file F]`** (shown in help): `https` and `local_port` only
  (`credential_not_applicable` otherwise); zero-network refusal first; the key is checked with the
  server before it is kept: a refused key, an identity that does not match the recorded trust or
  another contract stores nothing and says why; a server that does not answer keeps the key "not
  verified yet". The profile is validated before anything changes (a document this release cannot
  use stores nothing). Then, in one registry-locked step on the record as stored now (SRV-12),
  first the profile cached for the previous key is removed and the credential generation bumped
  (every connection under the old key ends, O8), and only then the key is stored, the record's
  `credential` written and a verified key's fetched profile recorded. Until a profile fetched with
  the key stored now is compared with the consent, the consent step refuses
  (`server_profile_changed`) and nothing is sent, so a record or profile write that fails after the
  key was stored never leaves it paired with the previous consent (that failure names `server
  login` and `server use`); a key that was not verified stays so until its own profile is fetched
  and compared (`finishup server use NAME` once the server is up, or the helper's refresh). The
  helper is stopped whatever happens once the previous key's profile was forgotten
  (A-CRED-STALE). The consent is bound to the key's
  id and principal, so a new key (a rotation included, though it keeps the principal) says to
  agree again with `finishup server use NAME` (ADR-052 decision 23).
- **`finishup server logout NAME`**: offline; under the registry lock, deletes the key the record
  names now, writes the record and bumps the credential generation; then stops the helper.
- **Base URLs** never hold a `.` or `..` path segment (`target_url_invalid`), and an official
  origin never matches one: the client library resolves such a segment away before sending, so
  the request would leave the recorded prefix.
- **Styles.** Edge `rest-1` offers `relay` and `direct`; `finishup server set NAME --style
  relay|direct` covers HTTPS and port targets. In the relay style (the default) only the helper
  reads the API key; in the direct style each dialing process (hooks, the MCP bridge, CLI commands)
  reads it itself, as `server set` says (ADR-008 amendment, layer 5).
- **The helper** serves every remote kind: for HTTPS and port targets its upstream is
  `RestUpstream` (one warm TLS transport shared by every relayed connection; the key reloaded when
  the credential generation moves), its profile refresh is `GET /v1/server`, and it never starts
  the server's service (the server's edge does). `server connect`, `disconnect` and `test` use the
  same helper runtime as SSH; `server status` shows `target.connection` (`style`,
  `styles_offered`, `helper`) for these targets too.
- **The terminal interface** still adds only a server on this computer: an HTTPS server is added
  with `finishup server add` in a terminal, where the key is typed.

### 13. The conformance kit (design v2 section 6)

`tests/conformance/rest/` is a black-box kit any FinishUP REST v1 server can run with a test key
(`FINISHUP_REST_URL`, `FINISHUP_REST_KEY` for an `operator` key, optional
`FINISHUP_REST_AGENT_KEY`, and `FINISHUP_REST_CA_FILE` or `FINISHUP_REST_TLS_PIN`), so the official
service's repository can prove compatibility. Without a URL it provisions, in a fresh 0700 folder
beneath the home directory, a throwaway CA, an isolated server root of the checkout with a
passphrase vault, an operator and an agent key, and runs both edges on free loopback ports over
real TLS; every process it starts is stopped by its own PID. Cases: minimal discovery with no key;
refusals in order (`Origin`, no key, a wrong key, an unsupported API manifest); the caller's key
in the profile; a session and calls bound to the consented revision (a stale one refused with 409);
idempotent operation ids and `operation_unknown`; scope as a `method_forbidden` result; an agent's
register, poll and end; an oversized body; and the frozen vectors of every API manifest the server
advertises.

## Honest limits

1. Over REST the server sees a key, not a person: an API key is a bearer credential limited to its
   scope's methods, and anyone holding it can use them until it is revoked or expires. On the
   client any process running as the same user can read the stored key (ADR-051 decision 7).
2. In the direct style every dialing process reads the key; the relay style keeps it in the helper
   alone. The style is the owner's choice and is not an authorization change.
3. The native edge puts the process that holds the vault on the network; its security review is the
   server owner's, and the gateway is the default.
4. Principals namespace claims, but a `status` or `receipt` call that names a task id is not yet
   fenced per principal: multi-owner hosting is groundwork only (design v2 question Q7).
5. The core server serves one API manifest; only a server that passes each window's frozen vectors
   may serve more.
6. The REST edge and HTTPS targets ran for real on Linux only (the conformance kit, 18 cases, nine
   per edge over real TLS from a throwaway CA, and an end-to-end run of add, use, relay and direct,
   a changed profile, login with a rotated key, logout, the native edge with `--port` and a pin,
   disconnect and remove). macOS and WSL 2 have no recorded run (owner: layer 7). The system store
   is Python's default verify paths: on macOS a python.org Python may need its certificates
   installed; untested.
7. PR CI does not run `tests/conformance/rest/` (it starts real services); a job for it is a
   follow-up.
8. A receipt's frozen version slice holds 64 entries: the next layer that adds operation schemas
   needs a receipt-document version bump.
9. Not built: the server copy and code sync over REST (layer 6); the WAN timing gate and an upgrade
   over running gateways and helpers (layer 7); adding an HTTPS server from the terminal interface;
   OAuth credential sources; an official service (another repository).

## Reverse states

| Way in | Way out | Way to see it |
|---|---|---|
| `finishup service api-key create` (server host) | `finishup service api-key revoke KEY_ID`: its next request fails and its agents end, on either edge; an expiry ends it on its own | `finishup service api-key list [--json]` (state, never a key) |
| `finishup service api-key create --rotate KEY_ID` | `finishup service api-key revoke` of the old key once its clients use the new one (`server login`) | `finishup service api-key list` (same principal, both keys) |
| `finishup service rest run` (either edge, foreground) | Ctrl-C or SIGTERM to the PID its supervisor started (never by pattern); the native edge's service stops with it | the listener's stderr line, `<log dir>/rest-audit.jsonl` |
| `finishup server add NAME https://…` or `--port PORT` (record, consent, key, credential generation) | `finishup server remove NAME` (deletes the key, then the root; a platform store it cannot use now is named, ADR-051 decision 7) | `finishup server list`, `server status [--json]` |
| `finishup server login NAME` (a new key; the generation moves; the helper stops) | `finishup server logout NAME` (offline; deletes the key; the generation moves; the helper stops) | `server status` (`API key: keyring`, `file` or `none`; never the value) |
| `finishup server set NAME --style direct` (each process reads the key) | `finishup server set NAME --style relay` (only the helper reads it) | `server status [--json]` (`target.connection.style`) |

## Consequences

- One contract for every HTTP client and server: a REST schema change moves the API manifest, needs
  a new entry in the frozen manifest vectors and is caught by the conformance kit.
- A server owner chooses the edge; a client sees only REST, through the same helper and styles as
  SSH, under the same gate, generations and per-frame checks (ADR-052 decisions 20 to 23). No new
  client phase is added: refusals over REST map to the five transport phases and the layer-3
  `server_profile_changed`.
- With no HTTPS or port target recorded, every surface behaves as in layer 4: nothing REST is
  imported on a hook's path (the hook import-diet test forbids the REST client, its mapping, its
  discovery, the REST edge, the gateway, starlette and uvicorn there; the REST client and mapping
  load only for an HTTPS or port target in the direct style), and no listener starts unless the
  owner runs `service rest run`.
- New closed tokens are command texts and REST reasons (`rest-error`, `service api-key` and
  `service rest run` refusals, `official_endpoint_unavailable`); no protocol reason code or
  continuation is added.
