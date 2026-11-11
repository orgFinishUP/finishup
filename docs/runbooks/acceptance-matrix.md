# Acceptance matrix, upgrade and WAN timing (layer 7)

Operator procedures and recorded results for the unified client/server build's lifecycle
validation: the compatibility matrix of
[ADR-051](../adr/ADR-051-client-server-cut-and-server-targets.md) run for real, an upgrade over a
still-running older helper, MCP bridge and service, the hook cold path over an injected WAN delay,
and the hosts on Linux. Decisions live in ADR-051 to ADR-054; this page holds how to run the checks,
what they showed on the recorded revision, and the gaps with their owners.

Everything here is contributor tooling under `scripts/acceptance/`. It never targets an everyday
installation: each run makes one fresh owner-only folder beneath the real home (`~/.yz-acc-*`;
never `/tmp`, which macOS resolves through a symlink), with a client home of private XDG folders,
isolated server roots, a private unprivileged `sshd` and throwaway TLS material, stops every
process it started by its own PID (FinishUP's helpers through `server disconnect`/`remove`, which
move the helper's stop epoch), and removes the folder. Nothing reads or writes `~/.ssh`, the
default FinishUP folders or a host's own configuration. Run every script from a checkout after
`uv sync`, with both root variables unset (the client must be an ambient installation: `server
add` refuses under a pin), and never beside another run that starts real services.

## The compatibility matrix

```text
uv run python scripts/acceptance/matrix.py list
uv run python scripts/acceptance/matrix.py run --cells 'ssh-*' --out <dir>
uv run python scripts/acceptance/matrix.py report --out <dir> --markdown <file>
```

`--cells` takes names or globs; a group of four cells takes about five minutes. The cells are the
design's matrix exactly:

| Server kind | Edge | Styles | Levels | Cells |
|---|---|---|---|---|
| local, named local | unix | unix | L0 | `local`, `named-local` |
| `ssh` | ssh → control socket | relay, direct | L1, L2 | `ssh-{relay,direct}-{L1,L2}` |
| `local_port` | gateway, native (REST) | relay, direct | L1, L2 | `port-{gateway,native}-{relay,direct}-{L1,L2}` |
| `https` (self-hosted) | gateway, native (REST) | relay, direct | L1, L2 | `https-{gateway,native}-{relay,direct}-{L1,L2}` |
| `https` (official) | REST (another repository) | relay, direct | as advertised | `official` |

Every remote cell, in order: **add** (the handshake and the consent ceremony on a pseudo-terminal:
OpenSSH's host-key question, the outside-read question, the typed name, the L2 disclosure);
**style** (`server set --style direct` for the direct cells); **use**; **connect**; a claim-bound
**start → publish → check → receipt** (the receipt's `evidence_provenance` must count reads from
the server's copy at L2 and none at L1); **L2 sync** (the server's copy records and its bounded
`code_copy` events); the **repository hold** and **zero network** refusing a start before any
dial (after `server disconnect`: the refusal names `repository_egress_held` /
`zero_network_remote_selected`, the counting relay in front of the server saw no new connection, no
helper started, the export database did not change); a **changed profile** (the server's service
restarted with a new profile revision: the next call is refused `server_profile_changed`, `server
status` says the consent changed, the owner agrees again with `server use`, the next call works);
**logout and login** (HTTPS and port: refused after `logout` with no dial, served after `login`);
**L2 forget** (the copy records go, the task's receipt names its forgotten content); **disconnect**
(the helper stops); **remove** (L2 with `--forget-copies`; the target folder goes). The local cells
start a task and show that zero network and a hold leave a local server alone (nothing leaves the
computer); the named local cell adds, uses and removes its server. `official` checks that `server
add official` refuses in this release (U8: no official endpoint is named yet) and runs the REST
conformance kit by URL against a stand-in (this checkout's gateway edge), as the official service's
repository will run it.

The hold and zero-network steps arm the state the way this computer's everyday FinishUP records it
(`everyday-repositories.json` and the reported policy marker): the remote cells run on a client
whose everyday installation has no vault, so the marker is what decides. Once the everyday
installation has a vault, a server elsewhere is refused while its live policy cannot be read
(`network_policy_unreadable`, ADR-051 decision 8); the local cells therefore run on a client home
of their own.

### Results (Linux x86-64, 2026-11-10, `53fa8e2a2`)

All 23 cells passed every step: 2 local, 4 SSH, 16 REST (both edges, both styles, both levels,
`local_port` and self-hosted `https`) and the official stand-in (the conformance kit's 9 cases).
Each cell took 21 to 90 seconds.

| Cell group | add | use | task | hold / zero network | re-consent | logout | L2 sync / forget | out |
|---|---|---|---|---|---|---|---|---|
| `local`, `named-local` | pass | pass | pass | pass (nothing refused) | n/a | n/a | n/a | pass |
| `ssh-*` (4) | pass | pass | pass | pass, 0 dials | pass | n/a | pass (L2) | pass |
| `port-*` (8) | pass | pass | pass | pass, 0 dials | pass | pass, 0 dials | pass (L2) | pass |
| `https-*` (8) | pass | pass | pass | pass, 0 dials | pass | pass, 0 dials | pass (L2) | pass |
| `official` | refuses (none named) | | | | | | | kit 9/9 |

Defects the matrix found, fixed in this layer with unit tests: in the direct style the refresh
marker a `server_profile_changed` refusal left was never taken (no helper on the path), so
`server status` went on calling the consent current and a narrowed profile was never adjusted;
the refusal now starts the target's helper, which fetches the profile itself. The re-run on the
merged head showed that fix never ran in the real direct style: the shared master keeps an
`ssh -W` client's stderr open past its exit, the close cancelled the stream's stderr reader, and
asking why the stream ended raised that cancellation in place of the refusal (a traceback from
`service status`, exit 1, and no helper). The question now names nothing in that case, and the
cell checks the first refusal is typed (exit 20, `remote_reconsent`, no traceback).

## Upgrade over a running helper, bridge and service

```text
uv run python scripts/acceptance/upgrade.py --old f1e3f5707 --out <file.json>
```

It builds the older revision (layer 4's head by default) and `HEAD` exactly as test instances are
built (`scripts/provision_test_instance.py create`, disposed at the end) and installs the two
wheels the way an everyday installation is upgraded: one unpinned environment per computer, the
newer wheel over the older in place, while the processes started from the older one keep running.
A pinned instance cannot play either computer (a client must be ambient; an instance is never
upgraded in place). The client and an SSH server (isolated root, private `sshd`), relay style.

What a running process does across an in-place upgrade:

- **An MCP bridge keeps its own code.** A bridge runs from a retained copy of its runtime
  (`.<venv>-releases/<digest>/`), so after the upgrade it, and every helper it starts, is still the
  older build.
- **The newer CLI replaces the older helper** (through its stop epoch, no pid signalled) and,
  while the server is still the older release, is refused with `remote_incompatible`
  (continuation `remote_release_mismatch`: install the same release on both; self-hosted servers
  keep release lockstep). Before this layer it said "the running local service … run `finishup
  service restart`", which repairs nothing for a server elsewhere.
- **The server's owner upgrades it and runs `finishup service restart`;** the vault is unlocked
  again there. The newer CLI then works without a new consent (the profile revision's issuer is
  kept).
- **The older bridge** is refused with a typed reason (`service_incompatible`) against the newer
  helper and server, never served half-way. A **newer bridge** reattaches (`start` mode `attach`)
  to the task the older one started.
- **Two builds of one version** (every build of this stack is 0.3.0; test instances and dogfood
  builds are too) cannot be ordered by version. In the run, the newer CLI replaced the older helper
  and the older bridge replaced the newer helper again on its next call, on every use. Fixed in
  this layer for every later upgrade: a helper of this release but another build that started
  after a process is the newer installation's and is never replaced by it; that process gets
  `service_incompatible` and the MCP bridge asks to reopen the session instead of naming `service
  restart`. A bridge from before this fix (layer 4's, in the run) still flaps until its session is
  reopened: reopen sessions after an upgrade.
- **Restart and replay.** The server's service restarted under an open bridge: the next call was
  served. A write replayed with its `request_id` after a restart returned the same accepted events
  and moved the head by one event only.
- **A new selection (O1).** After `server use local`, the open bridge's next requests reached this
  computer's own service (the remote connection ended; a request in flight would end
  `server_authorization_changed`, outcome unknown). Back with `server use lab`, the bridge kept the
  local server it now holds, as documented: a running bridge keeps a server on this computer;
  reopen the session to follow a switch back to a server elsewhere.

Older helpers asked for operations they do not declare (the L2 copy's two operations) refuse with
`operation_not_declared` before any work; that is covered by unit tests
(`tests/unit/service/test_workspace_hub.py`) rather than this run, whose older build predates L2.
Session reattach, a restart under a bridge, and replay after a restart ran for real above. A
pending operation's handle (`status` with `view: operation` for an in-flight check) and a clean
reopen and reconnect are covered by `tests/integration/application/test_status_operation_view.py`
and `tests/subprocess/test_reopen_retry_replay.py`; a check left in flight across a server restart
over a remote connection was not run (see the gaps).

## WAN timing gate (design v2 section 8.9)

```text
uv run python scripts/acceptance/wan_gate.py --rtt-ms 100 --out <file.json>
uv run python scripts/acceptance/wan_gate.py --rtt-ms 100 --mode proxy --out <file.json>
uv run python scripts/acceptance/wan_gate.py render <file.json>...
```

`--mode netns` (the default) runs the measurement inside a new unprivileged user and network
namespace whose own loopback gets `tc netem delay` of half the round trip, then drops back to the
account's uid in a nested user namespace. No interface or queueing discipline of the computer is
touched, and the namespace ends with its last process. Where unprivileged namespaces are refused
(Ubuntu's AppArmor restriction on many CI runners), `--mode proxy` holds every chunk in a userspace
relay instead, which makes handshakes cheaper than a real WAN (stated in the result).

The gate, per style, after a claim-bound task started:

| Measure | Budget (p95) | Source |
|---|---|---|
| warm connect (claim) + compact status in a fresh process | 650 ms | the required startup gate (`cli/startup_gate_probe.py`) |
| that whole process, interpreter start included | 3200 ms | the hook pass budget (`cli/observe_hooks.py`) |
| cold connect on a hook's path (helper and master stopped), on demand within the hook's 1.0 s budget | 1150 ms (budget + close) | `_HOOK_SERVICE_START_BUDGET_SECONDS` |

The cold connect must end within its budget, served or failing open with a named phase, and the
next call must be served. How long a cold helper takes to serve at all is reported, never gated.

### Results (netns, Linux x86-64, `53fa8e2a2`)

| RTT | Style | warm p50 / p95 (≤ 650) | warm process p95 (≤ 3200) | cold hook connect p95 (≤ 1150) | cold served p50 | `server test` p95 | Gate |
|---|---|---|---|---|---|---|---|
| 100 ms | ssh relay | 537 / 673 | 1481 | 1002, fails open `remote_unreachable`, next call served 7/7 | 2250 | 116 | **fail** |
| 100 ms | ssh direct | 592 / 753 | 1763 | 1003, fails open `remote_unreachable`, next served 7/7 | 1562 | 122 | **fail** |
| 100 ms | https relay | 491 / 536 | 1313 | 1149, fails open `remote_unreachable`, next served 7/7 | 1356 | 151 | pass |
| 100 ms | https direct | 884 / 967 | 1917 | 683, served 7/7 | 651 | 146 | **fail** |
| 0 ms | ssh relay | 244 / 254 | 996 | 1002, 2/4 served | 1048 | 13 | pass |
| 0 ms | ssh direct | 280 / 303 | 1094 | 352, served 4/4 | 361 | 13 | pass |
| 0 ms | https relay | 292 / 468 | 1614 | 1002, 3/4 served | 938 | 45 | pass |
| 0 ms | https direct | 499 / 880 | 3567 | 930, served 4/4 | 290 | 44 | fail |

At a 100 ms round trip the gate **fails** for three of the four styles: the warm startup-gate path
costs about 250 ms of client work plus about two round trips for the claim-bound connect and one
and a half for the status call, so it lands just above 650 ms for SSH and well above it for direct
HTTPS (a new TLS handshake and a key read in every process). The relay over HTTPS passes. The cold
hook path behaves as defined in every style: it ends within its budget, fails open naming
`remote_unreachable` (before this layer the direct styles named no phase, which hooks rendered as
this computer's service being down; fixed), and the helper it started serves the next call. `server
test` reports round trips of 116 to 151 ms and says "within the hook budgets" (it warns above
200 ms) while the startup gate itself exceeds 650 ms at this round trip: its warning threshold is
too lax for a claim-bound connect. Which budget the startup gate gets on a WAN (or fewer round
trips on the connect), and `server test`'s threshold, are owner decisions (report); the numbers are
re-measured by the script above.

## Hosts on Linux

```text
uv run python scripts/acceptance/hosts.py --out <file.json>
```

Against a disposable test instance from `HEAD` (pinned to its own root), each host in a scratch
home of its own, registered by the instance's absolute launcher with the host's own CLI:

| Host (version) | MCP | Hooks (recorded payload shapes) | Model session |
|---|---|---|---|
| Codex CLI 0.167.0 | registered and listed (`codex mcp add`/`list`/`remove`); Codex starts a server only in a model session | `hooks observe` ×13: exit 0, fail open (`{}`), no consent so nothing observed | not run |
| Claude Code 2.1.319 | the host started the bridge and completed the MCP handshake (`claude mcp list`: Connected); removed | `hooks claude-observe` ×3: exit 0 | not run |
| Cursor agent 2026.10.22 | the host started the bridge and listed its 8 tools (`mcp list-tools`); removed | `hooks cursor-observe` ×3: exit 0 | not run |

A model session (an agent turn calling FinishUP's tools, hooks firing from a live session) needs
the account's own host credentials and was not run. The bridge and hooks against servers elsewhere
were exercised by the scripts above driving `finishup mcp serve` over stdio as a host does (the
upgrade run) and the hook's own connect path (the WAN gate), not by a host session. The terminal
interface's server flows were not exercised (no add flow for SSH or HTTPS there yet).

## Continuous integration

`.github/workflows/real-network.yml` (pull requests to any branch, dispatch, weekly) installs
OpenSSH where the runner lacks it without starting the system service, and runs
`tests/capability/test_openssh_helper.py`, `tests/conformance/rest` and
`tests/capability/test_acceptance_matrix.py` (cells `local`, `ssh-relay-L2`,
`https-gateway-relay-L2`, `port-native-direct-L2`), naming every skip in the job summary. The WAN
gate runs report-only there (its table in the summary, its JSON uploaded).

## Gaps and owners

| Gap | Owner |
|---|---|
| macOS: every cell (launchd reaping of the helper, `/private/tmp`, the Homebrew launcher path, `getpeereid` on the relay, the system trust store through Python's default verify paths, the XDG variables being ignored for FinishUP's folders, case-insensitive file systems and `O_NOFOLLOW` per component in the exporter) | maintainer, on the macOS dogfood run (#1308 follow-up) |
| WSL 2: every cell (a distribution that stops takes the helper and service with it; systemd/linger for a session-bound endpoint; Windows-side versus Linux OpenSSH; a listener reached from Windows only as WSL forwards it) | maintainer, on a Windows machine with WSL 2 (#1308 follow-up) |
| Host model sessions (Codex, Claude Code, Cursor) against a server elsewhere, at L1 and L2 | maintainer's dogfood run (needs host credentials) |
| The WAN gate fails at 100 ms for SSH relay and direct and HTTPS direct; `server test`'s 200 ms threshold | owner decision (report), then the layer that changes the budget or the connect |
| The terminal interface's server flows (consent at L2, `server code`, `server remove`'s question, SSH and HTTPS add) | a later layer (ADR-051, ADR-054) |
| A check left in flight across a server restart over a remote connection (frozen operation recovery end to end) | the harness's next revision |
| Remote cells with a live everyday policy (the everyday installation's service running, its policy zero network) | the harness's next revision; unit and integration tests cover the live read |
