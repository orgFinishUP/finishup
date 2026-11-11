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
move the helper's stop epoch), and removes the folder only once that shutdown is proven: every
process it started exited and no lock beneath the folder is still held (a service, helper, OpenSSH
master or retained runtime of the run would hold one). Otherwise it keeps the folder, says which
locks are held and exits 1; it never stops anything by name. A `SIGTERM` ends a run through the
same cleanup, and the capability test runs the harness under an outer runner that asks it to stop
that way when its bound passes before it kills anything (and then only the harness's own process
group). The private `sshd` runs no user rc file (`PermitUserRC no`) and gives every session a
private `HOME` and XDG folders (checked when it starts), so neither the account's `~/.ssh/rc` nor
its shell's startup files run before a server command. Nothing reads or writes `~/.ssh`, the
default FinishUP folders or a host's own configuration, and every result text is redacted (the
run's folder, the home folder, secrets) before it is cut short, printed or written. Run every
script from a checkout after `uv sync`, with both root variables unset (the client must be an
ambient installation: `server add` refuses under a pin), and never beside another run that starts
real services.

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
**style** (`server set --style direct` for the direct cells, and `server status` must report it);
**use**; **connect**; a claim-bound
**start → publish → check → receipt** (the receipt's `evidence_provenance` must count reads from
the server's copy at L2 and none at L1); **L2 sync** (the server's copy records and its bounded
`code_copy` events); the **repository hold** and **zero network** refusing a start before any
dial (after `server disconnect`: the refusal names `repository_egress_held` /
`zero_network_remote_selected`, the counting relay in front of the server saw no new connection, no
helper started, the export database did not change); a **changed profile** (the server's service
restarted with a new profile revision: the next call is refused `server_profile_changed` typed,
`server status` says the consent changed, the call after that is refused here sending nothing (no
new connection, no byte toward an HTTPS or port server over the helper's warm connection, no
channel opened on the SSH server's `sshd`), the owner agrees again with `server use`, the next call
works);
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

### Results (Linux x86-64, 2026-11-11, `ebcbf76fb`)

All 23 cells passed every step: 2 local, 4 SSH, 16 REST (both edges, both styles, both levels,
`local_port` and self-hosted `https`) and the official stand-in (the conformance kit's 9 cases).
Each cell took 15 to 57 seconds, and every group's cleanup was proven (no process left, no lock
held, the folder removed). This run used the reviewed harness: in all 20 remote cells the call
refused after the consent changed sent nothing (0 dials; 0 bytes toward the HTTPS and port
servers over the helper's warm connection; 0 channels opened on the SSH server). Earlier runs
(2026-11-10 `53fa8e2a2`, 2026-11-11 `07e94dd94`) passed as well; a run on the merged head in
between failed `ssh-direct-L1` (below).

| Cell group | add | use | task | hold / zero network | re-consent | logout | L2 sync / forget | out |
|---|---|---|---|---|---|---|---|---|
| `local`, `named-local` | pass | pass | pass | pass (nothing refused) | n/a | n/a | n/a | pass |
| `ssh-*` (4) | pass | pass | pass | pass, 0 dials | pass, nothing sent | n/a | pass (L2) | pass |
| `port-*` (8) | pass | pass | pass | pass, 0 dials | pass, nothing sent | pass, 0 dials | pass (L2) | pass |
| `https-*` (8) | pass | pass | pass | pass, 0 dials | pass, nothing sent | pass, 0 dials | pass (L2) | pass |
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

What a running process does across an in-place upgrade (first run 2026-11-10; the same results
again on 2026-11-11 at `07e94dd94` and, with the reviewed harness, at `5b5a56008`, against layer
4's `f1e3f5707`; every step passed and the run's cleanup was proven):

- **An MCP bridge keeps its own code.** A bridge runs from a retained copy of its runtime
  (`.<venv>-releases/<digest>/`), so after the upgrade it, and every helper it starts, is still the
  older build.
- **The newer CLI replaces the older helper** (through its stop epoch, no pid signalled; the run
  checks a live helper of the newer build holds the target afterwards) and, while the server is
  still the older release, is refused with `remote_incompatible`
  (continuation `remote_release_mismatch`: install the same release on both; self-hosted servers
  keep release lockstep). Before this layer it said "the running local service … run `finishup
  service restart`", which repairs nothing for a server elsewhere.
- **The server's owner upgrades it and runs `finishup service restart`;** the vault is unlocked
  again there. The newer CLI then works without a new consent (the profile revision's issuer is
  kept).
- **The older bridge** is refused with its build's typed release mismatch against the newer helper
  and server (`SERVICE_UNAVAILABLE`, "belongs to a different FinishUP installation"; layer 4's
  build names no phase or continuation), keeps running, and is never served half-way. A **newer bridge** reattaches (`start` mode `attach`)
  to the task the older one started.
- **Two builds of one version** (every build of this stack is 0.3.0; test instances and dogfood
  builds are too) cannot be ordered by version. In the run, the newer CLI replaced the older helper
  and the older bridge replaced the newer helper again on its next call, on every use. Fixed in
  this layer for every later upgrade: the build installed now (the installation's own package
  files; a bridge's retained runtime reads the installation it was copied from) is the newer, so
  only a process of that build replaces a helper of another build of its release, and exactly
  that helper (a fenced stop). Any other process gets `service_incompatible` and the MCP bridge
  asks to reopen the session instead of naming `service restart`. (Ordering by the helper's start
  time, this layer's first fix, let an older bridge's helper started after the newer process hold
  the target for good.) A bridge from before this fix (layer 4's, in the run) still flaps until its
  session is reopened: reopen sessions after an upgrade.
- **Restart and replay.** The server's service restarted under an open bridge: the next call was
  served. A write replayed with its `request_id` after a restart (the restart succeeded and a new
  service process holds the server) returned the same accepted events (one), and the ledger head
  moved by exactly one event: 3 after the earlier steps, 4 after the write, still 4 after the
  replay. (The reviewed harness's first two runs failed this step on its own predicate, which read
  the frontier's sequence, a decimal string, as a number; fixed in the harness.)
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
| cold connect, call and close on a hook's path (helper and master stopped), the connect on demand within the hook's 1.0 s budget | 1150 ms (budget + close) | `_HOOK_SERVICE_START_BUDGET_SECONDS` |

The cold hook row times the complete operation, as one deadline would bound it: the connect, the
hook's call (one status) and its cleanup (the close). Every sample must be measured (a probe that
crashed or timed out fails the gate; it is never counted as 0 ms), served or failing open as a
remote outage (`remote_unreachable` or `remote_service_not_running`; any other phase fails), and
the next call after it must be served; the hook process's wall time is reported beside it. Before
sampling, `server set --style` must succeed and `server status` must report the style under test.
How long a cold helper takes to serve at all is reported, never gated.

### Results (netns, Linux x86-64, 100 ms round trip, 30 samples per style)

Measured on 2026-11-11 at `ebcbf76fb` with the reviewed harness ("fixed": the cold hook row is the
complete operation, connect, status and close; every sample must be measured; only an outage phase
counts as failing open; every next call must be served; the style is verified before sampling),
and in the same hour with the harness of `dbaf7ae52` ("earlier": the cold hook row is the connect
alone) against the same code. The import time and the CPU calibration (a fixed workload,
milliseconds) show how loaded the computer was.

| Harness | Style | warm p50 / p95 (≤ 650) | connect / status p50 | warm process p95 (≤ 3200) | cold hook p50 / p95 (≤ 1150) | hook process p95 | `server test`: new connection, slowest | import p50, calibration | Gate |
|---|---|---|---|---|---|---|---|---|---|
| fixed | ssh relay | 430 / 454 | 256 / 174 | 1409 | 1002 / 1113, fails open `remote_unreachable` 15/15, next served 15/15 | 2035 | 365 | 577, 67 | pass |
| earlier | ssh relay | 447 / 536 | – | 1566 | 1002 / 1064 (connect only), as above | – | – | 597, 55 | pass |
| fixed | ssh direct | 433 / 468 | 270 / 161 | 1337 | 1002 / 1004, fails open `remote_unreachable` 15/15, next served 15/15 | 2028 | 396 | 542, 57 | pass |
| earlier | ssh direct | 412 / 433 | – | 1176 | 1002 / 1003 (connect only), as above | – | – | 503, 56 | pass |
| fixed | https relay | 365 / 390 | 159 / 204 | 1250 | 1002 / 1003, fails open `remote_unreachable` 15/15, next served 15/15 | 1768 | 280 | 525, 55 | pass |
| earlier | https relay | 364 / 381 | – | 1186 | 1002 / 1003 (connect only), as above | – | – | 525, 56 | pass |
| fixed | https direct | 802 / 826 | 625 / 176 | 1589 | 808 / 827, served 15/15 (connect, status, close) | 1578 | 743 (warned) | 477, 54 | **fail** |
| earlier | https direct | 811 / 858 | – | 1671 | 639 / 671 (connect only), served 15/15 | – | 861 (warned) | 482, 62 | **fail** |

The reviewed harness changes no verdict: both relay styles (the default for both kinds) and direct
SSH meet the gate, and direct HTTPS fails it on the warm connect and status (each new process
makes a TCP connection and a TLS handshake, asks for its session and then for the status: four
round trips, 400 ms at this delay). Timing the cold hook's call and close as well adds about 170 ms
where the hook is served (direct HTTPS: 671 → 827 ms at p95, still within 1150); where it fails
open at its 1.0 s deadline nothing more runs, so the complete operation ends at the deadline (1002
to 1113 ms). No sample was missing, no fail-open named anything but `remote_unreachable`, and every
next call was served. Direct SSH, marginal at p95 in the earlier rounds (475 and 673 ms), passed
in both harnesses this time (468 and 433 ms): it remains load-sensitive. The earlier rounds' tables
(and the before/after of the third engineering round) are in the layer reports.

**Decided by the owner (2026-11-11): accept it and tell the user** (ADR-052 decision 24.5). No
budget changes. The relay styles, the default, must pass the gate; the direct styles stay
available and are measured and reported against the same budgets, never required: from this
decision `render` writes `pass`/`fail` for a relay style and `reported: within`, `reported: over`
or `reported: error` for a direct one (in the table above, the direct HTTPS rows' **fail** reads
`reported: over`). A slow direct connection is told to the user, with `finishup server set NAME
--style relay` as the remedy: `server test` (a direct new connection past 650 ms, or one that did
not answer), `server status` (a direct probe that did not answer in time), and the
`remote_direct_slow` continuation of a direct-style `remote_unreachable` on every surface (CLI,
`--json`, MCP, hooks, the terminal interface, the menu).

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

A real-network workflow, `.github/workflows/real-network.yml`, is written but **not yet in the tree**: adding a
workflow file needs a GitHub token with the `workflow` scope, which the build agent did not have, so the
file is kept as a patch in the build report for the maintainer to add. Once added (pull requests to any
branch, dispatch, weekly), it installs
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
| The WAN gate at 100 ms: direct HTTPS is over the budget (four round trips per process; 826 ms p95 with the reviewed harness) and direct SSH is load-sensitive at p95; both relay styles pass | decided (owner, 2026-11-11): reported, not required, for the direct styles; the user is told and offered relay (ADR-052 decision 24.5) |
| The terminal interface's server flows (consent at L2, `server code`, `server remove`'s question, SSH and HTTPS add) | a later layer (ADR-051, ADR-054) |
| A check left in flight across a server restart over a remote connection (frozen operation recovery end to end) | the harness's next revision |
| Remote cells with a live everyday policy (the everyday installation's service running, its policy zero network) | the harness's next revision; unit and integration tests cover the live read |
