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

### Results (Linux x86-64, 2026-11-11, `07e94dd94`)

All 23 cells passed every step: 2 local, 4 SSH, 16 REST (both edges, both styles, both levels,
`local_port` and self-hosted `https`) and the official stand-in (the conformance kit's 9 cases).
Each cell took 15 to 50 seconds. The first run (2026-11-10, `53fa8e2a2`) passed as well; a run on
the merged head in between failed `ssh-direct-L1` (below).

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

What a running process does across an in-place upgrade (first run 2026-11-10; the same results
again on 2026-11-11 at `07e94dd94`, against layer 4's `f1e3f5707`):

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

### Results (netns, Linux x86-64, 100 ms round trip, 30 samples per style)

Measured on the third engineering round's head (`5ab459ce6`) and, in the same hour, with that
round's two changes taken out again (`-dirty`: the code of `32c74325d`); the import time and the
CPU calibration (a fixed workload, milliseconds) show how loaded the computer was, so runs made at
different times can be compared.

| Code | Style | warm p50 / p95 (≤ 650) | connect / status p50 | warm process p95 (≤ 3200) | cold hook connect p50 / p95 (≤ 1150) | `server test`: new connection, slowest | import p50, calibration | Gate |
|---|---|---|---|---|---|---|---|---|
| after | ssh relay | 405 / 424 | 244 / 161 | 1205 | 1002 / 1003, fails open `remote_unreachable`, next served 15/15 | 347 | 486, 58 | pass |
| after | https relay | 356 / 440 | 154 / 202 | 1208 | 1002 / 1002, fails open `remote_unreachable`, next served 15/15 | 280 | 516, 59 | pass |
| after | ssh direct | 444 / 475 | 274 / 164 | 1400 | 1003 / 1004, fails open `remote_unreachable`, next served 15/15 | 500 | 571, 61 | pass |
| after (again) | ssh direct | 470 / 673 | 298 / 171 | 2020 | 1002 / 1003, as above | 401 | 632, 53 | **fail** |
| after | https direct | 873 / 936 | 678 / 199 | 2009 | 685 / 796, served 15/15 | 884 (warned) | 600, 60 | **fail** |
| before | ssh relay | 437 / 479 | 249 / 188 | 1304 | 1003 / 1187, fails open `remote_unreachable`, next served 15/15 | 493 | 515, 64 | **fail** (cold) |
| before | https relay | 442 / 551 | 170 / 264 | 1975 | 1002 / 1039, as above | 294 | 557, 55 | pass |
| before | ssh direct | 420 / 433 | 249 / 170 | 1126 | 1002 / 1003, as above | 358 | 473, 54 | pass |
| before | https direct | 852 / 889 | 643 / 208 | 1688 | 648 / 837, served 15/15 | 1500 (warned) | 504, 58 | **fail** |

Both relay styles, the default for both kinds, meet the gate with room to spare. The two changes:
the server resolved each of the computer's mount points again for every store a status read opens
(and for every control connection of an isolated root's service), which was most of a warm status
read's server time (45 to 56 ms, now 18 to 23); and the REST client kept an idle connection only 5
seconds, so the HTTPS relay answered every hook after a pause by opening a new TCP and TLS
connection first. That second cost is invisible to the back-to-back samples above: after an
8-second pause a warm HTTPS relay's connect and status took 650 to 750 ms before and about 350 ms
after (5 samples each, the same harness's probe).

The SSH direct style meets the gate at p50 and lands on either side of it at p95 with the
computer's load (475 and 673 ms in two runs of the same code): each process starts its own `ssh -W`
and opens its own channel, three round trips and a process start before the answer. Direct HTTPS
**fails**: each new process makes a TCP connection and a TLS handshake, asks for its session and
then for the status (four round trips, 400 ms at this delay) and loads the HTTPS client and does
its own hello work first, so it cannot reach 650 ms at this round trip without fewer round trips
(an owner decision: a longer budget for the direct style on a WAN, or relay only over a WAN). The
cold hook path behaves as defined in every style: it ends within its budget, served or failing open
naming `remote_unreachable`, and the next call is served. The numbers are re-measured by the script
above; earlier rounds' tables are in the layer reports.

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
| The WAN gate at 100 ms: direct HTTPS fails (four round trips per process) and direct SSH is marginal at p95; both relay styles pass | owner decision (report): the direct styles' budget on a WAN, or relay only over a WAN |
| The terminal interface's server flows (consent at L2, `server code`, `server remove`'s question, SSH and HTTPS add) | a later layer (ADR-051, ADR-054) |
| A check left in flight across a server restart over a remote connection (frozen operation recovery end to end) | the harness's next revision |
| Remote cells with a live everyday policy (the everyday installation's service running, its policy zero network) | the harness's next revision; unit and integration tests cover the live read |
