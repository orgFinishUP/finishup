# Startup and hot-path performance

This runbook records a measurement pass over every place a user or a host waits on FinishUP: the
launcher, the hook commands a host runs on each tool call, the MCP bridge, the control channel,
the ledger, change capture and setup. It lists what was measured, what changed, how to replay
the measurements, and what was deliberately left alone. Every change keeps standard output,
standard error, exit codes, wire shapes, digests, ledger contents and error order the same for
single-threaded callers. The deliberate user-visible difference is that `--help` now describes
every command; the other known differences are listed under
[Differences from the earlier behavior](#differences-from-the-earlier-behavior).

## Replaying the launcher measurements

[`scripts/benchmark_cli_startup.py`](../../scripts/benchmark_cli_startup.py) runs each entry
point through a checkout's installed launcher in a fresh process and interleaves the checkouts,
so machine noise lands on both sides. It starts no service and opens no vault. Give it a private
isolated root, never a live state directory:

```text
uv run python scripts/benchmark_cli_startup.py <baseline-checkout> <this-checkout> \
  --root <private-directory> --runs 15
```

Each checkout needs its own synced `.venv`. The script runs the Claude Code and Cursor observe
hooks as their host registrations do, with each host's ordinary observation profile, in a
workspace that has not consented. It does not set up consent, so it does not replay the consented
table below: those rows came from the same hook commands against two isolated roots that had each
been granted observation of the same workspace.

## Results

Minimum of 15 interleaved runs on an idle 8-core Linux machine, CPython 3.14.6, from a checkout,
comparing the commit before this pass with the commit after it. A bare `python -c pass` takes
about 10 ms on the same machine.

| Entry point | Before | After | Ratio |
|---|---|---|---|
| `finishup --version` | 755 ms | 36 ms | 21x |
| `finishup version` | 739 ms | 35 ms | 21x |
| `finishup version --json` | 776 ms | 63 ms | 12x |
| `finishup --help` | 832 ms | 362 ms | 2.3x |
| `finishup status --help` | 794 ms | 348 ms | 2.3x |
| `finishup service status`, no service running | 604 ms | 217 ms | 2.8x |
| `hooks claude-observe`, `PreToolUse` | 637 ms | 111 ms | 5.8x |
| `hooks claude-observe`, `PostToolUse` | 656 ms | 113 ms | 5.8x |
| `hooks cursor-observe`, `preToolUse` | 649 ms | 115 ms | 5.7x |
| `hooks cursor-observe`, `postToolUse` | 659 ms | 117 ms | 5.6x |
| `hooks observe` (Codex), `PreToolUse` | 650 ms | 131 ms | 5.0x |
| `hooks observe` (Codex), `PostToolUse` | 646 ms | 129 ms | 5.0x |
| `hooks startup-context --host claude` | 39 ms | 24 ms | 1.6x |
| `hooks startup-gate --host claude` | 64 ms | 43 ms | 1.5x |

Workspace granted observation, minimum of 11 interleaved runs; standard output, standard error
and exit code were identical on both sides:

| Hook | Before | After | Ratio |
|---|---|---|---|
| `hooks claude-observe`, `PostToolUse` | 773 ms | 355 ms | 2.2x |
| `hooks cursor-observe`, `postToolUse` | 785 ms | 364 ms | 2.2x |
| `hooks observe` (Codex), `PreToolUse` | 745 ms | 403 ms | 1.9x |
| `hooks observe` (Codex), `PostToolUse` | 819 ms | 498 ms | 1.6x |

Installed launcher: an independent test instance of each build
([test instances](test-instances.md)), where every hook runs two interpreters because the
launcher re-executes into its retained runtime. Minimum of 11 interleaved runs, workspace not
granted observation, hooks run without an observation profile:

| Entry point | Before | After |
|---|---|---|
| `finishup --version` | 737 ms | 35 ms |
| `finishup --help` | 852 ms | 371 ms |
| `finishup service status`, no service running | 761 ms | 338 ms |
| `hooks claude-observe`, `PreToolUse` | 170 ms | 132 ms |
| `hooks observe` (Codex), `PreToolUse` | 733 ms | 150 ms |
| `hooks startup-context --host claude` | 40 ms | 25 ms |
| `hooks startup-gate --host claude` | 105 ms | 64 ms |

One scripted session against a running service, from a checkout, two samples per step: `start`
1,067 to 552 ms, `publish-work` 982 to 467 ms, `check` 1,103 to 525 ms, `status` (compact) 935
to 500 ms, `receipt --json` 989 to 468 ms, `closure-prepare` inventory 1,271 to 752 ms, MCP
`initialize` about 1,450 to 970 ms. All 196 steps of that session printed the same standard
output, standard error and exit code on both builds once identifiers, timestamps and the root
path were masked, and the 44 events of the session's main
task matched in kind, version and order between the two ledgers.

Measurements taken inside the process. Each row compares the commit before one change with the
commit that made it, not the first commit with the last, so a row can understate the whole
gain:

| Work | Before | After |
|---|---|---|
| `service_status` control round trip | 8.4 ms | 1.0 ms |
| Validity check of a control result | 2.6 ms | 0.07 ms |
| Client schema preparation at connect (97 documents) | 66.6 ms | 51.7 ms |
| Canonical parse plus two encodes of an 800 KB hook state | 58 ms | 16 ms |
| Full schema catalog load, cold | 426 ms | 302 ms |
| Replay of a 3,008-event ledger | 5.2 s | 1.7 s |
| Stored state digest per append at 3,008 events | 51 ms | 4.7 ms |
| MCP bridge, first `tools/list` | 210 ms | 25 ms |
| MCP result text for a 100-row status page (Codex, Claude Code, generic; Cursor unchanged) | 19.5 ms | 9.2 ms |
| Change capture, 120 modified files | 135 ms, 138 Git spawns | 45 ms, 20 Git spawns |
| `setup status --host claude` | 4.5 s | 2.5 s |

## What changed

- **Launcher.** `--version`, `version` and `version --json` answer before the command graph
  loads. The full command line converts only the invoked command's path from Typer to click
  instead of all 210 commands, loads with cyclic collection off, and freezes its import heap
  before the command runs. Commands that serve until stopped (`service run`, `service rest run`,
  `helper run`) are not frozen.
- **Imports.** Protocol and configuration models are built on first use under one process-wide
  lock; the service and the MCP bridge still build every model before serving, so no request
  pays a first-use build. Ordinary hook passes, the advice refresh after a tool call and
  `service status` no longer import pydantic or the protocol models. The package version is read
  only when something asks for it.
- **Protocol.** A value made only of plain JSON types is checked in one walk and encoded by the
  C JSON encoder; anything else takes the original walker, with the same errors in the same
  order. Identifier validation accepts a canonical identifier with one precompiled match. The
  validity checker skips a union branch whose string-`const` discriminator (such as the method
  or the outcome) the instance contradicts, and reuses one validator per schema.
- **Kernel and storage.** Replay skips re-validating reference targets that are already
  projection keys. The stored state digest re-encodes only the records that changed; the cache
  holds each record's canonical text for as long as the ledger is open, about 1.5 times the
  snapshot's canonical text, where nothing was kept between appends before.
- **MCP bridge.** Launched as `finishup mcp serve`, the bridge starts without cyclic collection
  and serves over a frozen heap; launched with a leading root option
  (`finishup --home-project <dir> mcp serve`) it takes the full command line's path, where only
  the import heap is frozen. The advertised tool list is built once per bridge, and a result body
  is checked against the canonical profile once per text render.
- **Change capture.** Shown blobs are verified with two batched `git cat-file` calls, the
  repository fences ask `git rev-parse` once each, and the loose-object fence lists the object
  directory once.
- **Setup.** One connection observation lists Claude Code plugins once, hashes the host
  executable once and probes Codex once.

## Differences from the earlier behavior

- `--help` describes the 57 commands that listed no description, and `--deadline-ms` explains
  itself.
- The canonical codec can behave differently for a value mutated while it is being encoded; see
  the next section.
- An interrupt that lands in the roughly one millisecond while the invoked command is converted
  exits 130 without printing `cancelled`, as an interrupt during argument parsing already did.
- A failure's diagnostic record names `finishup.cli.entry` or `finishup.cli.lazy_command` as its
  origin where it named `finishup.cli.app`; the reason, the printed line and the exit code are
  the same.
- Until a protocol or configuration model is first used, `inspect.signature` of it shows the
  generic signature. Nothing in FinishUP reads it.
- Names that modules had only because they imported them (about 90, none in an `__all__`) are no
  longer importable from those modules. Names that moved to a lighter module are still importable
  from the old one as the same object; the hook-pairing objects report
  `finishup.domain.hook_pairing` as their `__module__`.
- In a build whose result-leaf registry is incomplete, the registry check fails at the first
  classification instead of at import. A correct build is unaffected.
- `finishup service stop` returns about half a second sooner. It has always answered once the
  service acknowledged the request, before the service process finished exiting, and the process
  still exits about as long after the request as before. The gap between the command returning
  and the process being gone therefore grew, from about 0.3 s to about 0.55 s measured here. A
  script that needs the process gone must wait for it; the instance-lifecycle packaging test
  relied on the old timing and now waits for the exit.

## Known difference in the canonical codec

The plain-value path reads a value twice, once to check it and once in the C encoder, where the
walker read each node once. A value that another thread or a finalizer mutates between those two
reads can be encoded as text the walker would have rejected, or raise the C encoder's
`ValueError` instead of the walker's error. Single-threaded inputs match the walker byte for
byte, including mappings whose iteration mutates the value: a differential fuzz of 2,000,000
seeds and a 5,870,560-case code-point sweep found no difference. A deliberate two-thread race
produced three float outputs in about three thousand attempts where the walker produced none.
Callers must not mutate a value while it is being encoded; the commit that adds the path is
self-contained for a maintainer who prefers the walker's guarantee to its speed.

## Measured and left alone

- **A native extension.** After the changes above, a C++ canonical encoder would save about 3 ms
  per MiB encoded, under 3% of a hook process, and would replace the pure-Python wheel with
  per-platform wheels for macOS and Linux. What remains is the creation of Python classes at
  import (about 127 ms of dataclasses and 64 ms of models for a workflow command), which an
  extension module does not remove. Only a separate native client for the six operations would
  move that, and it would have to reproduce validation, encoding, error rendering and exit codes
  byte for byte.
- **A lazy schema catalog for the MCP bridge.** It starts the bridge 13 to 20% faster with about
  32 MB less memory, but a package whose schema member and manifest digest were both rewritten
  would no longer be refused at startup unless the bridge touched that member. That changes an
  integrity check and needs a maintainer decision.
- **Skipping the canonical re-encode check for digest-verified schema members.** About 15 ms per
  connecting client; the same integrity question.
- **Reading only ownership fields from other workspaces granted observation.** With several such
  workspaces each hook decodes every other workspace's store, 25 to 80 ms each. A narrower read
  changes which malformed foreign stores make a hook fail.
- **Host-scoped discovery in setup.** Probing only the selected host saves about 300 ms, but a
  failure in another host's discovery would no longer reach the user.
- **Moving terminal-interface header discovery off the event loop.** It removes an 800 ms freeze
  on open, but lets the screen change while the refresh is still running.
- **Removing the whole-state validation loops in replay.** The remaining quadratic term, about
  half of replay time at 3,000 events. It is the kernel's integrity boundary and needs its own
  review.
- **Running commands on `asyncio` instead of `anyio`.** About 12 ms; equivalence of cancellation
  and interrupt handling could not be shown across roughly 120 call sites.

## Host and OS coverage

The changes are in shared code paths, so they apply to Codex, Claude Code and Cursor alike; the
hook tables above measure all three hook commands. Every number comes from Linux on CPython
3.14.6. An installed instance was provisioned and an upgrade over a still-running older service
was emulated by reinstalling the new build into the older instance: the older service kept
answering, `service restart` superseded it, and the ledger it had written read under the new
build. Not measured: macOS, Windows through WSL 2, other supported Python versions, a 2 vCPU
machine, and sessions driven by a real Codex, Claude Code or Cursor host.
