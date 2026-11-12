"""Provision, inspect, and dispose an independent FinishUP test instance (issue #604).

One instance is one directory tree beneath a short, owner-private base outside every repository:

    <base>/<tag>/dist/       the wheel built from the exact requested revision
    <base>/<tag>/runtime/    a virtual environment holding only that wheel (pinned to the root)
    <base>/<tag>/state/      the FINISHUP_ISOLATED_ROOT of that instance (config, data, state, run,
                             cache, log) sealed by the instance-identity marker
    <base>/<tag>/provenance.json   digest-only record of what was built and from where

``create`` builds the wheel with ``uv build --no-sources`` from the exact revision (refusing a
modified working tree unless ``--allow-dirty``), installs it into the runtime with ``uv``, and lets
the snapshot's own ``finishup instance create --bind-runtime`` seal the root. Because the runtime is
pinned, ``<base>/<tag>/runtime/bin/finishup`` resolves that root even when a host or shell drops the
environment variable, and never the everyday installation.

``dispose`` never leaves a launcher that has lost its pin, which would run ambient and reach the
everyday install (issue #1350):

1. It checks first and changes nothing on a refusal: the launcher must be pinned to this root, the
   root marked disposable, and no other process may hold the runtime (a host's bridge or hook, or
   any FinishUP process but the instance's own service; ``runtime_in_use``).
2. It withdraws the launchers: ``runtime/bin`` is renamed in one step, so no registered path can
   start the runtime any more, while the pin stays.
3. It stops only the service holding that root's singleton and removes the root through the
   runtime's own ``dispose_instance``, keeping the pin. A failure that removed nothing puts the
   launchers back, still pinned.
4. It prunes the retained runtimes, then removes the withdrawn launchers, the runtime with its pin,
   and the wheel.

Repeating ``dispose`` is a no-op, and it finishes a disposal an earlier run left part done.
Nothing here touches the everyday install, host configuration, or vaults.

An instance built from a revision before the FinishUP rename ships only the legacy ``yoetz``
launcher and package and reads ``YOETZ_ISOLATED_ROOT`` (ADR-028 upgrade tests). Every command
probes ``bin/finishup`` first, then ``bin/yoetz``, and drives whichever package that launcher
belongs to; snapshot commands never inherit either variable prefix (ADR-048).

This is contributor tooling; the shipped product surface is ``finishup instance``. Documented in
``docs/runbooks/test-instances.md``.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, cast

_REPO_ROOT: Final = Path(__file__).resolve().parents[1]
# Frozen legacy identifier (ADR-048): existing instances' provenance.json carries this schema tag.
_PROVENANCE_SCHEMA: Final = "yoetz.test-instance-provenance/1"
_DEFAULT_BASE: Final = Path.home() / ".yz-instances"
_TAG_ALPHABET: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_VCS_MARKERS: Final = (".git", ".hg", ".svn", ".jj")
# Launcher name -> the package it runs, FinishUP first. A pre-rename runtime has only the legacy
# ``yoetz`` launcher and package; a runtime that ships both resolves to FinishUP (ADR-048).
_RUNTIME_LAUNCHERS: Final = (("finishup", "finishup"), ("yoetz", "yoetz"))
# Product variable prefixes a snapshot command must not inherit: FinishUP and legacy (ADR-048).
_ENV_PREFIXES: Final = ("FINISHUP_", "YOETZ_")
_ISOLATED_ROOT_ENV_NAMES: Final = ("FINISHUP_ISOLATED_ROOT", "YOETZ_ISOLATED_ROOT")
# Frozen legacy identifier (ADR-048): the runtime pin's file name inside the runtime prefix.
_PIN_NAME: Final = "yoetz-instance-pin.json"
# Where ``dispose`` moves ``runtime/bin`` before anything is removed (issue #1350): no host
# registration names this path, and the interpreter still finds the runtime from here.
_WITHDRAWN_BIN: Final = ".bin-withdrawn"
# The lifecycles ``finishup instance dispose`` removes (ADR-028 decision 4).
_DISPOSABLE_LIFECYCLES: Final = frozenset({"persistent", "disposable"})
_PINNED_BINDINGS: Final = frozenset({"runtime_pin", "environment_and_pin"})
_GENERATION: Final = re.compile(r"[0-9a-f]{64}\Z")
_LEASE_NAME: Final = ".in-use"


class ProvisionError(Exception):
    """A bounded provisioning failure; the message names the condition, never content."""


def _fail(message: str) -> ProvisionError:
    return ProvisionError(message)


def _run(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    timeout: int = 600,
) -> subprocess.CompletedProcess[bytes]:
    # umask 022 so a runtime or interpreter uv creates here is never group/world-writable,
    # whatever the operator's umask (Ubuntu and Fedora default to 0002).
    return subprocess.run(  # noqa: S603 - fixed argv assembled from validated inputs
        args, capture_output=True, env=env, cwd=cwd, timeout=timeout, check=False, umask=0o022
    )


def _clean_env(home: Path | None = None) -> dict[str, str]:
    """The environment a snapshot command runs under: no FINISHUP_ or YOETZ_ variables leak in."""

    env = {name: value for name, value in os.environ.items() if not name.startswith(_ENV_PREFIXES)}
    if home is not None:
        env["HOME"] = str(home)
    return env


def _runtime_launcher(runtime: Path, directory: str = "bin") -> tuple[Path, str] | None:
    """Return the runtime's launcher and its package: ``bin/finishup``, else ``bin/yoetz``.

    ``directory`` is ``bin``, or the withdrawn copy of it during a disposal.
    """

    for name, package in _RUNTIME_LAUNCHERS:
        launcher = runtime / directory / name
        if launcher.is_file():
            return launcher, package
    return None


def _environment_export(root: Path) -> str:
    """Both isolation-root spellings with one value, so either launcher generation isolates."""

    return " ".join(f"{name}={root}" for name in _ISOLATED_ROOT_ENV_NAMES)


def _digest_bytes(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1_048_576), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _identity_digest(path: Path) -> str:
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        resolved = path
    return "sha256:" + hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()


def _validate_tag(tag: str) -> str:
    if not tag or len(tag) > 32 or set(tag) - _TAG_ALPHABET or tag.startswith("-"):
        raise _fail("tag_invalid: use 1-32 lowercase letters, digits, or hyphens")
    return tag


def _validate_base(base: Path) -> Path:
    if not base.is_absolute():
        raise _fail("base_invalid: --base must be absolute")
    for ancestor in (base, *base.parents):
        if any((ancestor / marker).exists() for marker in _VCS_MARKERS):
            raise _fail("base_in_repository: choose a base outside every repository")
    if base.is_relative_to(Path("/tmp")) or base.is_relative_to(Path("/private/tmp")):
        raise _fail("base_shared_temp: choose an owner-private base such as ~/.yz-instances")
    return base


def _layout(base: Path, tag: str) -> dict[str, Path]:
    root = base / tag
    return {
        "root": root,
        "dist": root / "dist",
        "runtime": root / "runtime",
        "state": root / "state",
        "src": root / "src",
        "provenance": root / "provenance.json",
    }


def _resolve_revision(checkout: Path, revision: str) -> tuple[str, bool]:
    resolved = _run(["git", "-C", str(checkout), "rev-parse", "--verify", f"{revision}^{{commit}}"])
    if resolved.returncode != 0:
        raise _fail(
            "revision_unresolvable: the requested revision is not a commit in that checkout"
        )
    sha = resolved.stdout.decode("ascii").strip()
    head = _run(["git", "-C", str(checkout), "rev-parse", "HEAD"]).stdout.decode("ascii").strip()
    return sha, sha == head


def _tree_modified(checkout: Path) -> bool:
    status = _run(["git", "-C", str(checkout), "status", "--porcelain", "--untracked-files=no"])
    return status.returncode != 0 or bool(status.stdout.strip())


def _export_revision(checkout: Path, sha: str, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(dir=destination.parent) as scratch:
        archive = Path(scratch) / "src.tar"
        with archive.open("wb") as sink:
            exported = subprocess.run(  # noqa: S603 - fixed git argv
                ["git", "-C", str(checkout), "archive", "--format=tar", sha],
                stdout=sink,
                stderr=subprocess.PIPE,
                check=False,
            )
        if exported.returncode != 0:
            raise _fail("revision_export_failed: git archive did not produce the tree")
        with tarfile.open(archive) as tar:
            tar.extractall(destination, filter="data")


def _build_wheel(source: Path, dist: Path) -> Path:
    dist.mkdir(mode=0o700, exist_ok=True)
    built = _run(["uv", "build", "--no-sources", "-o", str(dist), str(source)])
    if built.returncode != 0:
        sys.stderr.write(built.stderr.decode("utf-8", errors="replace"))
        raise _fail("wheel_build_failed")
    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        raise _fail("wheel_build_ambiguous: expected exactly one wheel")
    return wheels[0]


# Mirrors finishup.adapters.release_runtime.HASH_BYTECODE_EPOCH: any non-empty SOURCE_DATE_EPOCH
# makes uv's --compile-bytecode write checked-hash pycs, which the retained runtime reuses.
_HASH_BYTECODE_EPOCH: Final = "315532800"


def _hash_bytecode_env(env: dict[str, str]) -> dict[str, str]:
    """The install child's environment only; an epoch the operator exports is kept."""

    install_env = dict(env)
    if not install_env.get("SOURCE_DATE_EPOCH"):
        install_env["SOURCE_DATE_EPOCH"] = _HASH_BYTECODE_EPOCH
    return install_env


def _install_runtime(runtime: Path, wheel: Path, python: str, env: dict[str, str]) -> Path:
    created = _run(["uv", "venv", "--python", python, str(runtime)], env=env)
    if created.returncode != 0:
        sys.stderr.write(created.stderr.decode("utf-8", errors="replace"))
        raise _fail("runtime_venv_failed")
    interpreter = runtime / "bin" / "python"
    args = ["uv", "pip", "install", "--compile-bytecode", "--python", str(interpreter), str(wheel)]
    install_env = _hash_bytecode_env(env)
    installed = _run([*args[:2], "--offline", *args[2:]], env=install_env)
    if installed.returncode != 0:
        installed = _run(args, env=install_env)
    if installed.returncode != 0:
        sys.stderr.write(installed.stderr.decode("utf-8", errors="replace"))
        raise _fail("runtime_install_failed")
    found = _runtime_launcher(runtime)
    if found is None:
        raise _fail("runtime_launcher_missing")
    _remove_foreign_write(runtime)
    return found[0]


def _remove_foreign_write(runtime: Path) -> None:
    """Clear group/other write on the runtime this script just created.

    uv may hard-link package files from a cache written under a looser umask; the runtime
    refuses anything another account can write, so the copy is made owner-writable only.
    Links are never followed: the base interpreter is the operator's to repair.
    """

    for path in (runtime, *runtime.rglob("*")):
        facts = path.lstat()
        if stat.S_ISLNK(facts.st_mode):
            continue
        mode = stat.S_IMODE(facts.st_mode)
        if mode & 0o022:
            path.chmod(mode & ~0o022)


def _snapshot_command(launcher: Path, args: list[str], env: dict[str, str]) -> dict[str, object]:
    result = _run([str(launcher), *args, "--json"], env=env)
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode("utf-8", errors="replace"))
        raise _fail(
            f"snapshot_command_failed: {launcher.name} {' '.join(args)} exited {result.returncode}"
        )
    parsed = json.loads(result.stdout)
    if not isinstance(parsed, dict):
        raise _fail("snapshot_command_invalid_output")
    return cast(dict[str, object], parsed)


def _write_private_json(path: Path, body: dict[str, object]) -> None:
    encoded = json.dumps(body, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, encoded)
    finally:
        os.close(descriptor)


def _read_provenance(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    parsed = json.loads(path.read_bytes())
    return cast(dict[str, object], parsed) if isinstance(parsed, dict) else None


def command_create(args: argparse.Namespace) -> dict[str, object]:
    base = _validate_base(Path(args.base).expanduser())
    tag = _validate_tag(args.tag)
    checkout = Path(args.checkout).expanduser().resolve()
    if not (checkout / "pyproject.toml").is_file():
        raise _fail("checkout_invalid: --checkout must be a FinishUP source checkout")
    base.mkdir(mode=0o700, exist_ok=True)
    os.chmod(base, 0o700)
    layout = _layout(base, tag)
    if layout["root"].exists():
        raise _fail("instance_exists: dispose that tag first or choose another")
    layout["root"].mkdir(mode=0o700)
    try:
        sha, is_head = _resolve_revision(checkout, args.revision)
        source_state = "clean"
        source = checkout
        if is_head:
            if _tree_modified(checkout):
                if not args.allow_dirty:
                    raise _fail(
                        "checkout_modified: the working tree differs from HEAD; commit, stash, "
                        "pass --revision <commit>, or pass --allow-dirty to record source_state "
                        "modified"
                    )
                source_state = "modified"
        else:
            _export_revision(checkout, sha, layout["src"])
            source = layout["src"]
        wheel = _build_wheel(source, layout["dist"])
        package_digest = _digest_bytes(wheel)
        env = _clean_env()
        launcher = _install_runtime(layout["runtime"], wheel, args.python, env)
        create_args = [
            "instance",
            "create",
            "--root",
            str(layout["state"]),
            "--lifecycle",
            args.lifecycle,
            "--source-ref",
            sha,
            "--source-state",
            source_state,
            "--package-digest",
            package_digest,
            "--bind-runtime",
        ]
        if args.expires_in is not None:
            create_args += ["--expires-in", str(args.expires_in)]
        created = _snapshot_command(launcher, create_args, env)
        provenance: dict[str, object] = {
            "schema": _PROVENANCE_SCHEMA,
            "tag": tag,
            "lifecycle": args.lifecycle,
            "installation_id": created.get("installation_id"),
            "created_at": created.get("created_at"),
            "expires_at": created.get("expires_at"),
            "source_ref": sha,
            "source_state": source_state,
            "package_version": created.get("package_version"),
            "package_digest": package_digest,
            "wheel_name": wheel.name,
            "runtime_digest": _identity_digest(layout["runtime"]),
            "state_digest": _identity_digest(layout["state"]),
            "provisioned_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        }
        _write_private_json(layout["provenance"], provenance)
    except BaseException:
        shutil.rmtree(layout["root"], ignore_errors=True)
        raise
    return {
        **provenance,
        "launcher": str(launcher),
        "isolated_root": str(layout["state"]),
        "environment_export": _environment_export(layout["state"]),
    }


def command_status(args: argparse.Namespace) -> dict[str, object]:
    layout = _layout(_validate_base(Path(args.base).expanduser()), _validate_tag(args.tag))
    provenance = _read_provenance(layout["provenance"])
    if layout["root"].exists() and _runtime_launcher(layout["runtime"], _WITHDRAWN_BIN):
        # An earlier dispose withdrew the launchers and stopped part way: nothing can start this
        # instance; dispose again to finish. No launcher is run here.
        return {"tag": args.tag, "state": "disposing", "provenance": provenance}
    found = _runtime_launcher(layout["runtime"])
    if found is not None and not (layout["runtime"] / _PIN_NAME).is_file():
        # Its launcher lost its pin (left by a dispose before issue #1350's fix) and would run
        # ambient: never run it, dispose to remove it.
        return {"tag": args.tag, "state": "unpinned", "provenance": provenance}
    if provenance is None or found is None:
        return {"tag": args.tag, "state": "absent"}
    status = _snapshot_command(found[0], ["instance", "status"], _clean_env())
    return {"tag": args.tag, "state": "present", "provenance": provenance, "instance": status}


def _held_leases(releases: Path) -> list[Path]:
    """The retained runtimes' lease files some process holds (``adapters.release_runtime``).

    Every serving process of the runtime (an MCP bridge, a hook, the service) runs from a retained
    copy and holds that copy's lease shared for its whole life. A brief non-blocking exclusive try
    tells held from free and is released at once; it never waits and never removes anything.
    """

    held: list[Path] = []
    if not releases.is_dir():
        return held
    for generation in sorted(releases.iterdir()):
        if not _GENERATION.match(generation.name):
            continue
        lease = generation / _LEASE_NAME
        try:
            descriptor = os.open(lease, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            continue
        except OSError:
            held.append(lease)
            continue
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                held.append(lease)
                continue
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
    return held


def _lease_holders(leases: list[Path], *, proc: Path = Path("/proc")) -> set[int] | None:
    """The processes that have any of ``leases`` open, or ``None`` when this computer cannot say.

    Linux: ``/proc/<pid>/fd`` of the operator's own processes. Elsewhere (macOS): ``lsof -t``.
    Another account's processes are not seen; they cannot open these owner-only files.
    """

    targets = {os.path.realpath(lease) for lease in leases}
    if (proc / "self" / "fd").is_dir():
        found: set[int] = set()
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                descriptors = list((entry / "fd").iterdir())
            except OSError:
                continue
            for descriptor in descriptors:
                try:
                    if os.readlink(descriptor) in targets:
                        found.add(int(entry.name))
                        break
                except OSError:
                    continue
        return found
    lsof = shutil.which("lsof") or ("/usr/sbin/lsof" if Path("/usr/sbin/lsof").is_file() else None)
    if lsof is None:
        return None
    listed = _run([lsof, "-t", "--", *sorted(targets)], timeout=60)
    if listed.returncode not in {0, 1}:
        return None
    return {int(token) for token in listed.stdout.split() if token.isdigit()}


def _process_tree(pid: int) -> set[int] | None:
    """``pid`` and its descendants (``ps``), or ``None`` when ``ps`` cannot list them."""

    listed = _run(["ps", "-A", "-o", "pid=", "-o", "ppid="], timeout=30)
    if listed.returncode != 0:
        return None
    children: dict[int, list[int]] = {}
    for line in listed.stdout.decode("ascii", errors="replace").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0].isdigit() and fields[1].isdigit():
            children.setdefault(int(fields[1]), []).append(int(fields[0]))
    tree, pending = {pid}, [pid]
    while pending:
        for child in children.get(pending.pop(), []):
            if child not in tree:
                tree.add(child)
                pending.append(child)
    return tree


_IN_USE: Final = (
    "runtime_in_use: a host session still runs this instance (an MCP bridge, a hook, or another "
    "FinishUP process); nothing was stopped or removed, and the instance is still in place and "
    "pinned. Close that host session, or remove FinishUP from that host, then dispose again"
)


# After the launchers were withdrawn: the state is gone (or going), so a copy still running fails
# closed (its own pin names the removed root), and nothing can start the instance again.
_STILL_RUNNING: Final = (
    "runtime_in_use: a process that started before this disposal still runs a copy of the "
    "instance's runtime. The instance's launchers are withdrawn, so nothing can start it, and "
    "that copy cannot reach any other install. Close it, then dispose again to remove the rest"
)


def _refuse_in_use(releases: Path, status: dict[str, object]) -> None:
    """Refuse, before anything is stopped or removed, while any process but the service holds it.

    What this sees: every serving process (bridges, hooks, the service, upgrades), because each
    holds its retained runtime's lease. What it cannot see: a command started from the runtime
    itself that serves nothing (``status``, ``start`` and the like hold no lease); a host that is
    registered but not running (it finds the launchers gone after disposal, and fails); and a
    process that starts after this check (the withdrawn launchers stop new ones).
    """

    held = _held_leases(releases)
    if not held:
        return
    holder = status.get("service_holder")
    pid = cast(dict[str, object], holder).get("pid") if isinstance(holder, dict) else None
    if type(pid) is not int:
        raise _fail(_IN_USE)
    holders = _lease_holders(held)
    tree = _process_tree(pid)
    if holders is None or tree is None:
        raise _fail(
            "runtime_in_use_unverifiable: this instance's service is running, and this computer "
            "cannot show which other programs use its runtime; nothing was stopped or removed. "
            "Stop it with the instance's launcher (service stop), close its host sessions, then "
            "dispose again"
        )
    if holders - tree:
        raise _fail(_IN_USE)


def _state_intact(layout: dict[str, Path]) -> bool:
    return (layout["state"] / "state" / "instance-identity.json").is_file()


def _dispose_bootstrap(package: str) -> str:
    """``dispose_instance`` with the runtime's own package, keeping the pin (issue #1350).

    The pin is the only thing between the runtime and the everyday install, so it goes with the
    runtime itself, last; ``runtime_prefix`` names the withdrawn launcher folder, which has none.
    """

    return (
        "import json,sys; from pathlib import Path; "
        f"from {package}.cli.instance import dispose_instance; "
        f"from {package}.config.installation import InstanceIdentityError; "
        f"from {package}.config.paths import PathSafetyError\n"
        "a = json.loads(sys.argv[1])\n"
        "try:\n"
        "    r = dispose_instance(root=Path(a['root']), runtime_prefix=Path(a['prefix']), "
        "retain_logs=Path(a['logs']) if a['logs'] else None)\n"
        "except InstanceIdentityError as e:\n"
        "    print(json.dumps({'refused': e.reason})); sys.exit(3)\n"
        "except PathSafetyError as e:\n"
        "    print(json.dumps({'refused': e.reason_code})); sys.exit(3)\n"
        "print(json.dumps(r))"
    )


def _refusal_token(stdout: bytes) -> str:
    try:
        parsed = json.loads(stdout)
    except ValueError:
        return "dispose_failed"
    token = cast(dict[str, object], parsed).get("refused") if isinstance(parsed, dict) else None
    return token if isinstance(token, str) and token.isidentifier() else "dispose_failed"


def command_dispose(args: argparse.Namespace) -> dict[str, object]:
    layout = _layout(_validate_base(Path(args.base).expanduser()), _validate_tag(args.tag))
    if not layout["root"].exists():
        return {"tag": args.tag, "state": "absent", "disposed": False}
    runtime = layout["runtime"]
    bin_dir, withdrawn = runtime / "bin", runtime / _WITHDRAWN_BIN
    releases = runtime.parent / f".{runtime.name}-releases"
    if bin_dir.exists() and withdrawn.exists():
        raise _fail("instance_layout_invalid: both the launchers and a withdrawn copy exist")
    found = _runtime_launcher(runtime)
    if found is not None:
        if (runtime / _PIN_NAME).is_file() and layout["state"].exists():
            # 1. Check, changing nothing: pinned to this root, disposable, held by no host.
            status = _snapshot_command(found[0], ["instance", "status"], _clean_env())
            if status.get("mode") != "isolated" or status.get("binding") not in _PINNED_BINDINGS:
                raise _fail("instance_not_pinned: the launcher is not pinned to this instance")
            if status.get("lifecycle") not in _DISPOSABLE_LIFECYCLES:
                raise _fail("instance_not_disposable: the root is not a disposable instance")
            _refuse_in_use(releases, status)
        # Otherwise the launcher lost its pin, or names a root that is gone, in an earlier dispose:
        # it is never run, only withdrawn.
        # 2. Withdraw the launchers in one rename; the pin stays until the runtime goes.
        os.rename(bin_dir, withdrawn)
    elif withdrawn.exists() and _held_leases(releases) and not layout["state"].exists():
        raise _fail(_STILL_RUNNING)
    ran = _runtime_launcher(runtime, _WITHDRAWN_BIN)
    python = withdrawn / "python"
    outcome: object = {"disposed": False, "state": "absent"}
    if layout["state"].exists():
        # 3. Stop the root's own service and remove the root, keeping the pin.
        package = "finishup" if ran is None else ran[1]
        disposer = [str(python), "-I"] if python.exists() else [sys.executable]
        logs = (
            None if args.retain_logs is None else str(Path(args.retain_logs).expanduser().resolve())
        )
        request = {"root": str(layout["state"]), "prefix": str(withdrawn), "logs": logs}
        result = _run(
            [*disposer, "-c", _dispose_bootstrap(package), json.dumps(request)], env=_clean_env()
        )
        if result.returncode != 0:
            sys.stderr.write(result.stderr.decode("utf-8", errors="replace"))
            token = _refusal_token(result.stdout)
            if _state_intact(layout) and (runtime / _PIN_NAME).is_file() and withdrawn.exists():
                os.rename(withdrawn, bin_dir)
                raise _fail(
                    f"instance_dispose_failed: {token}: the instance is still in place and "
                    "pinned; its launchers are back"
                )
            raise _fail(
                f"instance_dispose_incomplete: {token}: part of the instance was removed; its "
                "launchers stay withdrawn, so nothing can start it. Dispose again"
            )
        outcome = json.loads(result.stdout)
    if releases.exists() and python.exists():
        # 4. Newer installed processes keep read-only runtime copies; prune with the runtime's
        # own lease-aware cleanup, then remove everything, the withdrawn launchers first.
        cleaned = _run(
            [str(python), "-I", "-c", _prune_bootstrap("finishup" if ran is None else ran[1])],
            env=_clean_env(),
            timeout=60,
        )
        if cleaned.returncode != 0:
            raise _fail("runtime_cleanup_failed: retained runtimes were left in place")
        counts = json.loads(cleaned.stdout)
        if not isinstance(counts, list):
            raise _fail("runtime_cleanup_failed: retained runtimes were left in place")
        values = cast(list[object], counts)
        if len(values) != 2 or type(values[1]) is not int or values[1] != 0:
            raise _fail(_STILL_RUNNING)
    elif _held_leases(releases):
        raise _fail(_STILL_RUNNING)
    if withdrawn.exists():
        shutil.rmtree(withdrawn)
    shutil.rmtree(layout["root"])
    return {
        "tag": args.tag,
        "state": "removed",
        "disposed": True,
        "launchers_withdrawn": True,
        "instance": outcome,
    }


def _prune_bootstrap(package: str) -> str:
    """The retained-runtime cleanup, run with the package the instance's runtime ships."""

    return (
        "import json,sys; from pathlib import Path; "
        f"from {package}.adapters.release_runtime import prune_release_runtimes; "
        "print(json.dumps(prune_release_runtimes(Path(sys.prefix), wait_seconds=5.0)))"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--base", default=str(_DEFAULT_BASE), help="Owner-private base directory."
        )
        command.add_argument("--tag", required=True, help="Instance name beneath the base.")
        command.add_argument("--json", action="store_true", help="Emit JSON instead of text.")

    create = sub.add_parser("create", help="Build, install, and seal a new instance.")
    common(create)
    create.add_argument("--checkout", default=str(_REPO_ROOT), help="Source checkout to build.")
    create.add_argument("--revision", default="HEAD", help="Commit to build (default HEAD).")
    create.add_argument("--lifecycle", choices=("persistent", "disposable"), default="disposable")
    create.add_argument("--expires-in", type=float, default=None, help="Hours until expiry.")
    create.add_argument("--allow-dirty", action="store_true", help="Record a modified tree.")
    create.add_argument("--python", default=sys.executable, help="Interpreter for the runtime.")

    status = sub.add_parser("status", help="Report the instance's provenance and status.")
    common(status)

    dispose = sub.add_parser("dispose", help="Stop, remove, and forget the instance.")
    common(dispose)
    dispose.add_argument("--retain-logs", default=None, help="Copy logs here before removal.")
    return parser


def _render(result: dict[str, object]) -> str:
    lines = [f"{key}: {value}" for key, value in result.items() if not isinstance(value, dict)]
    for key, value in result.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            lines.extend(
                f"  {inner}: {item}" for inner, item in cast(dict[str, object], value).items()
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    handlers = {"create": command_create, "status": command_status, "dispose": command_dispose}
    try:
        result = handlers[args.command](args)
    except ProvisionError as error:
        sys.stderr.write(f"{error}\n")
        return 2
    sys.stdout.write(
        (json.dumps(result, indent=2, sort_keys=True) if args.json else _render(result)) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
