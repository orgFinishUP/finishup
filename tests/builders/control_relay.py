"""Streams, a scripted daemon and a scripted client session for in-process connection tests.

Ported from the relay tests of ADR-051 (shared by the edge-relay and direct-dial branches), without
the ``ssh`` stand-in and the Unix listener: this release opens no remote kind, so a test that
exercises a claim-bound connection drives it over an in-memory pair instead.

* ``MemoryStream``/``memory_pair`` — an in-memory ``ControlStream`` pair; closing one end ends
  the other end's reads.
* ``ScriptedDaemon`` — serves control connections the way the daemon's control loop does, with
  fixed answers: ``service_status`` succeeds, every other call gets a ``vault_locked`` error
  result, a call to ``SLOW_METHOD`` waits until it is cancelled (then ``request_cancelled``), and
  a session whose hello declared a workspace agent receives one ``workspace_call`` after its
  first call and must answer it. Every frame it reads and writes is recorded as exact payload
  bytes.
* ``run_scripted_session`` — drives one fixed session over any stream: a hello with a fixed
  nonce, one call per agent-scope method, a cancel, the workspace call and its reply. It returns
  the payload bytes the client received, so every transport can be compared byte for byte.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from collections.abc import Buffer
from typing import Final, cast

import pytest

from builders.server_profiles import TEST_REVISION
from finishup.client.helper_status import (
    RELAY_BINDING_BYTES,
    read_relay_binding,
    relay_binding,
    starts_relay_binding,
)
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlCallRequest,
    ControlError,
    ControlMethod,
    ControlResult,
    RepositoryPrivacyContext,
    ServiceState,
    ServiceStatus,
    WorkspaceCall,
    WorkspaceClaim,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.schemas import load_schema_catalog
from finishup.protocol.server_profile import ServerProfileRevision
from finishup.service.control_protocol import (
    ControlProtocolError,
    ControlStream,
    encode_control_frame,
    parse_control_request,
    read_control_frame,
    server_handshake,
    workspace_call_frame,
)

__all__ = [
    "RELAY_KEY",
    "hello_frame",
    "AGENT_METHODS",
    "call_request",
    "split_frames",
    "CLAIM_DIGEST",
    "SERVICE_ID",
    "WORKTREE_DIGEST",
    "SLOW_METHOD",
    "MemoryStream",
    "ScriptedDaemon",
    "memory_pair",
    "relay_binding_frame",
    "rpc_id",
    "run_scripted_session",
    "scripted_service",
    "service_status",
]

SERVICE_ID: Final = "svc_00000000-0000-4000-8000-0000000000a1"
CLAIM_DIGEST: Final = "sha256:" + "c1a1" * 16
WORKTREE_DIGEST: Final = "sha256:" + "d1e2" * 16
# The agent scope's methods, each called once by the scripted session (ADR-051 decision 9).
AGENT_METHODS: Final = (
    ControlMethod.START,
    ControlMethod.PUBLISH_WORK,
    ControlMethod.CHECK,
    ControlMethod.RESPOND,
    ControlMethod.STATUS,
    ControlMethod.RECEIPT,
    ControlMethod.SERVICE_STATUS,
)
SLOW_METHOD: Final = ControlMethod.STATUS
_CALL_ID: Final = "rpc_00000000-0000-4000-8000-00000000c0de"


def rpc_id(sequence: int) -> str:
    return f"rpc_00000000-0000-4000-8000-{sequence:012x}"


def service_status() -> ServiceStatus:
    return ServiceStatus(
        protocol_version="1.0",
        service_version="0.1.0",
        service_instance_id=SERVICE_ID,
        service_generation="1",
        state=ServiceState.LOCKED,
        state_reason="human_authority_unavailable",
        vault_mode="uninitialized",
        capabilities=(),
        session_monitor="unavailable",
    )


class MemoryStream:
    """One end of an in-memory byte stream; ``aclose`` ends the peer's reads."""

    def __init__(self, peer_identity: object) -> None:
        self.peer_identity = peer_identity
        self.other: MemoryStream | None = None
        self.closed = False
        self._chunks: asyncio.Queue[bytes] = asyncio.Queue()
        self._buffer = bytearray()
        self._ended = False

    async def receive(self, max_bytes: int) -> bytes:
        while not self._buffer:
            if self._ended:
                return b""
            chunk = await self._chunks.get()
            if not chunk:
                self._ended = True
                return b""
            self._buffer.extend(chunk)
        chunk = bytes(self._buffer[:max_bytes])
        del self._buffer[:max_bytes]
        return chunk

    async def send_all(self, data: Buffer) -> None:
        if self.closed or self.other is None:
            raise ConnectionError("memory_stream_closed")
        payload = bytes(data)
        if payload:
            self.other._chunks.put_nowait(payload)

    async def shutdown_write(self) -> None:
        """End the peer's reads (a half-close); this end still reads what the peer sends."""

        if self.closed or self.other is None:
            return
        self.other._chunks.put_nowait(b"")

    async def aclose(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.other is not None:
            self.other._chunks.put_nowait(b"")


def memory_pair() -> tuple[MemoryStream, MemoryStream]:
    """``(client end, server end)``; each end's ``peer_identity`` names the other side."""

    client_peer = object()
    server_peer = object()
    client = MemoryStream(server_peer)
    server = MemoryStream(client_peer)
    client.other = server
    server.other = client
    return client, server


def _payload(frame: object) -> bytes:
    return encode_control_frame(frame)[4:]


class _Tap:
    """A stream that records every byte read from it (``pending``: bytes already read, read
    again first)."""

    def __init__(self, inner: ControlStream, sink: bytearray, pending: bytes = b"") -> None:
        self._inner = inner
        self._sink = sink
        self._pending = pending

    @property
    def peer_identity(self) -> object:
        return self._inner.peer_identity

    async def receive(self, max_bytes: int) -> bytes:
        if self._pending:
            data, self._pending = self._pending[:max_bytes], self._pending[max_bytes:]
        else:
            data = await self._inner.receive(max_bytes)
        self._sink.extend(data)
        return data

    async def send_all(self, data: Buffer) -> None:
        await self._inner.send_all(data)

    async def aclose(self) -> None:
        await self._inner.aclose()


def split_frames(data: bytes) -> list[bytes]:
    """The payloads of a byte stream of length-prefixed frames (a trailing partial is dropped)."""

    payloads: list[bytes] = []
    offset = 0
    while offset + 4 <= len(data):
        (length,) = struct.unpack(">I", data[offset : offset + 4])
        if offset + 4 + length > len(data):
            break
        payloads.append(data[offset + 4 : offset + 4 + length])
        offset += 4 + length
    return payloads


class ScriptedDaemon:
    """Serves connections with fixed answers and records every frame's payload bytes."""

    def __init__(self) -> None:
        self.inbound: list[bytearray] = []
        self.sent: list[bytes] = []
        self.connections = 0
        self.replies: list[JsonObject] = []
        # Set when a workspace reply arrives, so a test waits on it rather than on time.
        self.replied = asyncio.Event()
        # The connections ``scripted_service`` serves, one task each.
        self.serving: list[asyncio.Task[None]] = []
        # While set, a workflow call is left unanswered (it stays under way) and ``held`` is set
        # once one arrives, so a test acts while a request is in flight without waiting on time.
        self.hold_calls = False
        self.held = asyncio.Event()
        # The server-profile revision this service issues (ADR-052): a remote hello is admitted
        # only under it. The default is the revision of the test profile a consented target
        # names (``builders.server_profiles``).
        self.profile_revision: ServerProfileRevision | None = TEST_REVISION
        # When set, a claim is keyed to this handle (as a ready service keys it) and recorded in
        # ``claims``; otherwise a claim-bound session has no handle, as with a locked vault.
        self.claim_handle: str | None = None
        self.claims: list[WorkspaceClaim] = []
        # The repository keys clients named in a relay binding (``serve(relay=True)``).
        self.relay_keys: list[str] = []
        # Cancels that named a call already answered (they crossed its answer): no-ops.
        self.late_cancels = 0

    async def _key_claim(self, claim: WorkspaceClaim) -> RepositoryPrivacyContext | None:
        self.claims.append(claim)
        return RepositoryPrivacyContext(
            commitment="hmac-sha256:" + "c" * 64,
            identity_kind="client_claim",
            workspace_handle=self.claim_handle,
        )

    def received(self, connection: int = -1) -> list[bytes]:
        """Every frame payload one connection sent the daemon, its hello first."""

        return split_frames(bytes(self.inbound[connection]))

    async def _send(self, stream: ControlStream, frame: object) -> None:
        encoded = encode_control_frame(frame)
        self.sent.append(encoded[4:])
        await stream.send_all(encoded)

    async def serve(self, stream: ControlStream, *, relay: bool = False) -> None:
        """Serve one connection until its peer ends it.

        With ``relay`` (standing in for the target's helper and the server behind it, as
        ``scripted_service`` does) a relay binding the client wrote before its hello is read as
        the helper reads it and recorded in ``relay_keys``, never served.
        """

        self.connections += 1
        sink = bytearray()
        self.inbound.append(sink)
        pending = b""
        if relay:
            pending = await stream.receive(1)
            if starts_relay_binding(pending):
                rest = b""
                while len(rest) < RELAY_BINDING_BYTES - 1:
                    chunk = await stream.receive(RELAY_BINDING_BYTES - 1 - len(rest))
                    if not chunk:
                        return
                    rest += chunk
                key = read_relay_binding(pending + rest)
                if key is None:
                    return
                self.relay_keys.append(key)
                pending = b""
        stream = _Tap(stream, sink, pending)
        write_lock = asyncio.Lock()
        slow: dict[str, asyncio.Event] = {}
        tasks: set[asyncio.Task[None]] = set()
        answered: set[str] = set()
        workspace_called = False
        try:
            session = await server_handshake(
                stream,
                stream.peer_identity,
                service_status(),
                # A service that issues no revision admits a claim as layer 1 did.
                profile_revision=None
                if self.profile_revision is None
                else (lambda: self.profile_revision),
                claim_context_resolver=None if self.claim_handle is None else self._key_claim,
            )
            while True:
                try:
                    frame = await read_control_frame(stream)
                except ControlProtocolError:
                    return
                if frame.get("kind") == "workspace_reply":
                    self.replies.append(frame)
                    self.replied.set()
                    continue
                request = parse_control_request(frame)
                if not isinstance(request, ControlCallRequest):
                    # As the service admits a cancel (``ControlSession.admit``): one that names a
                    # call already answered crossed its answer and is a no-op; one that names no
                    # call of this connection ends it, and every call on it with it.
                    running = slow.get(request.target_rpc_id)
                    if running is None:
                        if request.target_rpc_id in answered:
                            self.late_cancels += 1
                            continue
                        return
                    running.set()
                    continue
                if request.method is SLOW_METHOD and request.rpc_id.endswith("51f0"):
                    event = slow[request.rpc_id] = asyncio.Event()

                    async def answer_after_cancel(
                        call: ControlCallRequest = request, done: asyncio.Event = event
                    ) -> None:
                        await done.wait()
                        async with write_lock:
                            slow.pop(call.rpc_id, None)
                            answered.add(call.rpc_id)
                            await self._send(
                                stream, _result(call, ControlError("request_cancelled"))
                            )

                    task = asyncio.create_task(answer_after_cancel())
                    tasks.add(task)
                    continue
                if self.hold_calls and request.method is not ControlMethod.SERVICE_STATUS:
                    self.held.set()
                    continue
                async with write_lock:
                    answered.add(request.rpc_id)
                    await self._send(stream, _answer(request))
                    if session.workspace_agent is not None and not workspace_called:
                        workspace_called = True
                        await self._send(
                            stream,
                            workspace_call_frame(
                                WorkspaceCall(
                                    kind="workspace_call",
                                    protocol_version="1.0",
                                    call_id=_CALL_ID,
                                    service_instance_id=SERVICE_ID,
                                    service_generation="1",
                                    operation="read_task_base",
                                    arguments=JsonObject({"workspace": "client:0123456789abcdef"}),
                                    deadline_ms=5_000,
                                )
                            ),
                        )
        except ControlProtocolError:
            return
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            with contextlib.suppress(Exception):
                await stream.aclose()


def _result(request: ControlCallRequest, body: ControlError | ServiceStatus) -> ControlResult:
    return ControlResult(
        protocol_version="1.0",
        rpc_id=request.rpc_id,
        service_instance_id=request.service_instance_id,
        service_generation=request.service_generation,
        method=request.method,
        outcome="error" if isinstance(body, ControlError) else "ok",
        body=body,
    )


def _answer(request: ControlCallRequest) -> ControlResult:
    if request.method is ControlMethod.SERVICE_STATUS:
        return _result(request, service_status())
    return _result(request, ControlError("vault_locked"))


def _hello(
    *, agent: bool, server_profile: ServerProfileRevision | None = None
) -> dict[str, JsonValue]:
    hello: dict[str, JsonValue] = {
        "protocol_version": "1.0",
        "client_kind": "cli",
        "client_version": "0.1.0",
        "connection_nonce": "1f" * 32,
        "schema_manifest_digest": load_schema_catalog().manifest_digest,
        "presentation_context": {
            "render_mode": "machine_readable",
            "output_is_controlling_tty": False,
        },
    }
    if agent:
        hello["workspace_claim"] = {
            "schema_version": "1.0.0",
            "identity_kind": "git_common_root",
            "digest": CLAIM_DIGEST,
            "worktree": WORKTREE_DIGEST,
        }
        hello["workspace_agent"] = {
            "schema_version": "1.0.0",
            "operations": ["read_task_base"],
            "max_reply_bytes": 1_048_576,
        }
    if server_profile is not None:
        from finishup.protocol.server_profile import revision_to_json

        hello["server_profile"] = revision_to_json(server_profile)
    return hello


_ACTOR: Final[dict[str, JsonValue]] = {"actor_id": "harness:test", "actor_type": "harness"}
_CLIENT: Final[dict[str, JsonValue]] = {
    "kind": "test_client",
    "version": "0.1.0",
    "integration": "local_cli",
}
_GENESIS: Final[dict[str, JsonValue]] = {"sequence": "0", "head_digest": "genesis"}


def _envelope(sequence: int) -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": f"req_00000000-0000-4000-8000-{sequence:012x}",
        "actor": _ACTOR,
        "client": _CLIENT,
    }


def _session(sequence: int) -> dict[str, JsonValue]:
    return {
        "session_id": f"ses_00000000-0000-4000-8000-{sequence:012x}",
        "writer_id": f"wri_00000000-0000-4000-8000-{sequence:012x}",
    }


def _body(sequence: int, method: ControlMethod) -> object:
    """A schema-valid request body for one agent-scope method (its content is never acted on)."""

    from finishup.protocol.models import (
        CheckRequest,
        PublishWorkRequest,
        ReceiptRequest,
        RespondRequest,
        StartRequest,
        StatusRequest,
    )

    base = _envelope(sequence)
    if method is ControlMethod.START:
        return StartRequest.model_validate(
            {**base, "mode": "create", "task_title": "parity", "requested_view": "compact"}
        )
    if method is ControlMethod.PUBLISH_WORK:
        draft: dict[str, JsonValue] = {
            "event_id": f"evt_00000000-0000-4000-8000-{sequence:012x}",
            "schema": {"name": "plan_published", "version": "1.0.0"},
            "occurred_at": "2026-01-01T00:00:00.000Z",
            "causal_parents": [],
            "payload": {"plan_version": 1, "summary": "Plan", "obligation_refs": []},
            "artifact_refs": [],
            "evidence_refs": [],
        }
        return PublishWorkRequest.model_validate(
            {
                **base,
                **_session(sequence),
                "expected_frontier": _GENESIS,
                "event_drafts": [draft],
            }
        )
    if method is ControlMethod.CHECK:
        return CheckRequest.model_validate(
            {
                **base,
                **_session(sequence),
                "expected_frontier": _GENESIS,
                "mode": "deterministic_only",
            }
        )
    if method is ControlMethod.RESPOND:
        return RespondRequest.model_validate(
            {
                **base,
                **_session(sequence),
                "expected_frontier": _GENESIS,
                "finding_id": f"fnd_00000000-0000-4000-8000-{sequence:012x}",
                "finding_frontier": _GENESIS,
                "disposition": "acknowledged",
            }
        )
    if method is ControlMethod.STATUS:
        return StatusRequest.model_validate(
            {**base, **_session(sequence), "view": "compact", "limit": "10"}
        )
    if method is ControlMethod.RECEIPT:
        return ReceiptRequest.model_validate(
            {
                **base,
                **_session(sequence),
                "task_id": f"tsk_00000000-0000-4000-8000-{sequence:012x}",
                "expected_frontier": _GENESIS,
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    return JsonObject({})


def call_request(sequence: int, method: ControlMethod) -> ControlCallRequest:
    """One schema-valid call frame of the scripted session."""

    return ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=rpc_id(sequence),
        service_instance_id=SERVICE_ID,
        service_generation="1",
        method=method,
        body=_body(sequence, method),  # pyright: ignore[reportArgumentType]
    )


async def _read_payload(stream: ControlStream) -> bytes:
    return _payload(await read_control_frame(stream, eof_reason="handshake_rejected"))


async def run_scripted_session(
    stream: ControlStream,
    *,
    agent: bool = True,
    server_profile: ServerProfileRevision | None = None,
    relay: bool = False,
) -> list[bytes]:
    """Drive the fixed session over ``stream``; return every payload the client received.

    Bodies are empty objects: the scripted daemon answers by method alone, so no workflow body
    shape is involved and only framing, routing and correlation are under test. A hello for a
    server elsewhere names the consented ``server_profile`` revision (ADR-052). With ``relay``
    (a session through the target's helper) a hello that claims a workspace is preceded by the
    relay binding, as a client writes it.
    """

    received: list[bytes] = []
    if relay and agent:
        await stream.send_all(relay_binding_frame())
    await stream.send_all(encode_control_frame(_hello(agent=agent, server_profile=server_profile)))
    received.append(await _read_payload(stream))
    for index, method in enumerate(AGENT_METHODS):
        await stream.send_all(encode_control_frame(call_request(0x5100 + index, method)))
        if agent and index == 0:
            # The result and the server's workspace call may arrive in either order on a
            # transport that relays them on separate requests; record them result first.
            first, second = await _read_payload(stream), await _read_payload(stream)
            received.extend(
                sorted((first, second), key=lambda payload: b"workspace_call" in payload)
            )
            reply: dict[str, JsonValue] = {
                "kind": "workspace_reply",
                "protocol_version": "1.0",
                "call_id": _CALL_ID,
                "outcome": "unavailable",
                "result": None,
                "reason": "not_git",
            }
            await stream.send_all(encode_control_frame(reply))
        else:
            received.append(await _read_payload(stream))
    slow = call_request(0x51F0, SLOW_METHOD)
    await stream.send_all(encode_control_frame(slow))
    cancel: dict[str, JsonValue] = {
        "kind": "cancel",
        "protocol_version": "1.0",
        "rpc_id": rpc_id(0x5200),
        "service_instance_id": SERVICE_ID,
        "service_generation": "1",
        "target_rpc_id": rpc_id(0x51F0),
    }
    await stream.send_all(encode_control_frame(cancel))
    received.append(await _read_payload(stream))
    return received


def frame_bytes(payload: bytes) -> bytes:
    """A payload with its 4-byte big-endian length prefix."""

    return struct.pack(">I", len(payload)) + payload


def as_json(payload: bytes) -> dict[str, JsonValue]:
    import json

    return cast(dict[str, JsonValue], json.loads(payload))


def canonical(value: dict[str, JsonValue]) -> bytes:
    return canonical_encode(value)


def scripted_service(monkeypatch: pytest.MonkeyPatch) -> ScriptedDaemon:
    """Answer every dial of ``finishup.service.client.connect_control`` with a ``ScriptedDaemon``.

    Each dial gets its own in-memory pair, served until the client ends it (``serving`` keeps
    the tasks); ``connections`` counts dials, so a refusal test asserts it stays 0: nothing was
    dialled, let alone sent. Call it from a test that runs an event loop.
    """

    from finishup.service import client as client_module

    daemon = ScriptedDaemon()

    async def dial() -> MemoryStream:
        client_end, server_end = memory_pair()
        daemon.serving.append(asyncio.create_task(daemon.serve(server_end, relay=True)))
        return client_end

    monkeypatch.setattr(client_module, "connect_control", dial)
    return daemon


def hello_frame(
    *, agent: bool = False, server_profile: ServerProfileRevision | None = None
) -> bytes:
    """One encoded scripted hello (a claim and an agent with ``agent``)."""

    return encode_control_frame(_hello(agent=agent, server_profile=server_profile))


# The repository key a scripted relayed client names (``relay_binding_frame``).
RELAY_KEY: Final = "sha256:" + "b3" * 32


def relay_binding_frame(key: str = RELAY_KEY) -> bytes:
    """What a client writes on a relayed connection before a hello that claims a workspace."""

    return relay_binding(key)
