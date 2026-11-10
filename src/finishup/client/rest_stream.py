"""The frame-to-REST mapping state machine (ADR-053, design v2 section 8.4).

``RestControlStream`` is a ``ControlStream``: a ``ServiceClient`` reads and writes ordinary control
frames on it (the direct style), and the target's helper pumps a local connection's frames through
it (the relay style), so **one mapping serves both** and every check the control path makes (the
gate before the dial, the authorization before every frame and on its watch, the helper's
per-frame check) holds over REST unchanged. Underneath is the one REST client
(``client.rest_client.RestTransport``).

**States.** ``await_hello`` → ``opening`` → ``open`` → (``ended``) → ``closing`` → ``closed``.

* **Hello and claim.** The first client frame must be a ``control-hello``. One naming a
  ``workspace_locator`` is never sent anywhere (a path on this computer never leaves it): the
  stream ends unanswered. Otherwise ``GET /v1/session`` with the hello's claim, consented revision
  and client kind; its answer becomes the hello-result the service would give (status, binding,
  handle, the revision; the methods are the client kind's own, a key's scope gap is a per-call
  ``method_forbidden``). A refusal ends the stream unanswered and names its phase
  (``failure_phase``): ``server_profile_changed`` (409), ``remote_auth_failed`` (401),
  ``remote_incompatible`` (404, 412, a document this release refuses), ``remote_service_not_running``
  (503), or the transport's phase. A hello declaring an agent whose claim was keyed registers it
  (``POST /v1/agents``) and starts one work long-poll; every call then names that agent
  (``finishup-agent``), so the server gives the call's workspace operations to this connection's
  own agent first, as it does on a control connection.
* **Pushed workspace calls.** Each call a poll returns is written to the client as its
  ``workspace_call`` frame, in order; each ``workspace_reply`` the client writes is
  ``POST /v1/agents/{id}/replies``. An agent the server no longer knows (``agent_unknown``: its
  lease ran out, the service restarted, its key was revoked) ends the stream, as a dropped control
  connection does, and the client connects again.
* **Calls.** The operation id is the frame's ``rpc_id``; ``POST /v1/{method}`` with the claim,
  the revision, the client kind, the service instance and generation, the deadline and the route
  and host profiles; a ``202`` is long-polled at ``/v1/operations/{id}`` until it answers; an
  ``operation_limit`` refusal (never dispatched) is retried with growing waits within the call's
  deadline. A ``409`` is the call's ``server_profile_changed`` error result.
* **Cancellation order.** A ``cancel`` always follows its call: the client wrote the call frame
  first, so its ``POST`` is already on its way when ``DELETE`` is sent. A ``DELETE`` sent before the
  server admitted the call answers ``operation_unknown`` and changes nothing: whatever order the
  answers come back in, it is sent again once the ``POST`` was answered, while the call runs (a
  ``DELETE`` that was not answered too). A call answered done drops its cancel (the result is
  final); one still running goes on to its own ``request_cancelled`` result.
* **Deadlines.** A call's ``deadline_ms`` is one absolute deadline for everything the call sends
  and waits for: every request's own bound, every retry's wait and every long-poll's ``wait_ms``
  end with it, and no ``POST`` is sent again after it (its result is then ``request_timeout``:
  the caller stopped waiting and the outcome is unknown). The caller's own deadline (a hook's,
  layer 4 decision 17) still spans the whole connection.
* **Authorization before every request.** ``may_send`` (and every check ``bind`` adds: a relayed
  stream's own admission and repository) is asked right before each request, the agent's
  registration, every retry and every poll included; once it refuses, nothing more is sent (the
  stream ends ``server_authorization_changed``, or the bound check's own phase).
* **Reconnect and unknown outcomes.** A ``POST`` whose answer was lost is sent again with the same
  operation id, at most ``_ATTEMPTS`` times (the server answers the operation it already admitted:
  at most once). A poll that fails is retried the same way. When a call's outcome cannot be learned
  (its answer expired, ``operation_unknown``, or the server stayed unreachable after it may have
  been admitted), its result is ``request_timeout``: the outcome is unknown and the ADR-030
  continuation says to repeat it under its original identity; the stream then ends.
* **Stable request ids across restarts.** The workflow ``request_id`` in every body is untouched:
  it is the kernel's idempotency key across a helper's or a bridge's restart. The operation id is
  stable across HTTP retries within one stream.
* **Close** (A-STOP-DELETE). Courtesy ``DELETE``s for the agent and for calls still running,
  bounded at one second in all and never sent once ``may_send`` says nothing may be sent (this
  computer is zero-network, or the admission lapsed); the server ends an agent whose polls stop and
  forgets answers on its own.

Nothing here logs or raises a host, URL, path or body: closed phases only.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from collections.abc import Awaitable, Buffer, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, Literal, cast

from finishup.adapters.control.unix_socket import LocalControlTransportError
from finishup.client.rest_client import RestAnswer, RestTransport, RestUnavailable
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlCallRequest,
    ControlCancelRequest,
    ControlClientKind,
    ControlError,
    ControlResult,
    WorkspaceAgentDeclaration,
    WorkspaceClaim,
)
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.server_profile import (
    ProfileError,
    ServerProfileRevision,
    revision_from_json,
)
from finishup.rest.contract import (
    AGENTS_PATH,
    HEADER_AGENT,
    HEADER_DEADLINE_MS,
    HEADER_HOST_PROFILE,
    HEADER_OPERATION_ID,
    HEADER_OUTCOME,
    HEADER_ROUTE_PROFILE,
    HEADER_SERVICE_GENERATION,
    HEADER_SERVICE_INSTANCE,
    MAX_WAIT_MS,
    SESSION_PATH,
    RestDocumentError,
    agent_declaration_document,
    parse_agent_registration,
    parse_agent_work,
    parse_session,
)
from finishup.service.control_protocol import (
    MAX_CONTROL_FRAME_BYTES,
    ControlProtocolError,
    decode_control_frame,
    encode_control_frame,
    hello_result_for,
    parse_control_request,
)

__all__ = ["RestControlStream", "RestPeerIdentity"]

# How many times a request whose answer was lost is sent again (same operation id).
_ATTEMPTS: Final = 3
_RETRY_FIRST_SECONDS: Final = 0.25
_BUSY_FIRST_SECONDS: Final = 0.25
_BUSY_MAX_SECONDS: Final = 2.0
_BUSY_TOTAL_SECONDS: Final = 30.0
# The close's courtesy DELETEs, in all.
_CLOSE_SECONDS: Final = 1.0
_WAIT_PARAM: Final = str(MAX_WAIT_MS)
_MAX_WORK_BYTES: Final = MAX_CONTROL_FRAME_BYTES * 2
# A long-poll's answer needs this much time past its ``wait_ms`` to come back.
_POLL_MARGIN_SECONDS: Final = 1.0
_WITHHELD: Final = "server_authorization_changed"


class RestPeerIdentity:
    """The opaque peer of a REST stream (the server is named nowhere)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "RestPeerIdentity(<server elsewhere>)"


@dataclass(slots=True)
class _Call:
    request: ControlCallRequest
    admitted: asyncio.Event = field(default_factory=asyncio.Event)
    pending: bool = False
    done: bool = False
    cancel_wanted: bool = False
    cancel_sent: bool = False
    cancel_attempts: int = 0


class _Withheld(Exception):
    """Nothing may be sent now: the stream's authorization refused (``phase``)."""

    def __init__(self, phase: str) -> None:
        self.phase = phase
        super().__init__(phase)


class _DeadlinePassed(Exception):
    """The call's own deadline passed: nothing more is sent or waited for."""


def _phase_of(answer: RestAnswer) -> str:
    """The closed remote phase a refusal names for a stream that cannot go on."""

    reason = answer.rest_error
    if answer.status == 401 or reason == "server_keys_unusable":
        return "remote_auth_failed"
    if reason == "server_profile_changed":
        return "server_profile_changed"
    if answer.status == 503:
        return "remote_service_not_running"
    if answer.status == 429:
        return "remote_unreachable"
    return "remote_incompatible"


class RestControlStream:
    """See the module text."""

    def __init__(
        self,
        transport: RestTransport,
        *,
        may_send: Callable[[], bool] | None = None,
        owns_transport: bool = False,
    ) -> None:
        self._transport = transport
        self._may_send_now = may_send or (lambda: True)
        self._checks: list[Callable[[], str | None]] = []
        self._owns_transport = owns_transport
        self._peer = RestPeerIdentity()
        self._inbound = bytearray()
        self._frames: asyncio.Queue[Mapping[str, JsonValue] | None] = asyncio.Queue()
        self._outbound: asyncio.Queue[bytes] = asyncio.Queue()
        self._read_buffer = bytearray()
        self._read_ended = False
        self._state = "await_hello"
        self._failure: str | None = None
        self._kind = ControlClientKind.CLI
        self._claim: WorkspaceClaim | None = None
        self._revision: ServerProfileRevision | None = None
        self._agent_id: str | None = None
        self._calls: dict[str, _Call] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._worker = asyncio.create_task(self._work())

    def __repr__(self) -> str:
        return f"RestControlStream(state={self._state!r})"

    @property
    def peer_identity(self) -> RestPeerIdentity:
        return self._peer

    @property
    def state(self) -> str:
        return self._state

    async def failure_phase(self) -> str | None:
        """The closed remote phase this stream ended with, if it can name one."""

        return self._failure

    def bind(self, refusal: Callable[[], str | None]) -> None:
        """Add a check asked before every request: a refusal (its phase) withholds the request.

        The helper binds each relayed stream to the admission it was opened under and to the
        repository its hello claims (design v2 section 8.3), so the stream's own retries and
        polls stop as soon as either refuses, not only when the client next writes a frame.
        """

        self._checks.append(refusal)

    def _withheld(self) -> str | None:
        """The phase that withholds the next request now; ``None`` when it may be sent."""

        for check in self._checks:
            try:
                phase = check()
            except Exception:  # noqa: BLE001 - a check that cannot be made withholds
                return _WITHHELD
            if phase is not None:
                return phase
        try:
            allowed = self._may_send_now()
        except Exception:  # noqa: BLE001 - a check that cannot be made withholds
            return _WITHHELD
        return None if allowed else _WITHHELD

    def _may_send(self) -> bool:
        return self._withheld() is None

    def _require_sendable(self) -> None:
        phase = self._withheld()
        if phase is not None:
            raise _Withheld(phase)

    # --- the ControlStream surface ------------------------------------------------------------

    async def receive(self, max_bytes: int) -> bytes:
        if type(max_bytes) is not int or max_bytes < 1:
            raise ValueError("receive_size_invalid")
        while not self._read_buffer:
            if self._read_ended:
                return b""
            chunk = await self._outbound.get()
            if not chunk:
                self._read_ended = True
                return b""
            self._read_buffer.extend(chunk)
        chunk = bytes(self._read_buffer[:max_bytes])
        del self._read_buffer[:max_bytes]
        return chunk

    async def send_all(self, data: Buffer) -> None:
        if self._state in {"ended", "closing", "closed"}:
            raise LocalControlTransportError("transport_failed")
        self._inbound.extend(bytes(data))
        while len(self._inbound) >= 4:
            (length,) = struct.unpack(">I", bytes(self._inbound[:4]))
            if length == 0 or length > MAX_CONTROL_FRAME_BYTES:
                self._end("remote_incompatible")
                raise LocalControlTransportError("transport_failed")
            if len(self._inbound) < 4 + length:
                return
            encoded = bytes(self._inbound[: 4 + length])
            del self._inbound[: 4 + length]
            try:
                frame = decode_control_frame(encoded)
            except ControlProtocolError:
                self._end(None)
                raise LocalControlTransportError("transport_failed") from None
            self._frames.put_nowait(frame)

    async def shutdown_write(self) -> None:
        """The client ended its side: what it sent is done; the stream closes."""

        self._frames.put_nowait(None)

    async def aclose(self) -> None:
        if self._state == "closed":
            return
        first = self._state != "closing"
        self._state = "closing"
        self._worker.cancel()
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(self._worker, *tasks, return_exceptions=True)
        # Asked after the cancellations were awaited, right before the DELETEs: a logout, a
        # lapse or zero-network meanwhile sends nothing more under the key this stream holds.
        if first and self._may_send():
            await self._courtesy()
        self._state = "closed"
        self._outbound.put_nowait(b"")
        if self._owns_transport:
            with contextlib.suppress(Exception):
                await self._transport.aclose()

    async def _courtesy(self) -> None:
        """Bounded DELETEs for the agent and calls still running (A-STOP-DELETE)."""

        requests: list[tuple[str, str]] = []
        if self._agent_id is not None:
            requests.append(("DELETE", f"{AGENTS_PATH}/{self._agent_id}"))
        requests.extend(
            ("DELETE", f"/v1/operations/{call.request.rpc_id}")
            for call in self._calls.values()
            if call.pending and not call.done
        )
        if not requests:
            return
        with contextlib.suppress(Exception):
            headers = self._transport.headers()
            async with asyncio.timeout(_CLOSE_SECONDS):
                await asyncio.gather(
                    *(
                        self._transport.request(method, path, headers=headers)
                        for method, path in requests
                    ),
                    return_exceptions=True,
                )

    # --- internals ----------------------------------------------------------------------------

    def _end(self, phase: str | None) -> None:
        """End the stream: the client reads end of stream and may ask ``failure_phase``."""

        if self._failure is None and phase is not None:
            self._failure = phase
        if self._state not in {"closing", "closed"}:
            # Ended, not yet closed: the owner's close still cancels what runs and sends the
            # bounded courtesy DELETEs.
            self._state = "ended"
        self._outbound.put_nowait(b"")

    def _deliver(self, frame: object) -> None:
        try:
            encoded = encode_control_frame(frame)
        except ControlProtocolError:
            self._end("remote_incompatible")
            return
        self._outbound.put_nowait(encoded)

    def _spawn(self, coroutine: Awaitable[None]) -> None:
        task = asyncio.ensure_future(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _work(self) -> None:
        try:
            while True:
                frame = await self._frames.get()
                if frame is None:
                    # The client ended its side: as the service does on a control connection, the
                    # connection ends (what is still running is cancelled by the close).
                    self._end(None)
                    return
                if self._state in {"ended", "closing", "closed"}:
                    return
                if self._state == "await_hello":
                    await self._hello(frame)
                    continue
                kind = frame.get("kind")
                if kind == "workspace_reply":
                    self._spawn(self._reply(frame))
                    continue
                try:
                    request = parse_control_request(cast(JsonObject, frame))
                except ControlProtocolError:
                    self._end(None)
                    return
                if isinstance(request, ControlCancelRequest):
                    self._cancel(request.target_rpc_id)
                else:
                    call = _Call(request)
                    self._calls[request.rpc_id] = call
                    self._spawn(self._call(call, frame))
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a mapping defect ends the stream, never the process
            self._end("remote_unreachable")

    async def _with_retries(
        self,
        send: Callable[[float | None], Awaitable[RestAnswer]],
        *,
        attempts: int = _ATTEMPTS,
        deadline: float | None = None,
    ) -> RestAnswer:
        """One idempotent request, sent again (bounded) when its answer was lost.

        The stream's authorization is asked before every attempt (``_Withheld``). With a
        ``deadline`` (the loop's clock), no attempt starts after it, each attempt is bounded by
        what is left of it (``send`` receives the seconds left), and a wait between attempts never
        outlasts it (``_DeadlinePassed``).
        """

        loop = asyncio.get_running_loop()
        delay = _RETRY_FIRST_SECONDS
        last: RestUnavailable | None = None
        for attempt in range(attempts):
            left = None if deadline is None else deadline - loop.time()
            if left is not None and left <= 0:
                raise _DeadlinePassed
            self._require_sendable()
            try:
                return await send(left)
            except RestUnavailable as error:
                if error.reason != "remote_unreachable":
                    raise
                last = error
                if attempt + 1 < attempts:
                    pause = delay if deadline is None else min(delay, deadline - loop.time())
                    if pause <= 0:
                        raise _DeadlinePassed from None
                    await asyncio.sleep(pause)
                    delay *= 2
        assert last is not None
        raise last

    # --- hello ----------------------------------------------------------------------------------

    async def _hello(self, frame: Mapping[str, JsonValue]) -> None:
        if "connection_nonce" not in frame or "workspace_locator" in frame:
            # Not a hello, or one naming a path on this computer: nothing is sent anywhere.
            self._end(None)
            return
        self._state = "opening"
        self._kind = ControlClientKind(cast(str, frame["client_kind"]))
        raw_claim = frame.get("workspace_claim")
        if isinstance(raw_claim, Mapping):
            claim = cast(Mapping[str, str], raw_claim)
            self._claim = WorkspaceClaim(
                identity_kind=cast(Literal["git_common_root", "directory"], claim["identity_kind"]),
                digest=claim["digest"],
                worktree=claim["worktree"],
            )
        raw_profile = frame.get("server_profile")
        if raw_profile is not None:
            try:
                self._revision = revision_from_json(raw_profile)
            except ProfileError:
                self._end(None)
                return
        if self._revision is None:
            # A remote client's hello always names the revision it consented to (ADR-052).
            self._end("server_profile_changed")
            return
        try:
            headers = self._transport.headers(
                revision=self._revision, claim=self._claim, client_kind=self._kind
            )
            answer = await self._with_retries(
                lambda _left: self._transport.request("GET", SESSION_PATH, headers=headers)
            )
        except RestUnavailable as error:
            self._end(error.reason)
            return
        except _Withheld as withheld:
            self._end(withheld.phase)
            return
        if answer.status != 200:
            self._end(_phase_of(answer))
            return
        try:
            session = parse_session(answer.body)
        except RestDocumentError:
            self._end("remote_incompatible")
            return
        if session.server_profile != self._revision or (
            session.workspace_binding != ("client_claim" if self._claim is not None else "none")
        ):
            self._end("remote_incompatible")
            return
        raw_agent = frame.get("workspace_agent")
        if isinstance(raw_agent, Mapping) and session.workspace_handle is not None:
            agent = cast(Mapping[str, JsonValue], raw_agent)
            declaration = WorkspaceAgentDeclaration(
                operations=tuple(cast(Sequence[str], agent["operations"])),
                max_reply_bytes=cast(int, agent["max_reply_bytes"]),
                role=cast(Literal["connection", "background"], agent.get("role", "connection")),
            )
            if not await self._register(declaration):
                return
        self._deliver(
            hello_result_for(
                session.status,
                self._kind,
                workspace_binding=session.workspace_binding,
                workspace_handle=session.workspace_handle,
                server_profile=session.server_profile,
            )
        )
        self._state = "open"

    async def _register(self, declaration: WorkspaceAgentDeclaration) -> bool:
        try:
            headers = self._transport.headers(
                revision=self._revision, claim=self._claim, client_kind=self._kind
            )
            # Asked again here: the session's answer took time, and a lapse, a hold or
            # zero-network since then sends neither the key nor the claim again.
            self._require_sendable()
            answer = await self._transport.request(
                "POST",
                AGENTS_PATH,
                headers=headers,
                content=agent_declaration_document(declaration),
            )
        except RestUnavailable as error:
            self._end(error.reason)
            return False
        except _Withheld as withheld:
            self._end(withheld.phase)
            return False
        if answer.status == 503 and answer.rest_error == "workspace_agent_unavailable":
            # The service cannot key the claim now: no agent answers, as over the socket.
            return True
        if answer.status != 201:
            self._end(_phase_of(answer))
            return False
        try:
            registration = parse_agent_registration(answer.body)
        except RestDocumentError:
            self._end("remote_incompatible")
            return False
        self._agent_id = registration.agent_id
        self._spawn(self._poll_work())
        return True

    # --- agents ---------------------------------------------------------------------------------

    async def _poll_work(self) -> None:
        agent_id = cast(str, self._agent_id)
        path = f"{AGENTS_PATH}/{agent_id}/work"
        while self._state == "open" or self._state == "opening":
            try:
                headers = self._transport.headers(revision=self._revision)
                answer = await self._with_retries(
                    lambda _left: self._transport.request(
                        "GET", path, headers=headers, params={"wait_ms": _WAIT_PARAM}, poll=True
                    )
                )
            except RestUnavailable as error:
                self._end(error.reason)
                return
            except _Withheld as withheld:
                self._end(withheld.phase)
                return
            if answer.status == 404:
                # The server no longer knows this agent: the connection is gone (a dropped
                # control connection's end), and the client connects again.
                self._agent_id = None
                self._end(None)
                return
            if answer.status != 200:
                self._end(_phase_of(answer))
                return
            try:
                work = parse_agent_work(answer.body, max_bytes=_MAX_WORK_BYTES)
            except RestDocumentError:
                self._end("remote_incompatible")
                return
            for call in work.calls:
                self._deliver(dict(call))

    async def _reply(self, frame: Mapping[str, JsonValue]) -> None:
        if self._agent_id is None or not self._may_send():
            return
        with contextlib.suppress(RestUnavailable):
            headers = self._transport.headers(revision=self._revision)
            await self._transport.request(
                "POST",
                f"{AGENTS_PATH}/{self._agent_id}/replies",
                headers=headers,
                content=canonical_encode(dict(frame)),
            )

    # --- calls ----------------------------------------------------------------------------------

    def _call_headers(self, call: ControlCallRequest) -> dict[str, str]:
        headers = self._transport.headers(
            revision=self._revision, claim=self._claim, client_kind=self._kind
        )
        headers[HEADER_OPERATION_ID] = call.rpc_id
        if self._agent_id is not None:
            headers[HEADER_AGENT] = self._agent_id
        headers[HEADER_SERVICE_INSTANCE] = call.service_instance_id
        headers[HEADER_SERVICE_GENERATION] = call.service_generation
        if call.deadline_ms is not None:
            headers[HEADER_DEADLINE_MS] = str(call.deadline_ms)
        if call.route_profile is not None:
            headers[HEADER_ROUTE_PROFILE] = call.route_profile
        if call.host_profile is not None:
            headers[HEADER_HOST_PROFILE] = call.host_profile
        return headers

    def _result(self, call: ControlCallRequest, error: ControlError) -> ControlResult:
        return ControlResult(
            protocol_version="1.0",
            rpc_id=call.rpc_id,
            service_instance_id=call.service_instance_id,
            service_generation=call.service_generation,
            method=call.method,
            outcome="error",
            body=error,
        )

    def _finish(self, call: _Call, result: object) -> None:
        call.done = True
        call.admitted.set()
        self._deliver(result)

    async def _call(self, call: _Call, frame: Mapping[str, JsonValue]) -> None:
        request = call.request
        loop = asyncio.get_running_loop()
        # One absolute deadline for the whole call (its ``deadline_ms``); a call with none still
        # bounds its ``operation_limit`` retries, but is polled until the server answers it.
        deadline = None if request.deadline_ms is None else loop.time() + request.deadline_ms / 1000
        busy_until = loop.time() + _BUSY_TOTAL_SECONDS if deadline is None else deadline
        body = canonical_encode(frame["body"])
        path = f"/v1/{request.method.value}"
        busy = _BUSY_FIRST_SECONDS
        sent = False

        def post(left: float | None) -> Awaitable[RestAnswer]:
            nonlocal sent
            sent = True
            return self._transport.request(
                "POST",
                path,
                headers=headers,
                content=body,
                params={"wait_ms": self._wait_param(left)},
                poll=True,
                seconds=left,
            )

        try:
            headers = self._call_headers(request)
            while True:
                answer = await self._with_retries(post, deadline=deadline)
                if answer.rest_error == "operation_limit" and loop.time() + busy < busy_until:
                    # Never dispatched: sent again after a growing wait, within the deadline.
                    await asyncio.sleep(busy)
                    busy = min(busy * 2, _BUSY_MAX_SECONDS)
                    continue
                break
            call.admitted.set()
            while answer.status == 202:
                call.pending = True
                if call.cancel_wanted and not call.cancel_sent:
                    await self._send_cancel(call)
                poll_headers = self._transport.headers(revision=self._revision)
                answer = await self._with_retries(
                    lambda left: self._transport.request(
                        "GET",
                        f"/v1/operations/{request.rpc_id}",
                        headers=poll_headers,
                        params={"wait_ms": self._wait_param(left)},
                        poll=True,
                        seconds=left,
                    ),
                    deadline=deadline,
                )
            call.pending = False
        except RestUnavailable as error:
            # It may have been admitted: its outcome is unknown, and the connection is gone.
            self._finish(
                call, self._result(request, ControlError("request_timeout", retryable=True))
            )
            self._end(error.reason)
            return
        except _DeadlinePassed:
            # Its caller stopped waiting: nothing more is sent for it, and whether an earlier
            # POST was admitted is unknown (the server forgets the operation on its own).
            self._finish(
                call, self._result(request, ControlError("request_timeout", retryable=True))
            )
            return
        except _Withheld as withheld:
            # Nothing more may be sent: never sent is a refusal, sent once is an unknown outcome.
            error = (
                ControlError("request_timeout", retryable=True)
                if sent
                else ControlError("service_unavailable", retryable=True)
            )
            self._finish(call, self._result(request, error))
            self._end(withheld.phase)
            return
        if answer.status == 200:
            self._finish(call, self._answered(request, answer))
            return
        reason = answer.rest_error
        if reason == "operation_unknown":
            # Its answer is no longer kept: the outcome is unknown (ADR-030 continuation).
            self._finish(
                call, self._result(request, ControlError("request_timeout", retryable=True))
            )
            return
        if reason == "server_profile_changed":
            # Refused before any work, as the service refuses a request bound to an old revision.
            self._finish(call, self._result(request, ControlError("server_profile_changed")))
            return
        if reason in {"frame_invalid", "header_invalid", "workspace_claim_required"}:
            self._finish(call, self._result(request, ControlError("frame_invalid")))
            return
        if reason == "frame_too_large":
            self._finish(call, self._result(request, ControlError("frame_too_large")))
            return
        if reason == "agent_unknown":
            # This connection's agent is gone at the server (its lease, a restart): as after a
            # dropped control connection, the call did not run and the client connects again.
            self._finish(
                call, self._result(request, ControlError("service_unavailable", retryable=True))
            )
            self._agent_id = None
            self._end(None)
            return
        phase = _phase_of(answer)
        self._finish(
            call, self._result(request, ControlError("service_unavailable", retryable=True))
        )
        self._end(phase)

    @staticmethod
    def _wait_param(left: float | None) -> str:
        """A long-poll's ``wait_ms``: the most the server allows, and short enough of the deadline
        for the answer to come back before it (halving as it nears, so the polls stay few)."""

        if left is None:
            return _WAIT_PARAM
        wait = max(left - _POLL_MARGIN_SECONDS, left / 2)
        return str(max(0, min(MAX_WAIT_MS, int(wait * 1000))))

    def _answered(self, request: ControlCallRequest, answer: RestAnswer) -> object:
        outcome = answer.headers.get(HEADER_OUTCOME)
        instance = answer.headers.get(HEADER_SERVICE_INSTANCE)
        generation = answer.headers.get(HEADER_SERVICE_GENERATION)
        try:
            body = strict_json_parse(answer.body)
        except ValueError:
            body = None
        if outcome not in {"ok", "error"} or instance is None or generation is None or body is None:
            return self._result(request, ControlError("request_timeout", retryable=True))
        return {
            "body": body,
            "method": request.method.value,
            "outcome": outcome,
            "protocol_version": "1.0",
            "rpc_id": request.rpc_id,
            "service_generation": generation,
            "service_instance_id": instance,
        }

    def _cancel(self, target: str) -> None:
        call = self._calls.get(target)
        if call is None or call.done:
            # Unknown or already answered: the result is final, the cancel is dropped.
            return
        call.cancel_wanted = True
        if not call.cancel_sent:
            # Sent now: its call was already written to the server (the client wrote the call
            # frame first). A DELETE that reaches the server before it admitted the call answers
            # ``operation_unknown`` and changes nothing; it is then sent again once the call's
            # POST was answered, so a cancel never acts before its call (cancellation order).
            self._spawn(self._send_cancel(call))

    async def _send_cancel(self, call: _Call) -> None:
        if call.cancel_sent or call.done or not self._may_send():
            return
        call.cancel_sent = True
        call.cancel_attempts += 1
        # Whether the call's POST was answered before this DELETE left: only a DELETE sent after
        # it can be known to have reached an admitted operation.
        after_admission = call.admitted.is_set()
        try:
            answer = await self._transport.request(
                "DELETE",
                f"/v1/operations/{call.request.rpc_id}",
                headers=self._transport.headers(),
            )
        except RestUnavailable:
            answer = None
        if answer is not None and (answer.status < 400 or after_admission):
            # Taken (or the operation is gone at the server): nothing more to send.
            return
        # Not taken: before admission, whatever order the answers came back in (the POST's 202
        # may have arrived while this DELETE was on its way), or not answered at all.
        call.cancel_sent = False
        if call.admitted.is_set() and not call.done and call.cancel_attempts < _ATTEMPTS:
            self._spawn(self._send_cancel(call))
