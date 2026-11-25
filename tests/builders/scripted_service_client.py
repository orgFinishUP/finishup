"""The real ``ServiceClient`` in a new process, over a peer with one recorded answer.

A test that asks what a *new* process has imported or built by some moment cannot use this
process: its models are built already. The child runs ``python -I -c``, which cannot import the
test builders, so ``run_in_new_process`` prepends ``SCRIPTED_SERVICE_CLIENT`` to the test's own
script. That text defines ``scripted_client(kind, reply)``: the real client, connected to a peer
that answers every call with ``reply`` (a control-result frame as plain JSON) under the call's
own ``rpc_id``. The client's own code encodes the request and decodes the result; only the
transport and the service are stand-ins. The text imports only modules that importing
``finishup.service.client`` already loads, so it changes neither what the child has loaded nor
which models it has built.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Final, cast

from finishup.ports.control import ControlMethod, ControlResult, ControlSuccessBody
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.ids import IdKind, new_id
from finishup.service.control_protocol import encode_control_frame

__all__ = ["SCRIPTED_SERVICE_CLIENT", "result_frame", "run_in_new_process"]

SCRIPTED_SERVICE_CLIENT: Final = r"""
import asyncio
import struct

import finishup.service.client as service_client
from finishup.ports.control import ControlMethod
from finishup.protocol.canonical import canonical_encode, strict_json_parse
from finishup.service.control_protocol import ControlSession


class _Peer:
    def __init__(self, reply):
        self.peer_identity = object()
        self._reply = reply
        self._incoming = bytearray()
        self._ready = asyncio.Condition()
        self._closed = False

    async def receive(self, max_bytes):
        async with self._ready:
            await self._ready.wait_for(lambda: bool(self._incoming) or self._closed)
            chunk = bytes(self._incoming[:max_bytes])
            del self._incoming[:max_bytes]
            return chunk

    async def send_all(self, data):
        call = strict_json_parse(bytes(data)[4:])
        payload = canonical_encode({**self._reply, "rpc_id": call["rpc_id"]})
        async with self._ready:
            self._incoming.extend(struct.pack(">I", len(payload)) + payload)
            self._ready.notify_all()

    async def aclose(self):
        async with self._ready:
            self._closed = True
            self._ready.notify_all()


def scripted_client(kind, reply):
    peer = _Peer(reply)
    session = ControlSession(
        protocol_version="1.0",
        client_kind=kind,
        service_instance_id=reply["service_instance_id"],
        service_generation=reply["service_generation"],
        allowed_methods=tuple(sorted(ControlMethod, key=lambda item: item.value.encode("ascii"))),
        peer_identity=peer.peer_identity,
        connection_nonce="0" * 64,
    )
    return service_client._connected_client(peer, session, kind)
"""


def result_frame(
    method: ControlMethod, body: ControlSuccessBody, *, service_instance_id: str | None = None
) -> dict[str, JsonValue]:
    """One successful result for ``method``, as the plain JSON of the frame the service writes."""

    frame = encode_control_frame(
        ControlResult(
            protocol_version="1.0",
            rpc_id=new_id(IdKind.CONTROL_RPC),
            service_instance_id=service_instance_id or new_id(IdKind.SERVICE_INSTANCE),
            service_generation="1",
            method=method,
            outcome="ok",
            body=body,
        )
    )
    return cast(dict[str, JsonValue], strict_json_parse(frame[4:]))


def run_in_new_process(script: str, stdin: JsonValue) -> dict[str, JsonValue]:
    """Run ``script`` after the scripted client's source; its stdout is one JSON object."""

    done = subprocess.run(  # noqa: S603 - no shell and a fixed interpreter
        [sys.executable, "-I", "-c", SCRIPTED_SERVICE_CLIENT + script],
        input=json.dumps(stdin).encode(),
        capture_output=True,
        timeout=120,
        check=False,
        env=dict(os.environ),
    )
    assert done.returncode == 0, done.stderr.decode()[-4000:]
    return cast(dict[str, JsonValue], json.loads(done.stdout))
