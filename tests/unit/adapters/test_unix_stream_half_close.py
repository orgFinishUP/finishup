"""Half-closing a Unix control stream whose peer already closed (macOS run, 2026-11-12).

Linux returns success from ``shutdown(SHUT_WR)`` once the peer has closed; macOS reports
``ENOTCONN``. A stream that half-closes after the peer may have gone (the helper's relays, the
daemon ending a torn stream, the confidential channel's client after a refused secret) must see
the same on both: the write side is closed either way, so the half-close is a no-op, and the
next read reports the peer's end.
"""

from __future__ import annotations

import asyncio
import errno
import socket

import pytest

from finishup.adapters.control.unix_socket import (
    AuthenticatedUnixStream,
    LocalControlTransportError,
    authenticate_peer,
)


class _ReportsNotConnected(socket.socket):
    """A socket that answers ``shutdown`` as macOS does once its peer has closed."""

    def shutdown(self, how: int) -> None:
        del how
        raise OSError(errno.ENOTCONN, "Socket is not connected")


class _ReportsBadDescriptor(socket.socket):
    def shutdown(self, how: int) -> None:
        del how
        raise OSError(errno.EBADF, "Bad file descriptor")


def _stream(kind: type[socket.socket]) -> tuple[AuthenticatedUnixStream, socket.socket]:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    peer = authenticate_peer(left)
    wrapped = kind(socket.AF_UNIX, socket.SOCK_STREAM, fileno=left.detach())
    return AuthenticatedUnixStream(wrapped, peer), right


def test_a_half_close_after_the_peer_closed_is_a_no_op_where_the_os_says_not_connected() -> None:
    async def run() -> bytes:
        stream, peer = _stream(_ReportsNotConnected)
        peer.close()
        try:
            await stream.shutdown_write()  # macOS: ENOTCONN; Linux: success
            return await stream.receive(1)
        finally:
            await stream.aclose()

    assert asyncio.run(run()) == b""


def test_a_half_close_on_a_live_peer_still_reaches_it() -> None:
    async def run() -> bytes:
        stream, peer = _stream(socket.socket)
        try:
            await stream.shutdown_write()
            peer.setblocking(True)
            return peer.recv(1)
        finally:
            peer.close()
            await stream.aclose()

    assert asyncio.run(run()) == b""


def test_any_other_half_close_failure_is_still_a_transport_failure() -> None:
    async def run() -> None:
        stream, peer = _stream(_ReportsBadDescriptor)
        try:
            await stream.shutdown_write()
        finally:
            peer.close()
            await stream.aclose()

    with pytest.raises(LocalControlTransportError, match="connection_failed"):
        asyncio.run(run())
