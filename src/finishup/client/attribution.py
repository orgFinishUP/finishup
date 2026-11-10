"""Which FinishUP service produced a remote connection's results, said in every human rendering.

A connection to a FinishUP server on another machine binds its workspace by claim
(``workspace_binding == "client_claim"``, ADR-051), and every piece of workspace evidence that
server holds came from this client's workspace agent. The human status and receipt renderings of
such a connection — CLI text, MCP text and the terminal interface — end with the fixed
provenance line, then, for a receipt whose coverage includes hook-observed evidence, the fixed
client-attested observation line (decision 12), then name the producing service by the instance
id its hello-result carried and by how this client reached it. A receipt whose service text says the provenance is unknown, and
every page of a receipt delivered in pages, keep only the second line. Nothing user-controlled
joins either line: no target name, host, address or path. JSON output stays unattributed. A
connection that is not claim-bound renders nothing here, so local output keeps its exact bytes.

The client reads a receipt's unknown provenance from the rendered text it is given or from the
result's ``workspace_provenance`` member, which every receipt format carries when the service
could not establish it (decision D4), JSON included; a receipt whose text the service withheld
still carries the member.

Level L2 (ADR-054, design v2 section 8.6). A connection whose target the owner consented to at
level L2 (``level`` ``L2``) may have its evidence read by the server from its copy of the
repository, so its status and other renderings end with ``SERVER_COPY_CONNECTION_LINE`` in place
of the client-attested line, never the sentence that the server did not read the repository
itself; an L1 connection keeps its exact bytes. A receipt whose result carries
``evidence_provenance`` (a level-L2 account), or whose service text ends with the server-copy or
the evidence-unknown section, says per kind of evidence where it was read: the client renders
that section from the member for a receipt with no service text (``evidence_provenance_section``)
and names only the producing service beside it. A receipt whose service text carries the
client-attested section never gets the connection's L2 line beside it either.

Transport tokens (closed; whoever builds the connection supplies one, ``unix`` by default):

* ``unix`` — the owner-only Unix control endpoint of a service on this machine;
* ``connector`` — a local relay process that carries the connection on to the server;
* ``ssh`` — an SSH channel this client process opened to the server host;
* ``https`` — HTTPS this client process speaks to the server or its network edge.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Literal, cast

from finishup.domain.evidence_provenance import evidence_provenance_from_json
from finishup.domain.receipts import (
    CLIENT_ATTESTED_OBSERVATION_LINE,
    CLIENT_ATTESTED_WORKSPACE_LINE,
    EVIDENCE_PROVENANCE_UNREADABLE_LINE,
    EVIDENCE_READS_PREFIX,
    SERVER_COPY_CONNECTION_LINE,
    WORKSPACE_PROVENANCE_UNKNOWN_LINE,
    evidence_provenance_lines,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "CONNECTION_LEVELS",
    "CONNECTION_TRANSPORTS",
    "ConnectionLevel",
    "ConnectionTransport",
    "ServiceAttribution",
    "attribution_lines",
    "connection_attribution",
    "coverage_hook_observed",
    "evidence_provenance_section",
    "shows_server_copy_section",
]

type ConnectionTransport = Literal["unix", "connector", "ssh", "https"]
CONNECTION_TRANSPORTS: Final[tuple[ConnectionTransport, ...]] = (
    "unix",
    "connector",
    "ssh",
    "https",
)
# The level the owner consented to for the connection's target (``client.targets``): L1 when the
# server never keeps a copy, L2 when it may read evidence from its copy (ADR-054).
type ConnectionLevel = Literal["L1", "L2"]
CONNECTION_LEVELS: Final[tuple[ConnectionLevel, ...]] = ("L1", "L2")
# Lines only the service's level-L2 sections hold: the counts line and the evidence-unknown line.
_SERVER_COPY_MARKERS: Final = (EVIDENCE_READS_PREFIX, EVIDENCE_PROVENANCE_UNREADABLE_LINE)


@dataclass(frozen=True, slots=True)
class ServiceAttribution:
    """The producing service of a claim-bound connection, how this client reached it, and the
    level its target was consented at (``L1`` unless the owner consented to ``L2``)."""

    service_instance_id: str
    transport: ConnectionTransport
    level: ConnectionLevel = "L1"

    def __post_init__(self) -> None:
        try:
            validate_id(IdKind.SERVICE_INSTANCE, self.service_instance_id)
        except ProtocolValueError:
            raise ValueError("service_attribution_invalid") from None
        if self.transport not in CONNECTION_TRANSPORTS or self.level not in CONNECTION_LEVELS:
            raise ValueError("service_attribution_invalid")

    def lines(self) -> tuple[str, str]:
        """The fixed provenance line for the connection's level, then the producing service;
        fixed words and tokens only. At level L2 the line says the server reads from its copy
        where it has one (``SERVER_COPY_CONNECTION_LINE``)."""

        return (
            SERVER_COPY_CONNECTION_LINE if self.level == "L2" else CLIENT_ATTESTED_WORKSPACE_LINE,
            f"This client reached FinishUP service {self.service_instance_id} "
            f"(transport: {self.transport}).",
        )


def connection_attribution(connection: object) -> ServiceAttribution | None:
    """The attribution of ``connection``'s results, or None when it is not claim-bound.

    Reads the connection's ``workspace_binding``, ``service_instance_id``, ``transport`` and
    ``consent_level``; ``ServiceClient`` carries all four, and any other client offering the same
    public methods must carry the first three. A ``consent_level`` that is absent or None (a
    connection whose target records no consent) is level L1. A claim-bound connection whose facts
    are missing or malformed raises ``ValueError("service_attribution_invalid")``: provenance is
    never silently dropped.
    """

    if getattr(connection, "workspace_binding", None) != "client_claim":
        return None
    service_instance_id: object = getattr(connection, "service_instance_id", None)
    transport: object = getattr(connection, "transport", None)
    level: object = getattr(connection, "consent_level", None)
    if level is None:
        level = "L1"
    if (
        type(service_instance_id) is not str
        or transport not in CONNECTION_TRANSPORTS
        or level not in CONNECTION_LEVELS
    ):
        raise ValueError("service_attribution_invalid")
    return ServiceAttribution(service_instance_id, transport, level)


def coverage_hook_observed(publication_channels: object) -> bool:
    """Whether a receipt result's ``coverage.publication_channels`` names hook-observed evidence.

    Takes the member as the wire or a model carries it (a sequence of channel tokens); anything
    else names none.
    """

    if isinstance(publication_channels, str) or not isinstance(publication_channels, (list, tuple)):
        return False
    return "hook_observed" in cast(Sequence[object], publication_channels)


def evidence_provenance_section(member: object, *, hook_observed: bool = False) -> str | None:
    """The "Workspace evidence" section a client renders from a receipt result's
    ``evidence_provenance`` member (ADR-054), for a receipt the service sent no text for.

    ``member`` is the wire mapping or the result model's member. The domain's fixed lines for that
    account (``evidence_provenance_lines``), under the heading, without the serving service (the
    connection names its producer). None for anything that is not a level-L2 account's exact
    form: nothing but those fixed words is ever rendered from it.
    """

    dump = getattr(member, "model_dump", None)
    if callable(dump):
        member = dump(mode="json", by_alias=True)
    try:
        account = evidence_provenance_from_json(member)
        if not account.level_l2:
            return None
        lines = evidence_provenance_lines(account, hook_observed=hook_observed is True)
    except ValueError:
        return None
    return "\n".join(("Workspace evidence", *lines))


def shows_server_copy_section(shown: str) -> bool:
    """Whether ``shown`` already carries a level-L2 "Workspace evidence" section (the service's
    server-copy or evidence-unknown section, or one rendered from the member)."""

    return any(marker in shown for marker in _SERVER_COPY_MARKERS)


def attribution_lines(
    attribution: ServiceAttribution | None,
    *,
    shown: str = "",
    receipt_page: bool = False,
    provenance_unknown: bool = False,
    hook_observed: bool = False,
    server_copy: bool = False,
) -> tuple[str, ...]:
    """The lines a status or receipt rendering ends with; none without an attribution.

    A line that ``shown`` already carries is not repeated: the service's own text and markdown
    receipt of a claim-bound task already ends with the fixed provenance line. When ``shown``
    carries the service's provenance-unknown line instead, or ``provenance_unknown`` says the
    receipt result carries ``workspace_provenance`` (every format, JSON included; decision D4),
    the task's own opening record could not say where its workspace evidence was read, so the
    connection's fixed provenance line, which would say the opposite, is left out too and only
    the producing service is named (ADR-051).

    ``receipt_page`` marks ``shown`` as one delivery page of a receipt the service paged. The
    receipt's "Workspace evidence" section is cut into fragments with the rest of its text and
    lands on at most one page, possibly split across two, so no page can tell whether it says the
    evidence was client-attested or that this is unknown. Every such page, the first and each
    continuation, names only the producing service; the section itself is part of the text the
    agent must read before the set is actionable-complete.

    ``hook_observed`` marks a receipt whose coverage includes hook-observed evidence: the fixed
    client-attested observation line follows the provenance line, on the same terms (never on a
    page or beside an unknown provenance, never twice), so a JSON receipt's rendering says what
    the service's text and markdown trailer says (decision 12).

    ``server_copy`` marks a receipt whose result carries ``evidence_provenance`` (ADR-054); it,
    like a ``shown`` that carries a level-L2 section, names only the producing service: the
    section says where each kind of evidence was read, the hook-observation line included. A
    ``shown`` that carries the service's client-attested section never gets the connection's
    level-L2 line beside it, which would contradict the task's own account.
    """

    if attribution is None:
        return ()
    withheld = (
        receipt_page
        or provenance_unknown
        or server_copy
        or WORKSPACE_PROVENANCE_UNKNOWN_LINE in shown
        or shows_server_copy_section(shown)
    )
    workspace, service = attribution.lines()
    if CLIENT_ATTESTED_WORKSPACE_LINE in shown:
        # The task's own account says where its evidence was read; the connection's line for its
        # level adds nothing true beside it (and at L1 it is that very line).
        workspace = CLIENT_ATTESTED_WORKSPACE_LINE
    candidates = (
        (workspace, CLIENT_ATTESTED_OBSERVATION_LINE, service)
        if hook_observed
        else (
            workspace,
            service,
        )
    )
    return tuple(
        line for line in candidates if line not in shown and not (withheld and line != service)
    )
