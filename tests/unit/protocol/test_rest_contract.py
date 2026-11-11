"""The REST v1 public contract (ADR-053): golden vectors, codecs and the API manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from finishup.ports.control import ControlMethod, WorkspaceClaim
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.schemas import validate_schema_instance
from finishup.protocol.server_profile import ServerProfileRevision
from finishup.rest import contract
from finishup.rest.contract import (
    REST_ROOT_SCHEMAS,
    RestDocumentError,
    api_manifest_digest,
    claim_for_principal,
    current_api_manifest,
    encode_claim_header,
    encode_revision_header,
    method_allowed,
    mint_api_key,
    parse_api_key,
    parse_claim_header,
    parse_revision_header,
)
from finishup.service.control_protocol import CONTROL_PROTOCOL_VERSION

_REPO = Path(__file__).resolve().parents[3]
_CASE = json.loads((_REPO / "fixtures" / "service" / "rest.case.json").read_text())
_MANIFESTS = json.loads(
    (_REPO / "fixtures" / "service" / "rest-api-manifests.case.json").read_text()
)


def _parse_rest_error(body: bytes) -> str:
    reason = contract.parse_rest_error(body)
    if reason is None:
        raise RestDocumentError
    return reason


def _parse_agent_work(body: bytes) -> contract.AgentWork:
    return contract.parse_agent_work(body, max_bytes=65_536)


def _encode_agent_work(work: contract.AgentWork) -> bytes:
    return contract.agent_work_document(work.calls)


_PARSERS: dict[str, Any] = {
    "rest-error": _parse_rest_error,
    "rest-discovery": contract.parse_discovery,
    "rest-session": contract.parse_session,
    "rest-operation": contract.parse_operation_pending,
    "rest-agent-declaration": contract.parse_agent_declaration,
    "rest-agent": contract.parse_agent_registration,
    "rest-agent-work": _parse_agent_work,
}


def _bytes(document: object) -> bytes:
    return canonical_encode(cast(Any, document))


@pytest.mark.parametrize("vector", _CASE["valid"], ids=lambda item: item["schema"])
def test_every_valid_vector_parses_validates_and_encodes_back_byte_for_byte(
    vector: dict[str, Any],
) -> None:
    body = _bytes(vector["document"])
    validate_schema_instance(vector["schema"], "1.0.0", vector["document"])
    parsed = _PARSERS[vector["schema"]](body)
    encoders: dict[str, Any] = {
        "rest-error": contract.rest_error_document,
        "rest-discovery": contract.discovery_document,
        "rest-session": contract.session_document,
        "rest-operation": contract.operation_pending_document,
        "rest-agent-declaration": contract.agent_declaration_document,
        "rest-agent": contract.agent_registration_document,
        "rest-agent-work": _encode_agent_work,
    }
    assert encoders[vector["schema"]](parsed) == body


@pytest.mark.parametrize("vector", _CASE["invalid"], ids=lambda item: item["schema"])
def test_every_rejected_vector_is_refused_by_the_parser_and_the_schema(
    vector: dict[str, Any],
) -> None:
    with pytest.raises(RestDocumentError):
        _PARSERS[vector["schema"]](_bytes(vector["document"]))
    if vector["schema"] in {"rest-session", "rest-discovery"} and (
        vector["document"].get("rest_majors") == ["2", "1"]
        or vector["document"].get("workspace_binding") == "none"
    ):
        # Order and "a handle only beside a claim" are the parser's rules, not the schema's.
        return
    with pytest.raises(Exception):  # noqa: B017, PT011 - any schema refusal
        validate_schema_instance(vector["schema"], "1.0.0", vector["document"])


def test_a_discovery_document_is_bounded_before_it_is_parsed() -> None:
    document = dict(_CASE["valid"][1]["document"])
    document["auth"] = ["api_key"] + [f"x{index}" for index in range(7)]
    body = _bytes(document)
    padded = body[:-1] + b" " * 5_000 + b"}"
    with pytest.raises(RestDocumentError):
        contract.parse_discovery(padded)


def test_the_claim_header_round_trips_and_names_no_path() -> None:
    vector = _CASE["headers"]["claim"]
    claim = WorkspaceClaim(**vector["claim"])
    assert encode_claim_header(claim) == vector["header"]
    assert parse_claim_header(vector["header"]) == claim
    for bad in ("", "directory:sha256:00", "/srv/work/project", vector["header"] + ":x"):
        with pytest.raises(ValueError, match="workspace_claim_invalid"):
            parse_claim_header(bad)


def test_a_claim_is_namespaced_per_principal_and_keeps_its_worktree() -> None:
    vector = _CASE["headers"]
    claim = WorkspaceClaim(**vector["claim"]["claim"])
    keyed = claim_for_principal(claim, vector["principal"]["principal"])
    assert keyed.digest == vector["principal"]["keyed_digest"]
    assert (
        keyed.digest
        == "sha256:"
        + hashlib.sha256(
            b"yoetz/claim-principal/v1\x00"
            + vector["principal"]["principal"].encode()
            + b"\x00"
            + claim.digest.encode()
        ).hexdigest()
    )
    assert keyed.worktree == claim.worktree
    assert claim_for_principal(claim, "p_ffffffffffffffff").digest != keyed.digest


def test_the_revision_header_round_trips_and_refuses_anything_else() -> None:
    vector = _CASE["headers"]["revision"]
    revision = ServerProfileRevision(**vector["revision"])
    assert encode_revision_header(revision) == vector["header"]
    assert parse_revision_header(vector["header"]) == revision
    for bad in _CASE["headers"]["rejected_revisions"]:
        with pytest.raises(ValueError, match="server_profile_invalid"):
            parse_revision_header(bad)


@pytest.mark.parametrize("secret", ["random", "underscored"])
def test_api_keys_have_one_spelling_and_never_echo_their_secret(
    secret: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    if secret == "underscored":
        # A base64url secret may hold "_": the whole secret, not its first fragment ("k" here,
        # which "ApiKeyToken" spells), is what must never be echoed (a flake seen in CI).
        import base64
        import secrets

        fixed = base64.urlsafe_b64decode("k_" + "A" * 41 + "=")
        real = secrets.token_bytes

        def token_bytes(count: int | None = None) -> bytes:
            # The secret only (32 bytes); the key id's own bytes stay random.
            return fixed if count == len(fixed) else real(count)

        monkeypatch.setattr(secrets, "token_bytes", token_bytes)
    token, text = mint_api_key()
    assert text.startswith("fuk_") and parse_api_key(text) == token
    assert "secret" not in repr(token) or "<redacted>" in repr(token)
    assert text.split("_", 2)[2] not in repr(token)
    assert parse_api_key(_CASE["headers"]["api_key"]["valid"]) is not None
    for bad in _CASE["headers"]["api_key"]["rejected"]:
        assert parse_api_key(bad) is None


def test_scopes_bound_the_methods_and_observation_ingest_needs_a_claim() -> None:
    assert method_allowed("agent", ControlMethod.CHECK, claim_bound=False)
    assert not method_allowed("agent", ControlMethod.REVIEW, claim_bound=True)
    assert method_allowed("operator", ControlMethod.REVIEW, claim_bound=False)
    for never in (
        ControlMethod.SERVICE_STOP,
        ControlMethod.BACKUP_EXECUTE,
        ControlMethod.SERVER_PROFILE,
        ControlMethod.OBSERVATION_REVOKE,
    ):
        assert not method_allowed("operator", never, claim_bound=True)
    assert not method_allowed("operator", ControlMethod.OBSERVATION_INGEST, claim_bound=False)
    assert method_allowed("agent", ControlMethod.OBSERVATION_INGEST, claim_bound=True)


def test_every_rest_error_reason_is_in_the_schema_and_has_one_status() -> None:
    for reason, status in contract.REST_ERROR_STATUS.items():
        validate_schema_instance(
            "rest-error", "1.0.0", {"reason": reason, "schema_version": "1.0.0"}
        )
        assert 400 <= status <= 599
    assert contract.UNAUTHENTICATED_REASONS <= set(contract.REST_ERROR_STATUS)


def test_this_release_pins_its_rest_api_manifest() -> None:
    """A REST contract change cannot land without a new entry in the manifests vector (U18)."""

    versions = _MANIFESTS["versions"]
    assert [version["api_manifest"] for version in versions][-1] == current_api_manifest()
    assert _MANIFESTS["roots"] == list(REST_ROOT_SCHEMAS)
    assert CONTROL_PROTOCOL_VERSION == "1.0"
    # The control wire the REST calls carry is the one the roots name.
    from finishup.service import control_protocol

    wire = getattr(control_protocol, "_CONTROL_SCHEMA_VERSION")
    assert f"service/control-request-{wire}.schema.json" in REST_ROOT_SCHEMAS


def test_the_api_manifest_is_the_closure_and_changes_with_any_member() -> None:
    members = {
        "service/a.schema.json": "sha256:" + "1" * 64,
        "service/b.schema.json": "sha256:" + "2" * 64,
        "common/c.schema.json": "sha256:" + "3" * 64,
        "common/unrelated.schema.json": "sha256:" + "4" * 64,
    }
    documents = {
        "service/a.schema.json": {"$ref": "https://schemas.yoetz.dev/0.1/common/c.schema.json#/x"},
        "service/b.schema.json": {"properties": {"x": {"$ref": "#/$defs/y"}}},
        "common/c.schema.json": {"type": "object"},
        "common/unrelated.schema.json": {},
    }

    def read(path: str) -> bytes:
        return json.dumps(documents[path]).encode()

    roots = ("service/a.schema.json", "service/b.schema.json")
    first = api_manifest_digest(members, read, roots)
    assert first == api_manifest_digest(
        {**members, "common/unrelated.schema.json": "sha256:" + "9" * 64}, read, roots
    )
    assert first != api_manifest_digest(
        {**members, "common/c.schema.json": "sha256:" + "9" * 64}, read, roots
    )
    with pytest.raises(RestDocumentError):
        api_manifest_digest(
            {key: value for key, value in members.items() if key != "common/c.schema.json"},
            read,
            roots,
        )


def test_an_agents_work_admits_exactly_the_control_wires_workspace_call_frames() -> None:
    """C5: each call is the ``workspace_call`` frame ``control-result`` 2.10.0 defines (every
    member bound as there), in the schema and in the parser; ``{}`` is refused by both."""

    work = json.loads(
        (_REPO / "schemas" / "service" / "rest-agent-work-1.0.0.schema.json").read_text()
    )
    result = json.loads(
        (_REPO / "schemas" / "service" / "control-result-2.10.0.schema.json").read_text()
    )
    (frame,) = [
        branch
        for branch in result["oneOf"]
        if branch.get("properties", {}).get("kind") == {"const": "workspace_call"}
    ]
    items = dict(work["$defs"]["WorkspaceCallRef"])
    assert items.pop("description") == "One control workspace_call frame."
    # The generator orders ``required``; the members are the same.
    assert sorted(items.pop("required")) == sorted(frame["required"])
    assert items == {key: value for key, value in frame.items() if key != "required"}
    with pytest.raises(RestDocumentError):
        contract.parse_agent_work(b'{"calls":[{}],"schema_version":"1.0.0"}', max_bytes=1 << 20)
    assert any(
        vector["schema"] == "rest-agent-work" and vector["document"]["calls"]
        for vector in _CASE["valid"]
    )
