"""A bad status ``filter`` or ``page`` member is reported where it is, under its parent field.

The view-specific filter and page models are chosen by the sibling ``view``. A failure inside the
chosen model must keep its ``/filter/...`` (or ``/page/...``) location so MCP ``safe_details``
name a field the caller can correct, the same way the ``check`` ``scope`` object does, and must
not hide the request's other field errors.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from finishup.mcp.errors import safe_validation_locations
from finishup.mcp.server import invalid_request_message
from finishup.protocol.models import (
    CheckRequestModel,
    StatusBriefSuccessModel,
    StatusRequestModel,
    StatusSuccessModel,
)

_IDENTITY: dict[str, object] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": "req_00000000-0000-4000-8000-000000000001",
    "actor": {"actor_id": "agent:logical-1", "actor_type": "logical_agent"},
    "client": {
        "kind": "cooperative_agent",
        "version": "0.1.0",
        "integration": "cooperative_mcp",
    },
    "session_id": "ses_00000000-0000-4000-8000-000000000002",
    "writer_id": "wri_00000000-0000-4000-8000-000000000003",
}


def _status_error(**fields: object) -> ValidationError:
    with pytest.raises(ValidationError) as caught:
        StatusRequestModel.model_validate({**_IDENTITY, **fields})
    return caught.value


def test_a_valid_routed_filter_is_admitted() -> None:
    request = StatusRequestModel.model_validate(
        {**_IDENTITY, "view": "findings", "filter": {"priority": 1}}
    )
    assert type(request.filter).__name__ == "StatusFindingsFilterModel"


@pytest.mark.parametrize(
    ("view", "member", "value"),
    [
        ("findings", "priority", "x"),
        ("findings", "include_resolved", "yes"),
        ("obligations", "status", "done"),
        ("history", "after_sequence", "01"),
    ],
)
def test_a_bad_filter_member_is_located_under_filter(view: str, member: str, value: str) -> None:
    error = _status_error(view=view, filter={member: value})
    assert [item["loc"] for item in error.errors()] == [("filter", member)]
    assert safe_validation_locations(error)[0]["field"] == f"/filter/{member}"


def test_an_unknown_filter_key_is_located_at_filter_like_check_scope() -> None:
    error = _status_error(view="findings", filter={"bogus": 1})
    locations = safe_validation_locations(error)
    assert locations == ({"field": "/filter", "reason": "extra_forbidden"},)
    assert "each view admits only its own filter keys" in invalid_request_message(
        "status", locations
    )

    with pytest.raises(ValidationError) as sibling:
        CheckRequestModel.model_validate(
            {
                **_IDENTITY,
                "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
                "scope": {"claim_ids": [], "obligation_ids": [], "bogus": 1},
            }
        )
    assert safe_validation_locations(sibling.value) == (
        {"field": "/scope", "reason": "extra_forbidden"},
    )


def test_a_bad_filter_does_not_hide_the_other_field_errors() -> None:
    client = {"kind": "nope", "version": "0.1.0", "integration": "cooperative_mcp"}
    error = _status_error(view="findings", filter={"priority": "x"}, client=client)
    prefixes = {item["loc"][:1] for item in error.errors()}
    assert ("client",) in prefixes
    assert ("filter",) in prefixes


@pytest.mark.parametrize("model", [StatusSuccessModel, StatusBriefSuccessModel])
def test_a_bad_result_page_member_is_located_under_page(
    model: type[StatusSuccessModel] | type[StatusBriefSuccessModel],
) -> None:
    with pytest.raises(ValidationError) as caught:
        model.model_validate(
            {
                **_IDENTITY,
                "ok": True,
                "task_id": "tsk_00000000-0000-4000-8000-000000000004",
                "view": "findings",
                "page": {"items": [], "next_cursor": None, "bogus": 1},
            }
        )
    locations = {item["loc"] for item in caught.value.errors()}
    assert ("page", "bogus") in locations
    assert ("bogus",) not in locations
