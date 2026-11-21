"""The pydantic-free protocol values stay the protocol models' own names, and load without pydantic.

``finishup.protocol.model_values`` holds the bounds, wire enums and outcome rules the domain and
kernel layers read, so a process that never builds a protocol model (an observation hook
refreshing its advice) skips pydantic. Moving them must not change a single observable fact: each
name is the same object through ``finishup.protocol.models``, keeps that module as its
``__module__`` (pickles and schema reference names key on it), and the modules that now bind
pydantic or the protocol models lazily still resolve every annotation and type check to the real
objects.
"""

from __future__ import annotations

import ast
import json
import pickle
import subprocess
import sys
import typing
from pathlib import Path
from typing import Annotated, get_args, get_origin

import pydantic
import pytest

import finishup.config.models as config_models
import finishup.protocol.model_values as model_values
import finishup.protocol.models as models
from finishup.domain import events
from finishup.kernel import command_attempts
from finishup.observability import logging as structured_logging
from finishup.ports import control, ledger
from finishup.ports.control import ControlMethod
from finishup.protocol.lazy_module import LazyModule

_LEAF = Path(model_values.__file__)


def _leaf_public_names() -> tuple[str, ...]:
    names: list[str] = []
    for node in ast.parse(_LEAF.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.ClassDef | ast.FunctionDef):
            names.append(node.name)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.append(node.target.id)
    return tuple(name for name in names if not name.startswith("_"))


def test_every_leaf_name_is_the_same_object_through_protocol_models() -> None:
    names = _leaf_public_names()
    assert len(names) == 44
    for name in names:
        assert getattr(models, name) is getattr(model_values, name), name


def test_moved_definitions_keep_protocol_models_as_their_module() -> None:
    for name in _leaf_public_names():
        value = getattr(model_values, name)
        if isinstance(value, type) or callable(value):
            assert value.__module__ == "finishup.protocol.models", name


def test_enum_pickles_name_protocol_models_and_round_trip() -> None:
    member = models.SemanticStatus.SUCCEEDED
    payload = pickle.dumps(member, protocol=4)
    assert b"finishup.protocol.models" in payload
    assert b"model_values" not in payload
    assert pickle.loads(payload) is member  # noqa: S301 - bytes made in this test
    assert pickle.loads(pickle.dumps(models.validate_semantic_outcome)) is (  # noqa: S301
        models.validate_semantic_outcome
    )
    assert repr(models.DataCategory.CLAIM_TEXT) == "<DataCategory.CLAIM_TEXT: 'claim_text'>"


def test_protocol_models_public_exports_are_unchanged() -> None:
    for name in models.__all__:
        assert hasattr(models, name), name
    assert set(_leaf_public_names()) - {
        "MAX_PROVIDER_REVIEW_TEXT_CHARS",
        "MAX_PROVIDER_MISSING_REASON_CHARS",
    } <= set(models.__all__)


def test_model_values_imports_without_pydantic() -> None:
    probe = (
        "import json, sys\n"
        "import finishup.protocol.model_values\n"
        "import finishup.protocol.lazy_module\n"
        "print(json.dumps([m for m in ('pydantic', 'finishup.protocol.models') "
        "if m in sys.modules]))\n"
    )
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and probe source
        [sys.executable, "-c", probe], capture_output=True, check=True
    )
    assert json.loads(completed.stdout) == []


def test_lazy_module_reads_real_attributes_and_ignores_dunder_probes() -> None:
    lazy = LazyModule("finishup.protocol.models")
    assert lazy.CheckScopeModel is models.CheckScopeModel
    with pytest.raises(AttributeError):
        _ = lazy.__wrapped__
    with pytest.raises(AttributeError):
        _ = lazy.not_a_protocol_name
    assert repr(lazy) == "<lazy module 'finishup.protocol.models'>"


def test_lazy_annotations_resolve_to_the_real_models() -> None:
    hints = typing.get_type_hints(events.CheckRecordedPayload)
    assert hints["scope"] is models.CheckScopeModel
    assert get_args(hints["policy_executions"]) == (models.CheckPolicyExecutionModel, Ellipsis)
    occurred_at = typing.get_type_hints(events.EventDraft, include_extras=True)["occurred_at"]
    assert get_origin(occurred_at) is Annotated
    field_info = get_args(occurred_at)[1]
    assert isinstance(field_info, pydantic.fields.FieldInfo)
    assert field_info.description == events.OCCURRED_AT_DRAFT_DESCRIPTION
    assert set(get_args(ledger.ProjectionItem.__value__)) == {
        models.StatusAssignmentItemModel,
        models.StatusCompactItemModel,
        models.StatusEvidenceItemModel,
        models.StatusFindingItemModel,
        models.StatusHistoryItemModel,
        models.StatusHistoryItemV14Model,
        models.StatusObligationItemModel,
        models.StatusResultItemModel,
        models.StatusVersionSliceModel,
    }
    assert models.StartRequest in get_args(control.ControlCallBody.__value__)
    assert models.ReceiptResult in get_args(control.ControlSuccessBody.__value__)


def test_lazy_function_annotations_resolve_to_the_real_models() -> None:
    attempts = typing.get_type_hints(command_attempts.command_attempts)["return"]
    assert get_args(attempts) == (models.StatusCommandAttemptModel, Ellipsis)
    logging_hints = typing.get_type_hints(structured_logging.configure_logging)
    assert logging_hints["config"] is config_models.LoggingConfig


_REQUEST_TYPES: dict[ControlMethod, type[object]] = {
    ControlMethod.START: models.StartRequest,
    ControlMethod.PUBLISH_WORK: models.PublishWorkRequest,
    ControlMethod.CHECK: models.CheckRequest,
    ControlMethod.RESPOND: models.RespondRequest,
    ControlMethod.STATUS: models.StatusRequest,
    ControlMethod.RECEIPT: models.ReceiptRequest,
}
_RESULT_TYPES: dict[ControlMethod, type[object]] = {
    ControlMethod.START: models.StartResult,
    ControlMethod.PUBLISH_WORK: models.PublishWorkResult,
    ControlMethod.CHECK: models.CheckResult,
    ControlMethod.RESPOND: models.RespondResult,
    ControlMethod.STATUS: models.StatusResult,
    ControlMethod.RECEIPT: models.ReceiptResult,
}


@pytest.mark.parametrize("method", list(ControlMethod))
def test_control_body_types_match_the_former_method_maps(method: ControlMethod) -> None:
    expected_call = _REQUEST_TYPES.get(method, control.JsonObject)
    expected_success = _RESULT_TYPES.get(method, control.JsonObject)
    assert control._expected_call_body_type(method) is expected_call  # pyright: ignore[reportPrivateUsage]
    assert control._expected_success_body_type(method) is expected_success  # pyright: ignore[reportPrivateUsage]
