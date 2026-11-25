"""One reply schema per review keeps the reviewer's prompt prefix byte-stable (#1172).

A simulated three-read review runs the real loop, reviewer facade and evaluators over a scripted
Codex app-server and the stateless Responses rendering. What each turn sends beside its new
messages never changes and each turn only appends, so the provider can serve all the earlier
context from its prompt cache; announcing the final turn adds no model turn. On both stateless
routes a whole review also runs through the service composition, the privacy coordinator, the
policy-enforcing gateway, the route's factory, renderer, evaluator and one-attempt transport; only
the network hop behind that transport is scripted.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from builders.ledger_adapters import FixedClock
from builders.policy_cases import clm
from builders.privacy_policies import minimal_external_policy
from builders.privacy_widenings import with_llm
from finishup.adapters.privacy.gateway import PolicyEnforcingOutboundGateway
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.adapters.providers import reviewer_cache_telemetry as telemetry
from finishup.adapters.providers.factory import ChatCompletionsExternalFactory
from finishup.adapters.providers.local_model import InstalledLocalModelProfileRegistry
from finishup.adapters.providers.openai_responses import OpenAIProfile, normalize_response
from finishup.adapters.providers.openai_responses import render_case as render_responses
from finishup.adapters.providers.openai_responses_factory import OpenAIResponsesExternalFactory
from finishup.application.reviewer_exchange import REVIEWER_REPLY_SCHEMAS, ReviewerExchangeModel
from finishup.application.reviewer_loop import FINAL_PHASE, ReviewerLoop, ReviewOutcome
from finishup.domain.privacy import (
    ApprovedOutboundCase,
    AuthorizationScope,
    AuthorizationScopeKind,
    ProviderBinding,
)
from finishup.ports.semantic import (
    REVIEWER_EXCHANGE_MEDIA_TYPES,
    Deadline,
    ReviewerMessage,
    ReviewerSession,
    SemanticEvaluatorPort,
    SemanticResult,
    SemanticResultReply,
    SemanticResultUnavailable,
    decode_reviewer_exchange,
    reviewer_exchange,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.models import SemanticStatus
from integration.privacy.test_egress_gateway import (
    _AuditKey,  # pyright: ignore[reportPrivateUsage]
    _CredentialMinter,  # pyright: ignore[reportPrivateUsage]
    _Ids,  # pyright: ignore[reportPrivateUsage]
)
from integration.service import test_reviewer_conversation_composition as composition
from integration.service import test_semantic_non_dispatch as non_dispatch
from unit.adapters.providers.test_reviewer_cache_telemetry import (
    _exchange,  # pyright: ignore[reportPrivateUsage]
    _UsageCapture,  # pyright: ignore[reportPrivateUsage]
    _UsageRuntime,  # pyright: ignore[reportPrivateUsage]
)
from unit.adapters.providers.test_reviewer_completions import (
    _DEADLINE,  # pyright: ignore[reportPrivateUsage]
    _DIGEST,  # pyright: ignore[reportPrivateUsage]
    _FINAL,  # pyright: ignore[reportPrivateUsage]
    _FIRST,  # pyright: ignore[reportPrivateUsage]
    _api_binding,  # pyright: ignore[reportPrivateUsage]
    _api_profile,  # pyright: ignore[reportPrivateUsage]
    _case,  # pyright: ignore[reportPrivateUsage]
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _NoSteps,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_READ = canonical_encode(
    {
        "reply": {
            "action": "read_ledger",
            "args": {"cursor": None, "max_bytes": None, "refs": [str(clm(1))], "view": "claims"},
        }
    }
).decode()


class _ThreeReads:
    """A broker offering three reads, each answered with a fixed result envelope."""

    store = _NoSteps()
    history_roots = ()
    cited_refs: frozenset[str] = frozenset()
    text_by_ref: dict[str, list[str]] = {}

    def __init__(self) -> None:
        self.calls = 0

    def reads_allowed(self) -> bool:
        return self.calls < 3

    def notice_fits(self) -> bool:
        return True

    async def execute(self, action: object, expired: object, reply: str = "") -> str:
        self.calls += 1
        return canonical_encode({"call_index": self.calls, "status": "ok"}).decode()


async def _review(
    binding: ProviderBinding,
    dispatch: Any,
    session: ReviewerSession,  # noqa: ANN401
) -> ReviewOutcome:
    async def admissible(_roots: frozenset[str]) -> bool:
        return True

    async with ReviewerExchangeModel(binding, dispatch, session) as model:
        return await ReviewerLoop(
            model,
            cast(Any, _ThreeReads()),
            instruction="Review it.",
            packet="packet",
            deadline=_DEADLINE,
            history_admissible=admissible,
            final_reserve_seconds=1.0,  # the scripted 30-second deadline leaves time to read
            clock=_Clock().monotonic_seconds,
        ).run()


async def test_a_three_read_codex_review_keeps_every_turns_settings_byte_identical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    labels: list[object] = []

    def record(**fields: object) -> str:
        labels.append(cast(dict[str, object], fields["counts"]).get("reviewer_cache_miss"))
        return "err_74000000-0000-4000-8000-000000000001"

    monkeypatch.setattr(telemetry, "record_bounded_counts_without_raising", record)
    runtime = _UsageRuntime(
        [_READ, _READ, _READ, _FINAL],
        [
            [(90_000, 0, 50)],
            [(92_000, 89_984, 50)],
            [(94_000, 91_904, 50)],
            [(96_000, 0, 50)],  # a scripted miss on the final turn
        ],
    )
    session = ReviewerSession("review-a", _DEADLINE)
    binding = ProviderBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0", "external"
    )
    media: list[str] = []
    requests = iter(f"req_74000000-0000-4000-8000-00000000000{n}" for n in range(1, 9))

    async def dispatch(payload: bytes, media_type: str, deadline: Deadline) -> SemanticResult:
        media.append(media_type)
        mode = "turn" if media_type == REVIEWER_EXCHANGE_MEDIA_TYPES["turn"] else "final"
        history = decode_reviewer_exchange(payload)
        return await _exchange(
            monkeypatch, runtime, session, history, next(requests), mode, REVIEWER_REPLY_SCHEMAS
        )

    outcome = await _review(binding, dispatch, session)
    assert (outcome.status, outcome.model_turns) == ("final", 4), outcome.reason

    turns = [params for method, params in runtime.requests if method == "turn/start"]
    beside = {
        canonical_encode(
            cast(JsonValue, {k: v for k, v in turn.items() if k not in {"input", "threadId"}})
        )
        for turn in turns
    }
    # The schema, model, effort and every other setting are the same bytes on all four turns.
    assert len(turns) == 4 and len(beside) == 1
    assert set(media) == {REVIEWER_EXCHANGE_MEDIA_TYPES["turn"]}
    # Each turn sends only what is new: the packet, each read result, and the last result with
    # the final-phase notice as a separate input.
    inputs = [[item["text"] for item in cast(list[dict[str, str]], t["input"])] for t in turns]
    assert inputs[0] == ["packet"]
    assert [len(texts) for texts in inputs[1:]] == [1, 1, 2] and inputs[3][1] == FINAL_PHASE
    # The final turn's scripted miss is unexplained, not a schema or settings change: the
    # telemetry's digest of what each turn sent beside its messages saw no change either.
    assert labels == ["first_turn", "none", "none", "unexplained"]


async def test_codex_refuses_a_continuation_that_rewrites_what_the_thread_holds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _UsageRuntime([_READ, _FINAL], [[(90_000, 0, 50)], [(92_000, 0, 50)]])
    session = ReviewerSession("review-a", _DEADLINE)
    request = "req_74000000-0000-4000-8000-000000000011"
    await _exchange(monkeypatch, runtime, session, _FIRST, request)
    runtime.requests.clear()
    rewritten: tuple[ReviewerMessage, ...] = (
        ("system", "Review it."),
        ("user", "another packet"),
        ("assistant", _READ),
        ("user", "observation"),
        ("user", FINAL_PHASE),
    )
    result = await _exchange(monkeypatch, runtime, session, rewritten, request)
    assert type(result) is SemanticResultUnavailable and runtime.requests == []
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and evidence.failure_stage == "case_invalid"
    await session.aclose()


async def test_responses_bodies_keep_one_schema_and_extend_the_previous_input() -> None:
    profile = _api_profile("responses")
    assert isinstance(profile, OpenAIProfile)
    binding = _api_binding(profile)
    answers = [_READ, _READ, _READ, _FINAL]
    bodies: list[dict[str, JsonValue]] = []

    async def dispatch(payload: bytes, media_type: str, deadline: Deadline) -> SemanticResult:
        mode = "turn" if media_type == REVIEWER_EXCHANGE_MEDIA_TYPES["turn"] else "final"
        case = _case(decode_reviewer_exchange(payload), binding, mode)
        rendered = render_responses(case, REVIEWER_REPLY_SCHEMAS)
        bodies.append(cast(dict[str, JsonValue], strict_json_parse(rendered.body)))
        response = type(
            "R", (), {"output_text": answers.pop(0), "status": "completed", "id": "resp"}
        )()
        exchange = reviewer_exchange(media_type, payload, REVIEWER_REPLY_SCHEMAS)
        return normalize_response(
            response, profile, policy_digest=_DIGEST, latency_ms=1, exchange=exchange
        )

    outcome = await _review(binding, dispatch, ReviewerSession("review-a", _DEADLINE))
    assert (outcome.status, outcome.model_turns) == ("final", 4), outcome.reason
    beside = {canonical_digest({k: v for k, v in body.items() if k != "input"}) for body in bodies}
    assert len(beside) == 1  # one schema, model, output limit and storage opt-out throughout
    inputs = [cast(list[JsonValue], body["input"]) for body in bodies]
    for before, after in zip(inputs, inputs[1:], strict=False):
        assert after[: len(before)] == before  # everything sent before, unchanged and first
    assert cast(dict[str, JsonValue], inputs[-1][-1]) == {"content": FINAL_PHASE, "role": "user"}


async def test_codex_refuses_an_empty_or_three_message_continuation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = "req_74000000-0000-4000-8000-000000000021"
    too_long: tuple[ReviewerMessage, ...] = (
        *_FIRST,
        ("assistant", _READ),
        ("user", "observation"),
        ("user", FINAL_PHASE),
        ("user", "one more"),
    )
    for history in (_FIRST, too_long):  # nothing new; three new messages
        runtime = _UsageRuntime([_READ, _FINAL], [[(90_000, 0, 50)], [(92_000, 0, 50)]])
        session = ReviewerSession("review-a", _DEADLINE)
        await _exchange(monkeypatch, runtime, session, _FIRST, request)
        runtime.requests.clear()
        result = await _exchange(monkeypatch, runtime, session, history, request)
        assert type(result) is SemanticResultUnavailable and runtime.requests == []
        await session.aclose()


@pytest.mark.parametrize("answer", ["not json", '{"reply":{}}'])
async def test_codex_carries_a_repair_and_the_notice_as_two_inputs(
    monkeypatch: pytest.MonkeyPatch, answer: str
) -> None:
    """After an answer the loop rejected, reads can end too: the repair notice and the
    final-phase notice follow the held thread, each its own input. A JSON object the loop's
    decoder rejected is held with and without it, and the repair extends the snapshot without it."""

    runtime = _UsageRuntime([answer, _FINAL], [[(90_000, 0, 50)], [(90_200, 89_984, 50)]])
    session = ReviewerSession("review-a", _DEADLINE)
    request = "req_74000000-0000-4000-8000-000000000031"
    await _exchange(monkeypatch, runtime, session, _FIRST, request)
    runtime.requests.clear()
    repair = "format_error: output_not_json. Reply with exactly one read action or final_judgment."
    history: tuple[ReviewerMessage, ...] = (*_FIRST, ("user", repair), ("user", FINAL_PHASE))
    result = await _exchange(monkeypatch, runtime, session, history, request)
    assert type(result) is SemanticResultReply
    (turn,) = [params for method, params in runtime.requests if method == "turn/start"]
    assert [item["text"] for item in cast(list[dict[str, str]], turn["input"])] == [
        repair,
        FINAL_PHASE,
    ]
    await session.aclose()


class _Answers(_UsageCapture):
    """The network behind the route's one-attempt transport: each exact body, the next answer.

    Request ``n`` reports ``2_000 * n`` input tokens and its whole predecessor's as cached.
    """

    def __init__(self, route: str, answers: list[str]) -> None:
        usages = [(2_000 * n, 2_000 * (n - 1), 30) for n in range(1, len(answers) + 1)]
        super().__init__(route, cast(list[tuple[int, int | None, int] | None], usages))
        self.answers = answers

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.text = self.answers.pop(0)
        return await super().handle_async_request(request)


class _Offline:
    """The route's real factory; only each one-attempt transport's network hop is replaced."""

    def __init__(
        self,
        factory: OpenAIResponsesExternalFactory | ChatCompletionsExternalFactory,
        network: httpx.AsyncBaseTransport,
    ) -> None:
        self.factory, self.network = factory, network
        self.profile, self.credential_authority = factory.profile, factory.credential_authority
        self.request_ids: list[str] = []

    def render(self, case: ApprovedOutboundCase) -> bytes:
        self.request_ids.append(case.request_id)
        return self.factory.render(case)

    def build_evaluator(self, *args: Any) -> SemanticEvaluatorPort:  # noqa: ANN401
        evaluator = self.factory.build_evaluator(*args)
        cast(Any, evaluator)._transport._inner = self.network  # the exact-body guard stays
        return evaluator


async def _repository_authority_current(_scope: object, _authority_digest: str) -> bool:
    return True


_READ_CALC = canonical_encode(composition._read_file("calc.py")).decode()  # pyright: ignore[reportPrivateUsage]
_JUDGMENT = canonical_encode(composition._FINAL).decode()  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("route", ["responses", "chat"])
@pytest.mark.parametrize(
    ("answers", "repaired"),
    [
        pytest.param([_READ_CALC] * 3 + [_JUDGMENT], None, id="three-reads"),
        pytest.param(
            [_READ_CALC, "not json", _READ_CALC, _READ_CALC, _JUDGMENT], 2, id="repair-then-reads"
        ),
    ],
)
async def test_each_stateless_exchange_through_the_gateway_extends_the_last_byte_for_byte(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    route: str,
    answers: list[str],
    repaired: int | None,
) -> None:
    """#1172: the coordinator re-admits the packet under a new request id on every exchange, and
    the real gateway renders each body afresh; the provider still sees each body's messages begin
    with the last body's, unchanged, and the same settings beside them. Only the final turn after
    a spent repair sends the read-free schema. The review's session reaches every exchange's
    telemetry, which carries the review's first request id and each exchange's prefix."""

    records: list[dict[str, object]] = []

    def record(**fields: object) -> str:
        records.append(fields)
        return "err_74000000-0000-4000-8000-000000000002"

    monkeypatch.setattr(telemetry, "record_bounded_counts_without_raising", record)
    profile = _api_profile(route)
    binding = _api_binding(profile)
    # The real gateway activates a destination only under the repository's own authority.
    policy = replace(
        with_llm(minimal_external_policy(), provider_binding=binding, max_tokens=16_384),
        effective_scope=AuthorizationScope(
            AuthorizationScopeKind.WORKSPACE,
            non_dispatch._INSTALLATION,  # pyright: ignore[reportPrivateUsage]
            non_dispatch._REPOSITORY,  # pyright: ignore[reportPrivateUsage]
        ),
    )
    network = _Answers(route, list(answers))
    factories: list[_Offline] = []

    def gateway_for(audit: object, clock: FixedClock) -> PolicyEnforcingOutboundGateway:
        real = (
            OpenAIResponsesExternalFactory(profile, clock, reply_schemas=REVIEWER_REPLY_SCHEMAS)
            if isinstance(profile, OpenAIProfile)
            else ChatCompletionsExternalFactory(
                profile, clock, reply_schemas=REVIEWER_REPLY_SCHEMAS
            )
        )
        factories.append(_Offline(real, network))
        return PolicyEnforcingOutboundGateway(
            external_factory_builders={binding: lambda: factories[0]},  # pyright: ignore[reportArgumentType]
            local_model_registry=InstalledLocalModelProfileRegistry(),
            local_model_resolver=None,
            credential_minter=_CredentialMinter(),  # pyright: ignore[reportArgumentType]
            audit=cast(Any, audit),
            classifier=LocalPrivacyEnforcer(),
            audit_mac=_AuditKey(),  # pyright: ignore[reportArgumentType]
            clock=clock,
            ids=_Ids(),  # pyright: ignore[reportArgumentType]
            repository_authority_validator=_repository_authority_current,
        )

    result, _gateway, _runtime = await composition._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path, monkeypatch, policy=policy, primary=binding, gateway_for=gateway_for
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    assert network.answers == [] and len(network.bodies) == len(answers)

    key = "input" if route == "responses" else "messages"
    bodies = [cast(dict[str, JsonValue], strict_json_parse(body)) for body in network.bodies]
    # Each body is the canonical encoding, so equal values are equal bytes.
    assert [canonical_encode(body) for body in bodies] == network.bodies
    sent = [cast(list[JsonValue], body[key]) for body in bodies]
    for n, (before, after) in enumerate(zip(sent, sent[1:], strict=False), start=1):
        # Every earlier message, unchanged and first, element for element and byte for byte.
        assert after[: len(before)] == before
        array = canonical_encode(after)
        assert array.startswith(canonical_encode(before)[:-1] + b",")
        assert array in network.bodies[n]
        new = cast(list[dict[str, JsonValue]], after[len(before) :])
        if n == repaired:  # the repair adds only its note; the malformed answer is left out
            assert [(m["role"], str(m["content"])[:13]) for m in new] == [("user", "format_error:")]
        else:  # the read action and its result; the last read's also the final-phase notice
            notice = ["user"] if n == len(sent) - 1 else []
            assert [m["role"] for m in new] == ["assistant", "user", *notice]
    assert cast(dict[str, JsonValue], sent[-1][-1]) == {"content": FINAL_PHASE, "role": "user"}

    def schema(body: dict[str, JsonValue]) -> JsonValue:
        if route == "responses":
            return cast(dict[str, dict[str, JsonValue]], body["text"])["format"]["schema"]
        response_format = cast(dict[str, dict[str, JsonValue]], body["response_format"])
        return response_format["json_schema"]["schema"]

    def beside(body: dict[str, JsonValue]) -> bytes:
        settings = {k: v for k, v in body.items() if k != key}
        if route == "responses":
            text = cast(dict[str, dict[str, JsonValue]], settings["text"])
            settings["text"] = {**text, "format": {**text["format"], "schema": None}}
        else:
            response_format = cast(dict[str, dict[str, JsonValue]], settings["response_format"])
            json_schema = {**response_format["json_schema"], "schema": None}
            settings["response_format"] = {**response_format, "json_schema": json_schema}
        return canonical_encode(cast(JsonValue, settings))

    # Model, output limit, storage opt-out and the reply format never change; the schema does
    # only on the final turn after the review's one repair is spent.
    assert len({beside(body) for body in bodies}) == 1
    schemas = [schema(body) for body in bodies]
    turns = len(bodies) - (repaired is not None)
    assert schemas[:turns] == [REVIEWER_REPLY_SCHEMAS.turn] * turns
    assert schemas[turns:] == [REVIEWER_REPLY_SCHEMAS.final] * (repaired is not None)

    # A new request id per exchange; every record carries the first and its exchange's place.
    (factory,) = factories
    assert len(set(factory.request_ids)) == len(answers)
    assert {cast(str, r["request_id"]) for r in records} == {factory.request_ids[0]}
    counts = [cast(dict[str, object], r["counts"]) for r in records]
    assert [c["reviewer_exchange_index"] for c in counts] == list(range(1, len(answers) + 1))
    assert [c["reviewer_prefix_tokens"] for c in counts] == [2_000 * n for n in range(len(answers))]
    assert [c["reviewer_cache_miss"] for c in counts] == ["first_turn"] + ["none"] * (
        len(answers) - 1
    )
