"""
Tests for app.fusion.fuse().

GraphState is built by hand -- same style as tests/test_state.py -- with
real RoutingDecisions from route_file() so coverage values are the ones
the router actually produces. No live services, no HTTP.
"""

from typing import Optional

import pytest

from app.fusion import fuse
from app.routing import route_file
from app.schemas import AgentResult, Finding, TrustScoreResult
from app.state import AgentCallRecord, GraphState, PendingCallback


# --- Helpers --------------------------------------------------------------


def _record(
    agent: str,
    file: str = "app.py",
    status: str = "pass",
    findings: Optional[list[Finding]] = None,
    callback_id: Optional[str] = None,
    result_none: bool = False,
    error_reason: Optional[str] = None,
) -> AgentCallRecord:
    result = None
    if not result_none:
        result = AgentResult(
            agent_name=agent, status=status, findings=findings or [],
            callback_id=callback_id,
        )
    return AgentCallRecord(
        file=file, agent=agent, expected=True, agent_ran=True, status=status,
        result=result, elapsed_ms=5, error_reason=error_reason,
        callback_id=callback_id,
    )


def _clean_code_state(file: str = "app.py") -> GraphState:
    decision = route_file(content="print('hi')", filename=file)
    assert decision.coverage == "full"
    return {
        "request_id": "req-1",
        "files": [{"content": "print('hi')", "filename": file}],
        "routing": [decision],
        "results": [_record(a, file=file) for a in decision.expected_agents],
        "pending_callbacks": [],
        "routing_notes": [],
    }


def _finding(severity, category="x", confidence=1.0, location=None, score=None):
    return Finding(
        category=category, severity=severity, confidence=confidence,
        location=location, score=score,
    )


# --- Baseline -------------------------------------------------------------


def test_all_pass_zero_findings_is_100_and_accept():
    out = fuse(_clean_code_state())
    assert isinstance(out, TrustScoreResult)
    assert out.trust_score == 100
    assert out.recommendation == "accept"
    assert "_override" not in out.agent_breakdown
    assert set(out.agent_breakdown) == {"code_security", "secret_detection", "prompt_injection"}
    assert all(v == 0.0 for v in out.agent_breakdown.values())


def test_returns_the_existing_output_contract():
    out = fuse(_clean_code_state())
    assert set(out.model_dump()) == {
        "trust_score", "recommendation", "explanation", "agent_breakdown", "detector_results",
    }
    assert len(out.detector_results) == 3


# --- Step 1: coverage gate ------------------------------------------------


@pytest.mark.parametrize(
    "content,filename",
    [
        ("binary\x00blob", "image.png"),        # binary -> none
        ("{}", "composer.lock"),                   # lockfile -> none
    ],
)
def test_coverage_none_is_never_accept(content, filename):
    clean = _clean_code_state()
    none_decision = route_file(content=content, filename=filename)
    assert none_decision.coverage == "none"
    assert none_decision.expected_agents == []
    clean["routing"].append(none_decision)
    clean["files"].append({"content": content, "filename": filename})
    out = fuse(clean)
    assert out.trust_score == 100          # score alone would say accept
    assert out.recommendation == "review"
    assert filename in out.explanation


def test_empty_request_is_never_accept():
    out = fuse({"routing": [], "results": [], "pending_callbacks": []})
    assert out.recommendation != "accept"


def test_partial_coverage_floors_at_review_with_note():
    decision = route_file(content="key: value", filename="config.yml")
    assert decision.coverage == "partial"
    state: GraphState = {
        "routing": [decision],
        "results": [_record("secret_detection", file="config.yml")],
        "pending_callbacks": [],
    }
    out = fuse(state)
    assert out.trust_score == 100
    assert out.recommendation == "review"
    assert "partial coverage" in out.explanation
    assert "not recognised" in out.explanation     # the router's own note text
    assert "config.yml" in out.explanation


# --- Step 2: status gate --------------------------------------------------


def test_expected_error_floors_at_review_even_when_clean():
    state = _clean_code_state()
    state["results"][0] = _record(
        "code_security", status="error", result_none=True,
        error_reason="timeout after 10.0s",
    )
    out = fuse(state)
    assert out.trust_score == 100
    assert out.recommendation == "review"
    assert "timeout after 10.0s" in out.explanation
    # An errored call still shows up in detector_results, as status=error.
    errored = [r for r in out.detector_results if r.agent_name == "code_security"]
    assert errored and errored[0].status == "error"


def test_pending_is_provisional_and_resolves_on_rerun():
    state = _clean_code_state()
    state["results"] = [
        r if r.agent != "prompt_injection"
        else _record("prompt_injection", status="pending", callback_id="cb-42")
        for r in state["results"]
    ]
    state["pending_callbacks"] = [
        PendingCallback(file="app.py", agent="prompt_injection", callback_id="cb-42")
    ]
    out = fuse(state)
    assert out.explanation.startswith("[PROVISIONAL — awaiting callback cb-42]")
    assert out.recommendation == "review"
    assert "mismatch" not in out.explanation

    # Callback resolves: the record becomes a normal pass, the pending
    # entry is cleared, and fuse() is simply re-run on the new state.
    state["results"] = [
        r if r.agent != "prompt_injection" else _record("prompt_injection")
        for r in state["results"]
    ]
    state["pending_callbacks"] = []
    resolved = fuse(state)
    assert "PROVISIONAL" not in resolved.explanation
    assert resolved.recommendation == "accept"
    assert resolved.trust_score == 100


def test_pending_callback_mismatch_is_surfaced():
    state = _clean_code_state()
    state["results"][2] = _record("prompt_injection", status="pending", callback_id="cb-1")
    state["pending_callbacks"] = []          # disagrees with the record
    out = fuse(state)
    assert "callback bookkeeping mismatch" in out.explanation


def test_errored_record_without_result_contributes_no_findings():
    state = _clean_code_state()
    state["results"][1] = _record("secret_detection", status="error", result_none=True,
                                  error_reason="HTTP 500 from secret_detection")
    out = fuse(state)
    assert out.agent_breakdown["secret_detection"] == 0.0


# --- Step 3: hard overrides -----------------------------------------------


def _state_with(agent: str, finding: Finding, file: str = "app.py") -> GraphState:
    state = _clean_code_state(file)
    if agent == "cipherguard":
        decision = route_file(content="requests\n", filename="requirements.txt")
        state["routing"] = [decision]
        state["results"] = [_record(a, file="requirements.txt") for a in decision.expected_agents]
        file = "requirements.txt"
    state["results"] = [
        r if r.agent != agent else _record(agent, file=file, status="fail", findings=[finding])
        for r in state["results"]
    ]
    return state


@pytest.mark.parametrize(
    "agent,finding,rule",
    [
        # score >= 90, but severity "low" + confidence 0.1 -> weighted risk 0.3,
        # so the weighted score alone would be 99.7 -> accept.
        ("cipherguard", _finding("low", "nonexistent_package", 0.1, score=100),
         "cipherguard_score>=90"),
        ("cipherguard", _finding("low", "typosquat", 0.1, score=90),
         "cipherguard_score>=90"),
        # critical secret: risk 40 * 0.1 = 4 -> score 96 alone.
        ("secret_detection", _finding("critical", "aws_key", 0.1),
         "secret_detection_critical_or_high_confident"),
        # high + confidence >= 0.85: risk 25*0.85 = 21.25 -> 78.75, still not
        # accept on its own, so use the boundary to prove the override fires.
        ("secret_detection", _finding("high", "github_token", 0.85),
         "secret_detection_critical_or_high_confident"),
        ("prompt_injection", _finding("critical", "instruction_override", 0.1),
         "prompt_injection_critical"),
        ("code_security", _finding("critical", "sql_injection", 0.1),
         "code_security_critical"),
    ],
)
def test_each_override_forces_reject(agent, finding, rule):
    out = fuse(_state_with(agent, finding))
    assert out.recommendation == "reject"
    assert out.agent_breakdown["_override"] == rule
    assert out.explanation.startswith("Rejected by hard override")


def test_overrides_fire_where_weighted_score_alone_says_accept():
    """Proves the overrides are doing the work: same findings, weighted
    score by hand, would be accept."""
    for agent, f in [
        ("cipherguard", _finding("low", "nonexistent_package", 0.1, score=100)),
        ("secret_detection", _finding("critical", "aws_key", 0.1)),
        ("prompt_injection", _finding("critical", "x", 0.1)),
        ("code_security", _finding("critical", "x", 0.1)),
    ]:
        from app.fusion import SEVERITY_WEIGHT
        assert 100 - SEVERITY_WEIGHT[f.severity] * f.confidence >= 80
        assert fuse(_state_with(agent, f)).recommendation == "reject"


def test_cipherguard_below_90_does_not_override():
    out = fuse(_state_with("cipherguard", _finding("medium", "typosquat", 0.8, score=89)))
    assert "_override" not in out.agent_breakdown
    assert out.trust_score == 92.0          # 100 - 10*0.8
    assert out.recommendation == "accept"


def test_secret_high_below_confidence_threshold_does_not_override():
    out = fuse(_state_with("secret_detection", _finding("high", "generic", 0.84)))
    assert "_override" not in out.agent_breakdown
    assert out.trust_score == 79.0          # 100 - 25*0.84
    assert out.recommendation == "review"


def test_critical_from_non_override_agent_does_not_override():
    """docker_security has no hard-override rule; a critical there is
    weighted, not forced to reject.

    CHANGED in PR #2 review fixes (severity floor): this used to assert
    "accept" (score 80 with a critical finding present). The new step-6
    gate floors any high/critical finding at Review. It is still NOT an
    override: no _override key, score unchanged at 80."""
    decision = route_file(content="FROM x", filename="Dockerfile")
    state: GraphState = {
        "routing": [decision],
        "results": [
            _record("docker_security", file="Dockerfile", status="fail",
                    findings=[_finding("critical", "root_user", 0.5)]),
            _record("secret_detection", file="Dockerfile"),
        ],
        "pending_callbacks": [],
    }
    out = fuse(state)
    assert "_override" not in out.agent_breakdown
    assert out.trust_score == 80.0
    assert out.recommendation == "review"       # was "accept" before the severity floor
    assert "held at review" in out.explanation


def test_cipherguard_score_survives_parsing_a_real_cipherguard_payload():
    """CipherGuard's Finding carries `score` at the top level. trust_engine's
    Finding must declare it, or Pydantic drops it on parse and the >=90
    override can never fire in the live system."""
    payload = {
        "agent_name": "cipherguard",
        "status": "fail",
        "findings": [{
            "detector_id": "cipherguard", "file_path": "requirements.txt",
            "line_number": 1, "preview": "reqeusts", "confidence": 1.0,
            "severity": "critical", "reason": "Package does not exist",
            "remediation": "Remove", "package": "reqeusts", "ecosystem": "python",
            "score": 100, "signals": ["nonexistent"], "risk_contribution": 100,
            "recommendation": "block", "category": "cipherguard",
        }],
        "evidence": {},
    }
    # v1 rich fields travel inside details; portable fields remain top-level.
    raw = payload["findings"][0]
    portable = {k:v for k,v in raw.items() if k in Finding.model_fields}
    portable["location"] = "requirements.txt:1"
    portable["details"] = {k:v for k,v in raw.items() if k not in Finding.model_fields}
    payload["findings"] = [portable]
    parsed = AgentResult(**payload)
    assert parsed.findings[0].score == 100


# --- Step 4/5: weighted score and bands ------------------------------------


def test_weighted_score_and_breakdown():
    state = _clean_code_state()
    state["results"][0] = _record("code_security", status="warn", findings=[
        _finding("high", "xss", 0.8),      # 20
        _finding("medium", "weak_hash", 0.5),  # 5
    ])
    out = fuse(state)
    assert out.trust_score == 75.0
    assert out.recommendation == "review"
    assert out.agent_breakdown["code_security"] == -25.0
    assert "xss" in out.explanation


def test_score_clamps_at_zero_and_rejects():
    state = _clean_code_state()
    state["results"][0] = _record("code_security", status="fail", findings=[
        _finding("high", f"issue{i}", 1.0) for i in range(6)   # 150 risk
    ])
    out = fuse(state)
    assert out.trust_score == 0.0
    assert out.recommendation == "reject"


# --- Multi-file -----------------------------------------------------------


def test_multi_file_worse_file_wins_and_both_named():
    clean = route_file(content="print('hi')", filename="clean.py")
    dirty = route_file(content="x = 1", filename="dirty.py")
    state: GraphState = {
        "routing": [clean, dirty],
        "results": (
            [_record(a, file="clean.py") for a in clean.expected_agents]
            + [
                _record("code_security", file="dirty.py", status="fail",
                        findings=[_finding("critical", "command_injection", 0.9,
                                           location="dirty.py:1")]),
                _record("secret_detection", file="dirty.py"),
                _record("prompt_injection", file="dirty.py"),
            ]
        ),
        "pending_callbacks": [],
    }
    out = fuse(state)
    assert out.recommendation == "reject"
    assert "dirty.py" in out.explanation
    # Both files' records are present in the response.
    files_seen = {r.file for r in state["results"]}
    assert files_seen == {"clean.py", "dirty.py"}
    assert len(out.detector_results) == 6


def test_multi_file_weighted_names_both_files():
    a = route_file(content="1", filename="a.py")
    b = route_file(content="2", filename="b.py")
    state: GraphState = {
        "routing": [a, b],
        "results": [
            _record("code_security", file="a.py", status="warn",
                    findings=[_finding("medium", "weak_hash", 1.0)]),
            _record("code_security", file="b.py", status="warn",
                    findings=[_finding("low", "debug_flag", 1.0)]),
        ],
        "pending_callbacks": [],
    }
    out = fuse(state)
    assert out.trust_score == 87.0
    assert "a.py" in out.explanation and "b.py" in out.explanation
    assert out.agent_breakdown["code_security"] == -13.0


def test_fuse_is_pure_same_input_same_output():
    state = _clean_code_state()
    assert fuse(state).model_dump() == fuse(state).model_dump()


# --- Step 6: severity floor (PR #2 review fixes) ----------------------------


def _with_pi(findings, status="fail"):
    state = _clean_code_state()
    state["results"] = [
        r if r.agent != "prompt_injection"
        else _record("prompt_injection", status=status, findings=findings)
        for r in state["results"]
    ]
    return state


def test_single_high_finding_scoring_80_is_review_not_accept():
    """The exact case Ahmed flagged: high prompt_injection at 0.8 ->
    risk 20 -> score 80, which the band alone calls accept."""
    out = fuse(_with_pi([_finding("high", "prompt_injection", 0.8, location="app.py:1")]))
    assert out.trust_score == 80.0                  # score itself untouched
    assert out.recommendation == "review"
    assert "_override" not in out.agent_breakdown
    assert "held at review" in out.explanation
    assert "high prompt_injection from prompt_injection in app.py (app.py:1)" in out.explanation


def test_high_finding_resolved_from_pending_callback_ends_at_review():
    state = _clean_code_state()
    state["results"] = [
        r if r.agent != "prompt_injection"
        else _record("prompt_injection", status="pending", callback_id="cb-7")
        for r in state["results"]
    ]
    state["pending_callbacks"] = [
        PendingCallback(file="app.py", agent="prompt_injection", callback_id="cb-7")
    ]
    provisional = fuse(state)
    assert provisional.explanation.startswith("[PROVISIONAL — awaiting callback cb-7]")
    assert provisional.recommendation == "review"
    # Pending floor already explains review; no severity clause yet (no findings).
    assert "held at review" not in provisional.explanation

    state["results"] = [
        r if r.agent != "prompt_injection"
        else _record("prompt_injection", status="fail", callback_id="cb-7",
                     findings=[_finding("high", "prompt_injection", 0.8)])
        for r in state["results"]
    ]
    state["pending_callbacks"] = []
    resolved = fuse(state)
    assert "PROVISIONAL" not in resolved.explanation
    assert resolved.trust_score == 80.0
    assert resolved.recommendation == "review"
    assert "held at review" in resolved.explanation


def test_critical_override_still_rejects_and_floor_adds_no_text():
    out = fuse(_with_pi([_finding("critical", "prompt_injection", 0.9)]))
    assert out.recommendation == "reject"
    assert out.agent_breakdown["_override"] == "prompt_injection_critical"
    assert "held at review" not in out.explanation


def test_severity_floor_never_lifts_reject():
    state = _clean_code_state()
    state["results"][0] = _record("code_security", status="fail", findings=[
        _finding("high", f"issue{i}", 1.0) for i in range(3)      # 75 risk -> 25
    ])
    out = fuse(state)
    assert out.trust_score == 25.0
    assert out.recommendation == "reject"
    assert "held at review" not in out.explanation


def test_score_already_review_gets_no_extra_text():
    out = fuse(_with_pi([_finding("high", "prompt_injection", 1.0)]))   # 75 -> review
    assert out.recommendation == "review"
    assert "held at review" not in out.explanation


@pytest.mark.parametrize("severity", ["medium", "low", "info"])
def test_medium_low_info_only_still_accept(severity):
    out = fuse(_with_pi([_finding(severity, "x", 1.0)], status="warn"))
    assert out.trust_score >= 80
    assert out.recommendation == "accept"
    assert "held at review" not in out.explanation


def test_clean_still_accept_with_no_severity_text():
    out = fuse(_clean_code_state())
    assert out.recommendation == "accept"
    assert "held at review" not in out.explanation


def test_errored_record_without_result_does_not_trigger_severity_floor():
    """Only agents that returned a result count; error records carry no
    findings (they already floor at review via the status gate)."""
    state = _clean_code_state()
    state["results"][0] = _record("code_security", status="error", result_none=True,
                                  error_reason="timeout")
    out = fuse(state)
    assert out.recommendation == "review"
    assert "held at review" not in out.explanation
