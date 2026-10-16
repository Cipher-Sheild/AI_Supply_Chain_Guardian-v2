"""
Tests for the status vocabulary and the shared graph state.

These cover the interface boundary between the orchestrator and fusion:
if any of these break, the two halves have drifted.
"""

import pytest
from pydantic import ValidationError

from app.routing import RoutingDecision, route_file
from app.schemas import AgentResult
from app.state import AgentCallRecord, PendingCallback, RoutingSummary, worst_coverage


# --- Status vocabulary ----------------------------------------------------


@pytest.mark.parametrize(
    "status", ["pass", "warn", "fail", "error", "stub", "pending"]
)
def test_all_six_status_values_validate(status):
    assert AgentResult(agent_name="x", status=status, callback_id="cb" if status == "pending" else None).status == status


def test_unknown_status_is_rejected():
    with pytest.raises(ValidationError):
        AgentResult(agent_name="x", status="banana")


def test_pending_carries_a_callback_id():
    result = AgentResult(
        agent_name="prompt_injection", status="pending", callback_id="cb-123"
    )
    assert result.status == "pending"
    assert result.callback_id == "cb-123"


def test_callback_id_defaults_to_none():
    assert AgentResult(agent_name="x", status="pass").callback_id is None


def test_error_is_distinct_from_fail():
    """A detector that never completed is not the same as one that found
    critical issues. Fusion treats them differently."""
    crashed = AgentResult(agent_name="x", status="error", evidence={"error": "timeout"})
    found = AgentResult(agent_name="x", status="fail")
    assert crashed.status != found.status


# --- Agent call record ----------------------------------------------------


def test_timed_out_call_records_error_and_agent_ran_true():
    """A timeout was still an attempt: agent_ran is True, status is error."""
    record = AgentCallRecord(
        file="app.py", agent="code_security", expected=True,
        agent_ran=True, status="error", result=None,
        elapsed_ms=10_000, error_reason="timeout after 10.0s",
    )
    assert record.agent_ran is True
    assert record.status == "error"
    assert record.result is None
    assert record.error_reason


def test_skipped_agent_has_agent_ran_false():
    record = AgentCallRecord(agent="cipherguard", expected=False, agent_ran=False)
    assert record.agent_ran is False
    assert record.status == "stub"


def test_successful_call_carries_the_full_result():
    """Fusion's override rules read findings, so the whole result is kept."""
    result = AgentResult(agent_name="code_security", status="fail")
    record = AgentCallRecord(
        file="app.py", agent="code_security", agent_ran=True,
        status="fail", result=result, elapsed_ms=2841,
    )
    assert record.result is not None
    assert record.result.agent_name == "code_security"
    assert record.elapsed_ms == 2841


def test_record_rejects_an_invalid_status():
    with pytest.raises(ValidationError):
        AgentCallRecord(agent="x", status="banana")


# --- Coverage aggregation -------------------------------------------------


def test_worst_coverage_takes_the_weakest_file():
    decisions = [
        route_file(content="x", artifact_type="code"),        # full
        route_file(content="x", filename="notes.txt"),         # partial
    ]
    assert worst_coverage(decisions) == "partial"


def test_worst_coverage_of_an_empty_request_is_none():
    """Nothing analysed is not the same as everything analysed."""
    assert worst_coverage([]) == "none"


def test_worst_coverage_all_full():
    decisions = [
        route_file(content="x", artifact_type="code"),
        route_file(content="x", artifact_type="dockerfile"),
    ]
    assert worst_coverage(decisions) == "full"


def test_a_single_unrouted_file_drags_coverage_to_none():
    decisions = [
        route_file(content="x", artifact_type="code"),         # full
        route_file(content="{}", filename="composer.lock"),      # none
    ]
    assert worst_coverage(decisions) == "none"


# --- Routing summary ------------------------------------------------------


def test_routing_summary_round_trips():
    summary = RoutingSummary(
        overall_coverage="partial",
        routing=[route_file(content="x", filename="notes.txt")],
        pending_callbacks=[
            PendingCallback(file="app.py", agent="prompt_injection", callback_id="cb-1")
        ],
        routing_notes=["file cap not reached"],
    )
    dumped = summary.model_dump()
    assert dumped["overall_coverage"] == "partial"
    assert dumped["pending_callbacks"][0]["callback_id"] == "cb-1"


def test_pending_callbacks_are_per_file_agent_pair():
    """One callback per (file, agent), not one per request -- a multi-file
    request can have several outstanding at once."""
    callbacks = [
        PendingCallback(file="a.py", agent="prompt_injection", callback_id="cb-1"),
        PendingCallback(file="b.py", agent="prompt_injection", callback_id="cb-2"),
    ]
    assert len({c.callback_id for c in callbacks}) == 2