"""
Shared graph state for trust_engine.

This module is the interface boundary between the orchestrator (item 3)
and the fusion layer (item 4). The orchestrator writes it; fusion reads
it. Both import these models from here rather than redefining them, so
the two halves cannot drift apart -- which is the failure mode the Phase
A audit found across the seven detector services.

Field additions go through the Router/Orchestrator/Fusion interface
agreement, not through a unilateral edit on either side.

Design note: nothing here is flattened into a summary. Fusion needs the
full AgentResult per call to apply its override rules -- "CipherGuard
score >= 90" and "critical Code Security finding" both require reading
actual findings, which a status summary would have discarded.
"""

from __future__ import annotations

import operator
from typing import Annotated, Literal, Optional, TypedDict

from pydantic import BaseModel, Field

from app.routing import Coverage, RoutingDecision
from app.schemas import AgentResult, TrustScoreResult

AgentStatus = Literal["pass", "warn", "fail", "error", "stub", "pending"]


class AgentCallRecord(BaseModel):
    """One (file, agent) pair: what was attempted and what came back.

    agent_ran is deliberately separate from status. An agent that timed
    out has agent_ran=True and status="error" -- it was attempted and the
    outcome is unknown. An agent the router never selected does not appear
    here at all. Fusion needs to tell those apart: the first floors the
    decision at Review, the second simply contributes no weight.
    """

    file: Optional[str] = None
    agent: str
    expected: bool = True
    agent_ran: bool = False
    status: AgentStatus = "stub"
    result: Optional[AgentResult] = None   # null when the call never completed
    elapsed_ms: int = 0
    error_reason: Optional[str] = None     # timeout, transport failure, parse failure
    callback_id: Optional[str] = None      # Prompt Injection, when status is pending


class PendingCallback(BaseModel):
    """An outstanding async result. One per (file, agent), not per request."""

    file: Optional[str] = None
    agent: str
    callback_id: str


class GraphState(TypedDict, total=False):
    """State flowing through the LangGraph graph.

    `results` carries an operator.add reducer so parallel branches append
    rather than overwrite each other -- without it, concurrent fan-out
    branches writing to the same key would race and only one would survive.
    """

    request_id: str
    files: list[dict]                                    # input files, as received
    routing: list[RoutingDecision]                       # one per file
    results: Annotated[list[AgentCallRecord], operator.add]
    pending_callbacks: list[PendingCallback]
    routing_notes: list[str]                             # request-level notes
    scoring: dict
    trust_result: dict                                   # written by fusion


class RoutingSummary(BaseModel):
    """Per-request routing view, surfaced in the engine response.

    Lives in the response's routing block rather than inside any agent's
    evidence, because no agent produced it.
    """

    overall_coverage: Coverage = "none"
    routing: list[RoutingDecision] = Field(default_factory=list)
    pending_callbacks: list[PendingCallback] = Field(default_factory=list)
    routing_notes: list[str] = Field(default_factory=list)


from app.public_schemas import PerFileOutcome

class ScanResponse(TrustScoreResult):
    """What /analyze and GET /scans/{request_id} return.

    TrustScoreResult (fusion's pure output) is left untouched; this wraps
    it with the request-level fields a caller needs to come back for a
    provisional result. All additions are new keys, so existing clients
    that read only the TrustScoreResult fields are unaffected.

    request_id  -- the id GET /scans/{request_id} accepts.
    scan_status -- "provisional" while any callback is outstanding (the
                   explanation then starts "[PROVISIONAL ..."), "final"
                   otherwise. Saves a poller from parsing the prefix.
    routing     -- RoutingSummary, which until now was defined but never
                   attached to any response.
    """

    scoring: dict = Field(default_factory=dict)
    per_file: list[PerFileOutcome] = Field(default_factory=list)
    request_id: str
    scan_status: Literal["final", "provisional"] = "final"
    routing: RoutingSummary = Field(default_factory=RoutingSummary)


_COVERAGE_RANK = {"full": 2, "partial": 1, "none": 0}


def worst_coverage(decisions: list[RoutingDecision]) -> Coverage:
    """The weakest coverage across all files in a request.

    An empty request is "none" rather than "full": having analysed nothing
    is not the same as having analysed everything, and fusion must never
    return Accept on the strength of an empty scan.
    """
    if not decisions:
        return "none"
    return min((d.coverage for d in decisions), key=lambda c: _COVERAGE_RANK[c])

def achieved_coverage(state: GraphState) -> Coverage:
    coverage = worst_coverage(state.get("routing", []))
    records = {(r.file,r.agent):r for r in state.get("results", []) if r.expected}
    for decision in state.get("routing", []):
        for agent in decision.expected_agents:
            record = records.get((decision.filename,agent))
            current = record.result.coverage if record and record.result else "none"
            if _COVERAGE_RANK[current] < _COVERAGE_RANK[coverage]: coverage = current
    return coverage
