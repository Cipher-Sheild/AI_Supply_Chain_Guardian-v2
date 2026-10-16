"""
Trust Score fusion.

`fuse(state) -> TrustScoreResult` is a pure function: no HTTP, no DB, no
clock, no randomness. Given the same GraphState it always returns the same
result, so it can be re-run (e.g. after a pending callback resolves) and
tested by hand-building state.

Order of evaluation:

1. Coverage gate   -- worst coverage across files. "none"/"partial" can
                      never be Accept (floor at Review).
2. Status gate     -- any expected agent with status "error", or any
                      "pending" result, floors at Review. Pending also
                      marks the explanation PROVISIONAL.
3. Hard overrides  -- any one forces Reject, regardless of score.
4. Weighted score  -- only decides the band when no override fired.
5. Decision bands  -- >=80 accept, 50-79 review, <50 reject. Gates from
                      steps 1-2 only ever add caution.
6. Severity floor  -- any high/critical finding from an agent that
                      returned a result floors at Review, so a confirmed
                      high-severity issue can never land on Accept just
                      because its weighted risk alone keeps the score >= 80.
                      Like the other gates it only adds caution: it never
                      moves Reject to Review and never changes trust_score.

When an override fires, trust_score is reported as 0.0: the weighted score
did not decide the outcome, and reporting e.g. 92/100 next to "reject"
would mislead a reader. Per-agent risk contributions are still reported in
agent_breakdown so the dashboard can show what else was found.
"""

from __future__ import annotations

import logging
import math
from typing import Optional

from app.scorers import DEFAULT_SCORER, Scorer
from app.schemas import AgentResult, Finding, TrustScoreResult
from app.state import AgentCallRecord, GraphState, worst_coverage

logger = logging.getLogger(__name__)

SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}

# Step 6: findings at these severities floor the decision at Review.
SEVERITY_FLOOR = ("high", "critical")

ACCEPT_MIN_SCORE = 80
REVIEW_MIN_SCORE = 50

CIPHERGUARD_OVERRIDE_SCORE = 90
SECRET_HIGH_CONFIDENCE = 0.85

_RANK = {"accept": 0, "review": 1, "reject": 2}


def _floor(current: str, minimum: str) -> str:
    """Return the more cautious of two recommendations."""
    return current if _RANK[current] >= _RANK[minimum] else minimum


def _band(score: float) -> str:
    if score >= ACCEPT_MIN_SCORE:
        return "accept"
    if score >= REVIEW_MIN_SCORE:
        return "review"
    return "reject"


def _where(record: AgentCallRecord, finding: Optional[Finding] = None) -> str:
    """Human-readable location: filename, plus the finding's own location
    when it has one and it is not just the filename again."""
    file = record.file or "<unnamed file>"
    loc = finding.location if finding is not None else None
    if loc and loc != record.file:
        return f"{file} ({loc})"
    return file


# --- Step 3: hard overrides -----------------------------------------------


def _check_override(record: AgentCallRecord) -> Optional[tuple[str, str]]:
    """Return (rule_id, human description) for the first override this
    record triggers, or None. Only completed results carry findings."""
    if record.result is None or not record.expected or not record.agent_ran:
        return None
    findings = record.result.findings
    if record.result.decision_floor == "reject":
        return ("agent_policy_reject", f"{record.agent} requires rejection in {_where(record)}")
    if any(f.hard_block for f in findings):
        return ("hard_block", f"{record.agent} confirmed a hard block in {_where(record)}")
    agent = record.agent

    if agent == "cipherguard":
        scores = [f.score for f in findings if f.score is not None]
        if scores and max(scores) >= CIPHERGUARD_OVERRIDE_SCORE:
            top = max(
                (f for f in findings if f.score is not None), key=lambda f: f.score
            )
            pkg = (top.details or {}).get("package") or (top.details or {}).get("package_name")
            what = f"package '{pkg}'" if pkg else "a dependency"
            return (
                "cipherguard_score>=90",
                f"CipherGuard scored {what} {top.score:g}/100 "
                f"(>= {CIPHERGUARD_OVERRIDE_SCORE}) in {_where(record, top)}",
            )

    if agent == "secret_detection":
        for f in findings:
            if f.severity == "critical" or (
                f.severity == "high" and f.confidence >= SECRET_HIGH_CONFIDENCE
            ):
                return (
                    "secret_detection_critical_or_high_confident",
                    f"Secret Detection found a {f.severity} {f.category} "
                    f"(confidence {f.confidence:.2f}) in {_where(record, f)}",
                )

    if agent == "prompt_injection":
        for f in findings:
            if f.severity == "critical":
                return (
                    "prompt_injection_critical",
                    f"Prompt Injection found a critical {f.category} in {_where(record, f)}",
                )

    if agent == "code_security":
        for f in findings:
            if f.severity == "critical":
                return (
                    "code_security_critical",
                    f"Code Security found a critical {f.category} in {_where(record, f)}",
                )

    return None


# --- Main entry point -----------------------------------------------------


def fuse(state: GraphState, scorer: Scorer = DEFAULT_SCORER) -> TrustScoreResult:
    routing = state.get("routing", []) or []
    records: list[AgentCallRecord] = [r for r in (state.get("results", []) or []) if r.expected]
    floor = "accept"
    caveats: list[str] = []

    # Step 1 -- coverage gate.
    coverage = worst_coverage(routing)
    if coverage in ("none", "partial"):
        floor = _floor(floor, "review")
        for decision in routing:
            if decision.coverage == "full":
                continue
            name = decision.filename or "<unnamed file>"
            reasons = "; ".join(decision.notes) or "no reason recorded"
            caveats.append(f"{decision.coverage} coverage: {reasons} — `{name}`")
        if not routing:
            caveats.append("no coverage: request contained no files")

    expected = [(d.filename, a) for d in routing for a in d.expected_agents]
    present = {(r.file, r.agent) for r in records if r.expected}
    if any(pair not in present for pair in expected):
        floor = _floor(floor, "review")
        caveats.append("missing expected detector results")
    if state.get("routing_notes"):
        floor = _floor(floor, "review")
        caveats.extend(state["routing_notes"])
    for r in records:
        if not r.expected:
            continue
        result = r.result
        if not r.agent_ran:
            floor = _floor(floor, "review")
            caveats.append(f"{r.agent} did not run")
        if result is None or r.status == "stub" or (r.status == "fail" and (result is None or not result.findings)):
            floor = _floor(floor, "review")
            caveats.append(f"{r.agent} did not provide a completed usable result")
        if result and (result.status != r.status or result.agent_name != r.agent):
            floor = _floor(floor, "review")
            caveats.append("inconsistent detector identity or status")
        if result:
            floor = _floor(floor, result.decision_floor)
            if result.unresolved or result.coverage != "full":
                floor = _floor(floor, "review")
                caveats.append(f"{r.agent} reported unresolved or incomplete coverage")
            if any(f.category == "license_review" for f in result.findings):
                floor = _floor(floor, "review")
                caveats.append("license policy requires review")

    # Step 2 -- status gate.
    errored = [r for r in records if r.expected and r.status == "error"]
    if errored:
        floor = _floor(floor, "review")
        parts = [
            f"{r.agent} on {r.file or '<unnamed file>'}: {r.error_reason or 'agent reported error'}"
            for r in errored
        ]
        caveats.append(
            f"{len(errored)} expected agent call(s) did not complete ({'; '.join(parts)})"
        )

    pending = [r for r in records if r.status == "pending"]
    provisional_prefix = ""
    if pending:
        floor = _floor(floor, "review")
        ids = [
            r.callback_id or (r.result.callback_id if r.result else None) or "unknown"
            for r in pending
        ]
        provisional_prefix = f"[PROVISIONAL — awaiting callback {', '.join(ids)}] "

    # Cross-check pending records against state["pending_callbacks"].
    from_records = {
        (r.file, r.agent, r.callback_id) for r in pending
    }
    from_state = {
        (p.file, p.agent, p.callback_id) for p in (state.get("pending_callbacks", []) or [])
    }
    if from_records != from_state:
        mismatch = (
            f"callback bookkeeping mismatch: records={sorted(map(str, from_records))} "
            f"pending_callbacks={sorted(map(str, from_state))}"
        )
        floor = _floor(floor, "review")
        logger.warning(mismatch)
        caveats.append(mismatch)

    # Step 3 -- hard overrides.
    override: Optional[tuple[str, str]] = None
    for r in records:
        override = _check_override(r)
        if override:
            break

    # Step 4 -- weighted risk (computed always; decides the score only
    # when no override fired).
    breakdown: dict = {}
    scored: list[tuple[float, AgentCallRecord, Finding]] = []
    total_risk = 0.0
    for r in records:
        breakdown.setdefault(r.agent, 0.0)
        if r.result is None or not r.agent_ran:
            continue
        for f in r.result.findings:
            risk = SEVERITY_WEIGHT[f.severity] * f.confidence
            total_risk += risk
            breakdown[r.agent] -= risk
            if risk > 0:
                scored.append((risk, r, f))
    breakdown = {k: (round(v, 2) if v else 0.0) for k, v in breakdown.items()}

    if override:
        trust_score = 0.0
        recommendation = "reject"
        breakdown["_override"] = override[0]
    else:
        trust_score = scorer.score(state, total_risk)
        if not isinstance(trust_score, (int, float)) or not math.isfinite(trust_score) or not 0 <= trust_score <= 100:
            raise ValueError("scorer must return a finite score in [0, 100]")
        recommendation = _band(trust_score)
        if (state.get('_model_scoring') or {}).get('method')=='weighted_fallback':
            floor=_floor(floor,'review')
            caveats.append('configured ML scorer unavailable; weighted fallback requires review')

    # Step 5 -- gates only add caution.
    recommendation = _floor(recommendation, floor)

    # Step 6 -- severity floor. Explained only when it is what moved the
    # decision off Accept; if the score, an override or another gate
    # already says review/reject, that explanation already stands.
    severe = [
        (r, f)
        for r in records
        if r.result is not None
        for f in r.result.findings
        if f.severity in SEVERITY_FLOOR
    ]
    if severe and recommendation == "accept":
        recommendation = "review"
        shown = "; ".join(
            f"{f.severity} {f.category} from {r.agent} in {_where(r, f)}" for r, f in severe[:3]
        )
        more = f" (+{len(severe) - 3} more)" if len(severe) > 3 else ""
        caveats.append(
            f"held at review because {len(severe)} high/critical finding(s) are present "
            f"({shown}{more}); the score alone would have been accept"
        )

    # Explanation.
    if override:
        lead = f"Rejected by hard override: {override[1]}."
    else:
        lead = f"Trust score {trust_score:g}/100 ({recommendation})."
        if scored:
            scored.sort(key=lambda t: t[0], reverse=True)
            tops = [
                f"{f.severity} {f.category} from {r.agent} in {_where(r, f)} (risk {risk:.1f})"
                for risk, r, f in scored[:3]
            ]
            lead += " Top risks: " + "; ".join(tops) + "."
        else:
            lead += f" No findings from {len(records)} agent call(s)."
    explanation = provisional_prefix + lead
    if caveats:
        explanation += " " + " ".join(c.rstrip(".") + "." for c in caveats)

    detector_results = [
        r.result
        if r.result is not None
        else AgentResult(
            agent_name=r.agent,
            status="error",
            findings=[],
            evidence={"error": r.error_reason, "file": r.file},
        )
        for r in records
    ]

    output = TrustScoreResult(
        trust_score=trust_score,
        recommendation=recommendation,
        explanation=explanation,
        agent_breakdown=breakdown,
        detector_results=detector_results,
    )

    from app.ml.explanation import scoring_details
    state["scoring"] = scoring_details(state, output)
    return output
