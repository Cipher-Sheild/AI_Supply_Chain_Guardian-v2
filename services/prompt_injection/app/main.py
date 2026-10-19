from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from uuid import uuid4

import httpx

import yaml
from dotenv import load_dotenv
from fastapi import FastAPI

from app.correlation import build_combined_span, collect_weak_candidates, contributing_locations
from app.embeddings import batch_similarity_to_anchors, combine_confidence, preload as preload_embeddings
from app.extraction import Span, extract_spans
from app.heuristics import HeuristicResult, HeuristicScanner
from app.judge import judge_span
from app.semantic_classifier import ClassifierUnavailable
from app.schemas import AgentResult, ArtifactRequest
from app.redaction import redact

load_dotenv()

logger = logging.getLogger("prompt_injection.main")
AGENT_NAME = "prompt_injection"
app = FastAPI(title=f"AI Supply Chain Guardian -- {AGENT_NAME}")
_CONFIG_PATH = Path(__file__).parent.parent / "config.yml"


def _load_config() -> dict:
    with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


_config = _load_config()
_scanner = HeuristicScanner(_config)


@app.on_event("startup")
async def _startup() -> None:
    def warm_models():
        # Transformers lazily imports shared modules. Serialize cold imports
        # for the embedding model and optional local judge in one worker.
        preload_embeddings()
        if os.getenv('LLM_PROVIDER','ollama')=='local':
            from app.local_judge import warm
            try: warm()
            except Exception:
                logger.warning('Local judge warm-up failed; readiness remains degraded', exc_info=True)
    _spawn(asyncio.to_thread(warm_models))
    _spawn(_outbox_worker())


@app.get("/health")
async def health():
    from app.readiness import readiness
    return await readiness(AGENT_NAME)



# ---------------------------------------------------------------------------
# Severity / status mapping
# ---------------------------------------------------------------------------

def _severity_for(confidence: float) -> str:
    """Map a 0-1 confidence score onto the trust_engine Finding.severity enum.

    Uses the existing severity_thresholds (fail/warn) plus a new "critical"
    breakpoint for the highest-confidence, unambiguous matches (e.g. a
    blatant Stage-1 heuristic hit). critical/fail/warn thresholds are all
    read from config.yml with sane fallbacks, so config.yml does not have
    to be edited for this to work, though adding an explicit
    `severity_thresholds.critical: 0.9` entry is recommended for clarity.
    """
    thresholds = _config["severity_thresholds"]
    critical = thresholds.get("critical", 0.9)
    fail = thresholds["fail"]
    warn = thresholds["warn"]
    if confidence >= critical:
        return "critical"
    if confidence >= fail:
        return "high"
    if confidence >= warn:
        return "medium"
    return "low"


def _status_for(confidence: float) -> str:
    thresholds = _config["severity_thresholds"]
    if confidence >= thresholds["fail"]:
        return "fail"
    if confidence >= thresholds["warn"]:
        return "warn"
    return "pass"


def _location_str(span: Span) -> str:
    """Flatten a Span's nested Location into the single string trust_engine expects."""
    location = span.location
    filename = location.filename
    line = location.line
    if filename and line is not None:
        return f"{filename}:{line}"
    if line is not None:
        return f"line {line}"
    if filename:
        return filename
    return "unknown"


# ---------------------------------------------------------------------------
# Finding builders -- every one of these now returns a Finding-shaped dict:
# {category, severity, confidence, location, details}. All stage-specific
# and diagnostic data (stage name, source_type, snippet, heuristic_score,
# embedding_similarity, judge evidence, contributing_locations, ...) lives
# only inside `details`.
# ---------------------------------------------------------------------------

def _heuristic_finding(span: Span, heuristic_result: HeuristicResult) -> dict:
    confidence = heuristic_result.score
    return {
        "category": "prompt_injection",
        "severity": _severity_for(confidence),
        "confidence": round(confidence, 4),
        "location": _location_str(span),
        "details": {
            "stage": "heuristic",
            "source_type": span.source_type,
            "text_snippet": span.text[:200],
            "evidence": "; ".join(heuristic_result.reasons) or "matched heuristic pattern",
        },
    }


def _embedding_finding(
    span: Span,
    heuristic_result: HeuristicResult,
    similarity: float,
    combined: float,
    stage: str = "embedding",
) -> dict:
    return {
        "category": "prompt_injection",
        "severity": _severity_for(combined),
        "confidence": round(combined, 4),
        "location": _location_str(span),
        "details": {
            "stage": stage,
            "source_type": span.source_type,
            "text_snippet": span.text[:200],
            "heuristic_score": round(heuristic_result.score, 4),
            "embedding_similarity": round(similarity, 4),
            "evidence": "; ".join(heuristic_result.reasons) or "semantic similarity to known injection phrasing",
        },
    }


def _capped_finding(
    span: Span,
    heuristic_result: HeuristicResult,
    similarity: float,
    combined: float,
    stage: str = "embedding_capped",
) -> dict:
    return {
        "category": "prompt_injection",
        "severity": _severity_for(combined),
        "confidence": round(combined, 4),
        "location": _location_str(span),
        "details": {
            "stage": stage,
            "source_type": span.source_type,
            "text_snippet": span.text[:200],
            "heuristic_score": round(heuristic_result.score, 4),
            "embedding_similarity": round(similarity, 4),
            "evidence": "escalation-band confidence, but per-artifact LLM call budget was exhausted "
                        "-- flagged unverified by Stage 3",
        },
    }


async def _llm_judge_finding(
    span: Span,
    heuristic_result: HeuristicResult,
    similarity: float,
    judge_cfg: dict,
    stage: str = "llm_judge",
    failures: Optional[list[dict]] = None,
) -> dict | None:
    """A finding if the judge confirms an injection, else None.

    A judge that produced no verdict (call failed, response unparseable)
    is NOT a "not injection" verdict: it is recorded in `failures` (when
    given) so the caller can report status="error" instead of "pass".
    """
    votes = judge_cfg.get("votes", 1)
    result = await judge_span(span, votes=votes)
    if getattr(result, "failed", False):
        if failures is not None:
            failures.append({
                "location": _location_str(span),
                "stage": stage,
                "reason": result.failure_reason or "LLM judge produced no verdict",
            })
        return None
    if result.confidence < judge_cfg.get("min_confidence_to_flag", 0.5):
        if failures is not None: failures.append({"location":_location_str(span),"stage":stage,"reason":"Judge confidence below decision threshold"})
        return None
    if result.is_injection and result.confidence >= judge_cfg.get("min_confidence_to_flag", 0.5):
        details = {
            "stage": stage,
            "source_type": span.source_type,
            "text_snippet": span.text[:200],
            "heuristic_score": round(heuristic_result.score, 4),
            "embedding_similarity": round(similarity, 4),
            "evidence": result.justification,
        }
        if result.votes_total > 1:
            details["judge_votes"] = f"{result.votes_for}/{result.votes_total}"
        return {
            "category": "prompt_injection",
            "severity": _severity_for(result.confidence),
            "confidence": round(result.confidence, 4),
            "location": _location_str(span),
            "details": details,
        }
    classifier_candidate=any(reason.startswith('__guardian_classifier_candidate__') for reason in heuristic_result.reasons)
    # A plain document title is not an instruction. Only clear classifier-only
    # title noise after an explicit, high-confidence benign contextual verdict.
    # Action/authority headings, heuristic signals and ambiguous judges retain
    # the existing Review behaviour.
    import re
    ordinary_title=(span.source_type=='markdown_prose'
        and re.fullmatch(r'#{1,6}\s+[\w][\w &()/.-]{0,100}',span.text.strip()) is not None
        and not re.search(r'\b(ignore|reveal|send|override|follow|forget|execute|run|read|write|system|assistant|prompt|instructions?|polic(?:y|ies)|trust|exfiltrat\w*|bypass)\b',span.text,re.I))
    signals=[re.fullmatch(r'__guardian_classifier_candidate__ probability=(0(?:\.\d+)?|1(?:\.0+)?)',reason)
             for reason in heuristic_result.reasons]
    weak_classifier=bool(signals) and all(match is not None and float(match.group(1))<0.7 for match in signals)
    if (classifier_candidate and weak_classifier and ordinary_title and heuristic_result.score==0
            and not heuristic_result.authority_review
            and all(reason.startswith('__guardian_classifier_candidate__') for reason in heuristic_result.reasons)
            and result.requires_review is False and result.confidence>=0.9):
        return None
    # Public re-evaluation showed that allowing a benign LLM verdict to clear
    # a trained screening signal increased false accepts. Keep disagreement
    # at Review; explicit contextual ambiguity also requires Review.
    if result.requires_review is True or classifier_candidate:
        return {'category':'prompt_injection_uncertain','severity':'medium','confidence':0.55,
            'location':_location_str(span),'details':{'stage':'classifier_judge_disagreement',
            'source_type':span.source_type,'text_snippet':span.text[:200],
            'evidence':'The trained screening model flagged this instruction-like span, while contextual judgment did not confirm an attack. Review its authority before an AI follows it.',
            'classifier_signals':heuristic_result.reasons}}
    return None


# ---------------------------------------------------------------------------
# Async Stage 3: pending result now, resolved result via callback later.
#
# Stage 3 (the LLM judge) is the only slow part of this service: 10-70s
# per call against a local model (README), while trust_engine waits at
# most DETECTOR_TIMEOUT_SECONDS (10s) for any detector. So when an
# artifact needs at least one real judge call, /analyze answers at once
# with status="pending" + a callback_id, carrying only what Stages 1+2
# (and the deterministic over-budget "capped" logic) have already
# decided. A background task runs the judge calls, computes the real
# status over the complete finding set, and POSTs the resolved
# AgentResult (same agent_name, same callback_id) to trust_engine.
#
# When nothing escalates (the common case) none of this runs: the result
# is synchronous pass/warn/fail exactly as before.
# ---------------------------------------------------------------------------

# Full callback URL, with "{callback_id}" substituted per request, e.g.
# http://trust_engine:8000/callback/{callback_id}. Named in the same
# <SERVICE>_..._URL style as trust_engine's DETECTOR_URL_ENV_VARS. If the
# value has no "{callback_id}" placeholder, the id is appended as a path
# segment.
CALLBACK_URL_ENV_VAR = "TRUST_ENGINE_CALLBACK_URL"
# Shared secret, identical to trust_engine's CALLBACK_TOKEN. Sent as
# X-Callback-Token on every callback POST; trust_engine rejects callbacks
# without it (401). Never logged.
CALLBACK_TOKEN_ENV_VAR = "CALLBACK_TOKEN"
CALLBACK_TOKEN_HEADER = "X-Callback-Token"
CALLBACK_TIMEOUT_SECONDS = 10.0
# Transport error / timeout / 5xx: one attempt plus exactly one retry;
# after that the result is dropped with a warning. Nobody is left waiting
# on this HTTP request to report an error to, and trust_engine's pending
# snapshot expires on its own TTL.
CALLBACK_MAX_ATTEMPTS = 2
CALLBACK_RETRY_DELAY_SECONDS = 1.0
# 404: retried on this schedule (seconds to wait before each retry).
#
# Why 404 is retried: trust_engine stores the pending scan in Redis only
# AFTER its /analyze graph finishes, and the graph waits for the slowest
# routed detector (~2 s for code_security, up to trust_engine's
# DETECTOR_TIMEOUT_SECONDS = 10 s). Stage 3 here starts the moment we
# answer "pending", so a fast judge (a fast model, or one that fails
# instantly: no API key, wrong model, 403) can call back before the scan
# exists -- and trust_engine answers 404. That 404 almost always means
# "not stored yet", rarely "expired" (the TTL is an hour).
#
# Window: 0.5+1+1.5+2+3+3+4 = 15 s of waiting over 8 attempts -- the 10 s
# detector timeout plus ~5 s for routing, fusion and the Redis write, with
# early retries short so the common ~2 s case resolves within a second or
# two. It cannot cover a request whose graph takes longer than ~15 s
# (e.g. many files queued behind MAX_CONCURRENT_AGENT_CALLS); /analyze only
# accepts a single artifact today, so that is not reachable yet.
CALLBACK_NOT_FOUND_RETRY_DELAYS_SECONDS = (0.5, 1.0, 1.5, 2.0, 3.0, 3.0, 4.0)

# Indirection so tests can skip real waiting without patching the global
# asyncio.sleep the event loop itself relies on.
_sleep = asyncio.sleep

# Strong references to in-flight background tasks. asyncio only keeps a
# weak reference to a task, so without this set a pending Stage 3 run
# could be garbage-collected mid-flight. Tests also use it to await the
# background work deterministically.
_background_tasks: set[asyncio.Task] = set()



def _callback_token() -> Optional[str]:
    token = os.getenv(CALLBACK_TOKEN_ENV_VAR, "").strip()
    return token or None


def _callback_url(callback_id: str) -> Optional[str]:
    template = os.getenv(CALLBACK_URL_ENV_VAR, "").strip()
    if not template:
        return None
    if "{callback_id}" in template:
        # str.replace rather than str.format: a URL may legitimately
        # contain other braces, which .format() would choke on.
        return template.replace("{callback_id}", callback_id)
    return f"{template.rstrip('/')}/{callback_id}"


@dataclass
class _Stage3Plan:
    """Everything decided synchronously, plus the LLM work still to do.

    The finding *order* of the old single-pass analyze() is preserved by
    _assemble(): Stage 1/2 findings, then judge findings, then capped
    overflow, then the cross-span finding.
    """

    base_findings: list[dict]                        # Stage 1 + Stage 2 flags
    to_judge: list[tuple]                            # (span, h, similarity, combined)
    overflow_findings: list[dict]                    # over-budget, capped -- no LLM
    cross_span_finding: Optional[dict] = None        # cross-span result decided w/o LLM
    cross_span_judge: Optional[tuple] = None         # (span, h, similarity, contributing)
    spans_scanned: int = 0
    escalation_count: int = 0
    judge_findings: list[dict] = field(default_factory=list)
    cross_span_llm_finding: Optional[dict] = None
    # Spans the judge could not decide (see _llm_judge_finding).
    judge_failures: list[dict] = field(default_factory=list)

    @property
    def needs_llm(self) -> bool:
        return bool(self.to_judge) or self.cross_span_judge is not None

    def sync_findings(self) -> list[dict]:
        """What is already known before any judge call returns."""
        out = list(self.base_findings) + list(self.overflow_findings)
        if self.cross_span_finding is not None:
            out.append(self.cross_span_finding)
        return out

    def all_findings(self) -> list[dict]:
        out = list(self.base_findings) + list(self.judge_findings) + list(self.overflow_findings)
        if self.cross_span_finding is not None:
            out.append(self.cross_span_finding)
        if self.cross_span_llm_finding is not None:
            out.append(self.cross_span_llm_finding)
        return out


class WorkLimitExceeded(ValueError):
    pass

def _plan(artifact: ArtifactRequest) -> _Stage3Plan:
    """Stages 1 and 2, the budget split, and the cross-span decision.

    Logic is unchanged from the original single-pass analyze(); only the
    LLM awaits have been lifted out into _run_stage3(). Whether the
    cross-span check needs the judge is knowable here without any LLM
    call: it depends only on Stage 1+2 scores and on len(to_judge).
    """
    high_conf_threshold = _config["regex_heuristics"]["high_confidence_threshold"]
    band = _config["fusion"]["escalation_band"]
    fusion_weights = _config["fusion"]
    max_llm_calls = _config["fusion"].get("max_llm_calls_per_artifact", 5)
    weak_floor = _config["fusion"].get("cross_span_weak_floor", 0.15)

    # extract_spans expects the plain artifact fields (content/type/filename/
    # ai_tool_source) it always has -- converting the validated ArtifactRequest
    # to a dict here keeps extraction.py untouched.
    spans = extract_spans(artifact.model_dump())
    if len(spans)>200: raise WorkLimitExceeded("artifact exceeds 200 extracted spans")
    findings: list[dict] = []

    # Pass 1: Stage 1 (heuristics) on every span.
    heuristic_results = [_scanner.score_span(span) for span in spans]
    stage2_candidates: list[tuple[Span, HeuristicResult]] = []
    for span, h in zip(spans, heuristic_results):
        if h.score >= high_conf_threshold:
            findings.append(_heuristic_finding(span, h))
        elif h.authority_review:
            findings.append({'category':'prompt_injection_uncertain','severity':'medium',
                'confidence':0.55,'location':_location_str(span),
                'reason':'The supplied instruction claims precedence over existing guidance; its authority needs review.',
                'remediation':'Verify the source and instruction hierarchy before allowing an assistant to follow this text.',
                'details':{'stage':'authority_precedence_review','source_type':span.source_type,
                    'text_snippet':span.text[:200],
                    'evidence':'An instruction claims authority over earlier/system/developer guidance. Review authority before following it; this is not a confirmed exfiltration attack.'}})
        else:
            stage2_candidates.append((span, h))

    # Pass 2: Stage 2 (embedding similarity), batched.
    escalation_candidates: list[tuple[Span, HeuristicResult, float, float]] = []
    weak_candidates: list[tuple[Span, HeuristicResult, float, float]] = []
    if stage2_candidates:
        texts = [span.text for span, _ in stage2_candidates]
        similarities = batch_similarity_to_anchors(texts)
        from app.semantic_classifier import batch_probabilities,threshold
        probabilities=batch_probabilities(texts);review_threshold=threshold()
        scored = []
        for (span, h), similarity, probability in zip(stage2_candidates, similarities,probabilities):
            combined = combine_confidence(h.score, similarity, fusion_weights)
            if probability>=review_threshold:
                h.reasons.append(f"__guardian_classifier_candidate__ probability={probability:.4f}")
                combined=max(combined,(band["low"]+band["high"])/2)
            scored.append((span, h, similarity, combined))
        for span, h, similarity, combined in scored:
            if combined >= band["high"]:
                findings.append(_embedding_finding(span, h, similarity, combined))
            elif combined >= band["low"]:
                escalation_candidates.append((span, h, similarity, combined))
        weak_candidates = collect_weak_candidates(scored, band["low"], weak_floor)

    # Pass 3 split: Stage 3 (LLM judge) is capped, highest-confidence first.
    # Spans over the budget are decided right here, without an LLM call.
    escalation_candidates.sort(key=lambda item: item[3], reverse=True)
    to_judge = escalation_candidates[:max_llm_calls]
    overflow = escalation_candidates[max_llm_calls:]
    escalation_count = len(to_judge)

    plan = _Stage3Plan(
        base_findings=findings,
        to_judge=to_judge,
        overflow_findings=[
            _capped_finding(span, h, similarity, combined)
            for span, h, similarity, combined in overflow
        ],
        spans_scanned=len(spans),
        escalation_count=escalation_count,
    )

    # Pass 4: cross-span correlation over spans that were individually too
    # weak to escalate alone but may form a real instruction in combination.
    if len(weak_candidates) >= 2:
        combined_span = build_combined_span(weak_candidates)
        h_combined = _scanner.score_span(combined_span)
        similarity_combined = batch_similarity_to_anchors([combined_span.text])[0]
        combined_confidence = combine_confidence(h_combined.score, similarity_combined, fusion_weights)
        contributing = contributing_locations(weak_candidates)

        if combined_confidence >= band["high"]:
            plan.cross_span_finding = _embedding_finding(
                combined_span, h_combined, similarity_combined, combined_confidence,
                stage="cross_span_correlation",
            )
        elif combined_confidence >= band["low"]:
            remaining_budget = max_llm_calls - escalation_count
            if remaining_budget > 0:
                plan.cross_span_judge = (combined_span, h_combined, similarity_combined, contributing)
            else:
                plan.cross_span_finding = _capped_finding(
                    combined_span, h_combined, similarity_combined, combined_confidence,
                    stage="cross_span_capped",
                )
    return plan


async def _run_stage3(plan: _Stage3Plan) -> None:
    """The LLM-judge calls, exactly as the old analyze() made them: the
    per-span judges concurrently via asyncio.gather, then the cross-span
    judge. Fills plan.judge_findings / plan.cross_span_llm_finding."""
    judge_cfg = _config.get("llm_judge", {})

    if plan.to_judge:
        judge_tasks = [
            _llm_judge_finding(span, h, similarity, judge_cfg, failures=plan.judge_failures)
            for span, h, similarity, combined in plan.to_judge
        ]
        judge_results = await asyncio.gather(*judge_tasks)
        plan.judge_findings = [f for f in judge_results if f is not None]

    if plan.cross_span_judge is not None:
        combined_span, h_combined, similarity_combined, contributing = plan.cross_span_judge
        finding = await _llm_judge_finding(
            combined_span, h_combined, similarity_combined, judge_cfg,
            stage="cross_span_llm_judge",
            failures=plan.judge_failures,
        )
        if finding is not None:
            # contributing_locations is only ever populated for
            # cross_span_llm_judge findings, per spec.
            finding["details"]["contributing_locations"] = contributing
            plan.cross_span_llm_finding = finding


def _build_result(
    plan: _Stage3Plan,
    findings: list[dict],
    start: float,
    status: Optional[str] = None,
    callback_id: Optional[str] = None,
    extra_evidence: Optional[dict] = None,
) -> AgentResult:
    overall_confidence = max((f["confidence"] for f in findings), default=0.0)
    evidence = {
        "spans_scanned": plan.spans_scanned,
        "findings_count": len(findings),
        "elapsed_ms": round((time.perf_counter() - start) * 1000, 2),
        "escalated_to_llm": plan.escalation_count,
    }
    if extra_evidence:
        evidence.update(extra_evidence)
    if status is None:
        status = _status_for(overall_confidence)
        if plan.judge_failures:
            # Spans that reached Stage 3 are exactly the suspicious ones.
            # If the judge could not decide one, the artifact is "unknown",
            # not clean: report "error" so trust_engine floors at Review.
            # Only a confirmed "fail" from other findings stands, since it
            # is already at least as cautious.
            evidence["judge_failures"] = plan.judge_failures
            reasons = sorted({f["reason"] for f in plan.judge_failures})
            evidence["error"] = (
                f"Stage 3 LLM judge could not judge {len(plan.judge_failures)} escalated "
                f"span(s) ({', '.join(f['location'] for f in plan.judge_failures)}): "
                + "; ".join(reasons)
            )
            if status != "fail":
                status = "error"
    from app.embeddings import _model_load_failed
    if _model_load_failed: evidence["embedding_mode"] = "degraded_bag_of_words"
    return AgentResult(
        agent_name=AGENT_NAME,
        decision_floor="review" if any(f.get("category")=="prompt_injection_uncertain" for f in findings) else "accept",
        status=status,
        findings=redact(findings),
        coverage="partial" if _model_load_failed or plan.judge_failures or plan.overflow_findings else "full",
        unresolved=bool(_model_load_failed or plan.judge_failures or plan.overflow_findings or (plan.cross_span_finding and plan.cross_span_finding.get("details",{}).get("stage") == "cross_span_capped")),
        evidence=redact(evidence),
        callback_id=callback_id,
    )


async def _post_callback(url: str, result: AgentResult, token: str) -> bool:
    """POST the resolved result to trust_engine. Never raises.

    Sends the shared secret as X-Callback-Token (never logged).
    Returns True only on a 2xx; redirects are not confirmed delivery. Retry policy by outcome:

    - 404: trust_engine has not stored the scan yet (see
      CALLBACK_NOT_FOUND_RETRY_DELAYS_SECONDS) -- retried on that
      schedule; when it runs out, one warning and give up.
    - any other 4xx (401/403 auth refused, 422 bad body, ...): not
      retried -- the same body with the same token cannot start working.
    - transport error, timeout, 5xx: one retry after
      CALLBACK_RETRY_DELAY_SECONDS.

    The two retry budgets are independent: a 404 never uses up the single
    transient retry, and vice versa.
    """
    payload = result.model_dump(mode="json")
    not_found_delays = list(CALLBACK_NOT_FOUND_RETRY_DELAYS_SECONDS)
    transient_retries_left = CALLBACK_MAX_ATTEMPTS - 1
    attempt = 0
    waited_for_scan = 0.0
    while True:
        attempt += 1
        try:
            async with httpx.AsyncClient(timeout=CALLBACK_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    url, json=payload, headers={CALLBACK_TOKEN_HEADER: token},
                )
        except Exception as exc:  # noqa: BLE001 -- must never escape a background task
            outcome, reason = "transient", f"{type(exc).__name__}: {exc}"
        else:
            status = response.status_code
            if 200 <= status < 300:
                if attempt > 1:
                    logger.warning(
                        "callback %s delivered on attempt %d (HTTP %s) after waiting %.1fs "
                        "for trust_engine to store the scan",
                        result.callback_id, attempt, status, waited_for_scan,
                    )
                return True
            if 300 <= status < 400:
                logger.warning("callback redirect refused; delivery not acknowledged")
                return False
            if status == 404:
                outcome, reason = "not_found", "HTTP 404"
            elif status < 500:
                logger.warning(
                    "callback %s to %s rejected with HTTP %s (%s); not retrying",
                    result.callback_id, url, status, response.text[:200],
                )
                return False
            else:
                outcome, reason = "transient", f"HTTP {status}"

        if outcome == "not_found":
            if not not_found_delays:
                logger.warning(
                    "callback %s to %s: HTTP 404 on all %d attempts over %.1fs; the scan never "
                    "appeared in trust_engine; it will stay provisional until TTL. Giving up.",
                    result.callback_id, url, attempt, waited_for_scan,
                )
                return False
            delay = not_found_delays.pop(0)
            logger.warning(
                "callback %s to %s: HTTP 404 on attempt %d (trust_engine has not stored the "
                "scan yet?); retrying in %ss",
                result.callback_id, url, attempt, delay,
            )
            waited_for_scan += delay
        else:
            if transient_retries_left <= 0:
                logger.warning(
                    "callback %s to %s failed again (%s); giving up after %d attempts",
                    result.callback_id, url, reason, attempt,
                )
                return False
            transient_retries_left -= 1
            delay = CALLBACK_RETRY_DELAY_SECONDS
            logger.warning(
                "callback %s to %s failed (%s); retrying once in %ss",
                result.callback_id, url, reason, delay,
            )
        await _sleep(delay)


async def _resolve_and_callback(
    plan: _Stage3Plan, callback_id: str, url: str, token: str, start: float
) -> None:
    """Background body: finish Stage 3, then deliver. Never raises.

    If Stage 3 itself blows up (judge_span already swallows LLM call
    failures, so this means a bug), a status="error" result is delivered
    instead of nothing, so trust_engine resolves the record as
    "did not complete" (floors at Review) rather than staying provisional
    until its TTL.
    """
    try:
        await _run_stage3(plan)
        result = _build_result(
            plan, plan.all_findings(), start,
            callback_id=callback_id, extra_evidence={"stage3": "resolved_async"},
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Stage 3 background resolution for %s failed", callback_id)
        result = AgentResult(
            agent_name=AGENT_NAME,
            status="error",
            findings=[],
            evidence={"error": f"Stage 3 background resolution failed: {type(exc).__name__}: {exc}"},
            callback_id=callback_id,
        )
    from app.outbox import get_outbox
    box=get_outbox()
    await asyncio.to_thread(box.result,callback_id,url,result.model_dump(mode="json"))
    if await _post_callback(url, result, token):
        await asyncio.to_thread(box.acknowledge,callback_id)
    else:
        await asyncio.to_thread(box.retry,callback_id)


_judge_slots = asyncio.Semaphore(max(1,min(2,int(os.getenv("PROMPT_JUDGE_WORKERS","1")))))
async def _deliver_job(callback_id=None,plan=None,start=None):
    from app.outbox import get_outbox
    box=get_outbox()
    async with _judge_slots:
        claimed=await asyncio.to_thread(box.claim,callback_id)
        if not claimed: return
        id,payload=claimed
        try:
            token=_callback_token()
            if not token:
                await asyncio.to_thread(box.retry,id)
                return
            if payload["phase"]=="result":
                if await _post_callback(payload["url"],AgentResult(**payload["result"]),token):
                    await asyncio.to_thread(box.acknowledge,id)
                else: await asyncio.to_thread(box.retry,id)
            else:
                if plan is None:
                    from app.runtime import bounded_work
                    plan=await bounded_work(_plan,ArtifactRequest(**payload["artifact"]))
                await asyncio.wait_for(_resolve_and_callback(plan,id,payload["url"],token,start or time.perf_counter()),150)
        except Exception:
            logger.warning("durable callback job deferred",exc_info=False)
            await asyncio.to_thread(box.retry,id)

async def _outbox_worker():
    # One worker per process, bounded by two judge slots including immediate jobs.
    while True:
        try: await _deliver_job()
        except asyncio.CancelledError: raise
        except Exception: logger.warning("callback journal unavailable",exc_info=False)
        await asyncio.sleep(1)

@app.on_event("shutdown")
async def _shutdown():
    for task in list(_background_tasks): task.cancel()
    await asyncio.gather(*list(_background_tasks),return_exceptions=True)


def _spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


@app.post("/analyze", response_model=AgentResult)
async def analyze(artifact: ArtifactRequest) -> AgentResult:
    from app.capabilities import supports
    kind = artifact.type or artifact.artifact_type
    if kind and not supports(AGENT_NAME, kind):
        return AgentResult(agent_name=AGENT_NAME,status="stub",coverage="none")
    start = time.perf_counter()
    from app.runtime import bounded_work
    try: plan = await bounded_work(_plan, artifact)
    except (ClassifierUnavailable,WorkLimitExceeded) as exc:
        return AgentResult(agent_name=AGENT_NAME,status="error",coverage="none",evidence={"error":str(exc)})

    if not plan.needs_llm:
        # Common case: nothing escalated to Stage 3. Synchronous, unchanged.
        return _build_result(plan, plan.all_findings(), start)

    callback_id = uuid4().hex
    url = _callback_url(callback_id)
    token = _callback_token()
    if url is None or token is None:
        # Callback not configured (e.g. this service run standalone with
        # uvicorn, outside Compose): no target URL, or no shared secret --
        # in which case trust_engine would 401 the callback. Either way,
        # going pending would leave the caller provisional forever, so fall
        # back to the original synchronous behaviour and say so in the
        # logs. Only the variable *names* are logged, never the token.
        missing = [
            name for name, value in ((CALLBACK_URL_ENV_VAR, url), (CALLBACK_TOKEN_ENV_VAR, token))
            if value is None
        ]
        logger.warning(
            "%s not set; running Stage 3 synchronously instead of returning pending",
            " and ".join(missing),
        )
        await _run_stage3(plan)
        return _build_result(plan, plan.all_findings(), start)

    pending = _build_result(
        plan, plan.sync_findings(), start,
        status="pending", callback_id=callback_id,
        extra_evidence={"stage3": "pending"},
    )
    from app.outbox import get_outbox
    try:
        await asyncio.to_thread(get_outbox().enqueue,callback_id,
            {"phase":"job","url":url,"artifact":artifact.model_dump(mode="json")})
    except Exception:
        return AgentResult(agent_name=AGENT_NAME,status="error",evidence={"error":"durable callback journal unavailable or full"})
    _spawn(_deliver_job(callback_id,plan,start))
    return pending


from app.runtime import BoundsMiddleware
app.add_middleware(BoundsMiddleware)
