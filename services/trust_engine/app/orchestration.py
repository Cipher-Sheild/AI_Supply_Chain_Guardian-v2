"""
Trust Engine orchestration.

Each "agent" is a remote HTTP service reachable by its Docker Compose
service name, not an in-process function call. The graph is:

    route -> call_agents -> fuse -> END

- route:        app.routing.route_files() decides, per file, which agents
                should run (and the coverage that implies).
- call_agents:  only the routed agents are called, concurrently, via
                httpx.AsyncClient + asyncio.gather. One AgentCallRecord is
                produced per (file, agent) pair that was actually routed.
                An agent the router did not select gets no record at all
                (see AgentCallRecord's docstring in app.state).
- fuse:         app.fusion.fuse() turns routing + records into the
                existing TrustScoreResult contract.

State is the shared app.state.GraphState -- not redefined here -- so the
orchestrator and fusion cannot drift apart.

LangGraph node return values are *partial updates*, not whole states.
That matters for `results`, which carries an operator.add reducer:
returning the full state from a node would re-append every existing
record and duplicate them. Each node therefore returns only the keys it
owns.
"""

import asyncio
from pathlib import Path
import os
import time
from typing import Optional
from uuid import uuid4

import httpx
from langgraph.graph import StateGraph, END
from pydantic import ValidationError

from app.fusion import fuse
from app.routing import route_files
from app.capabilities import MATRIX
from app.schemas import AgentResult
from app.state import AgentCallRecord, GraphState, PendingCallback

# Each detector's URL is read from its own env var (see docker-compose.yml
# and .env.example), never hardcoded, so this works both inside Compose
# (service-name hostnames) and when pointed at services running elsewhere.
DETECTOR_URL_ENV_VARS = {
    "cipherguard": "CIPHERGUARD_URL",
    "code_security": "CODE_SECURITY_URL",
    "secret_detection": "SECRET_DETECTION_URL",
    "docker_security": "DOCKER_SECURITY_URL",
    "workflow_cicd": "WORKFLOW_CICD_URL",
    "license_compliance": "LICENSE_COMPLIANCE_URL",
    "prompt_injection": "PROMPT_INJECTION_URL",
}

# TODO: tune — how long to wait for a single detector service before
# treating it as failed/unreachable.
DETECTOR_TIMEOUT_SECONDS = 8.0
SCAN_DEADLINE_SECONDS = min(9.0, float(os.getenv("SCAN_DEADLINE_SECONDS", "9")))
_GLOBAL_CALLS = asyncio.Semaphore(int(os.getenv("GLOBAL_AGENT_WORKERS", "12")))

# Guardrails from the Router/Orchestrator/Fusion interface agreement.
#
# Without a cap, N files x M agents fans out as one burst: a 50-file
# request routed to three agents each is 150 simultaneous POSTs. A
# concurrency test against code_security measured latency rising from
# roughly 5s at low concurrency to 13s at 50 concurrent, because Semgrep
# spawns a subprocess per request. The semaphore bounds in-flight calls
# so a large request degrades gracefully instead of saturating the
# detector containers.
#
# Both are deliberately conservative starting points, not tuned values.
MAX_FILES_PER_REQUEST = 50
MAX_CONCURRENT_AGENT_CALLS = 12


class DetectorCallError(Exception):
    """A detector call that did not complete. `reason` is short and
    human-readable; it becomes AgentCallRecord.error_reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


async def _post_detector(
    client: httpx.AsyncClient, agent_name: str, url: str, artifact: dict
) -> AgentResult:
    """POST one artifact to one detector and parse the response.

    Raises DetectorCallError on timeout, transport failure, non-2xx, or a
    response that fails trust_engine's own AgentResult validation. The
    caller decides how to record that -- this function never guesses.
    """
    try:
        response = await client.post(url, json=artifact, timeout=min(DETECTOR_TIMEOUT_SECONDS, float(os.getenv(agent_name.upper() + "_TIMEOUT_SECONDS", "8"))))
        response.raise_for_status()
    except httpx.TimeoutException:
        raise DetectorCallError(f"timeout after {DETECTOR_TIMEOUT_SECONDS}s")
    except httpx.HTTPStatusError as exc:
        raise DetectorCallError(f"HTTP {exc.response.status_code} from {agent_name}")
    except httpx.HTTPError as exc:
        raise DetectorCallError(f"transport error: {type(exc).__name__}: {exc}")

    try:
        result = AgentResult(**response.json())
        if result.agent_name != agent_name:
            raise ValueError(f"agent identity mismatch: expected {agent_name}, got {result.agent_name}")
        return result
    except (ValueError, ValidationError, TypeError) as exc:
        # ValidationError is a ValueError subclass; listed for readability.
        first_line = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
        raise DetectorCallError(f"invalid response from {agent_name}: {first_line}")


async def _request_detector(
    client: httpx.AsyncClient, agent_name: str, url: str, artifact: dict
) -> AgentResult:
    """Dispatch seam used by the routed path (and patched by tests).
    Raises DetectorCallError on any failure; see _post_detector."""
    return await _post_detector(client, agent_name, url, artifact)


async def _call_detector(
    client: httpx.AsyncClient, agent_name: str, url: str, artifact: dict
) -> AgentResult:
    """Never-raising single-call helper: returns an AgentResult with
    status="error" (never "fail") when the call does not complete.

    "fail" means the scanner ran and found critical issues; "error" means
    the scanner itself did not complete. The routed dispatch path below
    uses _request_detector directly so it can record `result=None` plus an
    `error_reason` instead of a synthesized result; this wrapper is kept
    for callers that only want an AgentResult (and is pinned by
    test_transport_failure_reports_error_not_fail).
    """
    try:
        return await _post_detector(client, agent_name, url, artifact)
    except DetectorCallError as exc:
        return AgentResult(
            agent_name=agent_name,
            status="error",
            findings=[],
            evidence={"error": exc.reason},
        )


# --- Nodes ----------------------------------------------------------------


async def _route(state: GraphState) -> GraphState:
    """Decide which agents run for each file.

    Files beyond MAX_FILES_PER_REQUEST are dropped here rather than in
    dispatch, so the rest of the graph never sees a file it will not
    report on. The drop is recorded in routing_notes: a silently
    truncated request would let fusion score a partial scan as though it
    were complete.

    request_id: main.py does not supply one, so it is generated here when
    absent. A caller that already has one (a future multi-file endpoint,
    a callback resumption) can pass it in and it is kept.
    """
    files = state.get("files", [])
    notes = list(state.get("routing_notes", []))

    if len(files) > MAX_FILES_PER_REQUEST:
        notes.append(
            f"request contained {len(files)} files; only the first "
            f"{MAX_FILES_PER_REQUEST} were routed (cap: "
            f"MAX_FILES_PER_REQUEST). Coverage is incomplete for this request."
        )
        files = files[:MAX_FILES_PER_REQUEST]

    update: GraphState = {
        "files": files,
        "routing": route_files(files),
        "routing_notes": notes,
    }
    if not state.get("request_id"):
        update["request_id"] = uuid4().hex
    return update


async def _call_one(
    client: httpx.AsyncClient, file_dict: dict, filename: Optional[str], agent: str
) -> AgentCallRecord:
    """Call one routed agent for one file and build its record. Never raises."""
    env_var = DETECTOR_URL_ENV_VARS.get(agent)
    url = os.environ.get(env_var) if env_var else None
    if not url:
        # The router expected this agent but there is nowhere to send it.
        # That is an attempted-and-unknown outcome, not a skip: it must
        # floor the decision at Review rather than quietly vanish.
        return AgentCallRecord(
            file=filename, agent=agent, expected=True, agent_ran=True,
            status="error", result=None, elapsed_ms=0,
            error_reason=f"no URL configured ({env_var or 'unknown agent'} unset)",
        )

    started = time.perf_counter()
    try:
        result = await _request_detector(client, agent, url, file_dict)
    except DetectorCallError as exc:
        return AgentCallRecord(
            file=filename, agent=agent, expected=True, agent_ran=True,
            status="error", result=None,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            error_reason=exc.reason,
        )
    except Exception as exc:  # noqa: BLE001 — one broken detector must not take down the request
        return AgentCallRecord(
            file=filename, agent=agent, expected=True, agent_ran=True,
            status="error", result=None,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            error_reason=f"unexpected error: {type(exc).__name__}: {exc}",
        )

    # A detector that answered but reported status="error" (it ran and
    # could not complete, e.g. prompt_injection's LLM judge failed) usually
    # says why in evidence["error"]; carry that into error_reason so the
    # fused explanation names the cause instead of "agent reported error".
    error_reason = None
    if result.status == "error":
        reported = (result.evidence or {}).get("error")
        error_reason = str(reported) if reported else None
    return AgentCallRecord(
        file=filename, agent=agent, expected=True, agent_ran=True,
        status=result.status, result=result,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
        error_reason=error_reason,
        callback_id=result.callback_id,
    )


def canonical_request(file_dict: dict, decision) -> dict:
    payload = dict(file_dict)
    payload["type"] = decision.artifact_type
    payload["artifact_type"] = decision.artifact_type
    payload["file_path"] = decision.filename
    payload["filename"] = decision.filename
    if decision.artifact_type=='code':
        suffix=Path(decision.filename or '').suffix.lower()
        languages={'.py':'python','.js':'javascript','.jsx':'javascript','.mjs':'javascript','.cjs':'javascript','.ts':'typescript','.tsx':'typescript','.php':'php','.java':'java','.go':'go'}
        if suffix in languages:payload['language']=languages[suffix]
    elif decision.artifact_type=='markdown':payload['language']='markdown'
    if decision.artifact_type in {"dockerfile","compose"}:
        payload["options"]={"enable_cve_scan":True,**(payload.get("options") or {})}
    if decision.artifact_type == "dependency":
        content = payload.get("content", "").lstrip()
        path = (decision.filename or "").replace("\\", "/").lower()
        name=path.rsplit('/',1)[-1]
        is_node = name in {'package.json','package-lock.json','npm-shrinkwrap.json'} or (not path and (payload.get("ecosystem") in {"node","npm","javascript"} or payload.get("format") == "package.json" or content.startswith("{")))
        payload["format"] = name if name in MATRIX['dependency_filenames'] else "package.json" if is_node else "requirements"
        payload["ecosystem"] = 'rust' if name in {'cargo.toml','cargo.lock'} else 'go' if name in {'go.mod','go.sum'} else "node" if is_node else "python"
    elif decision.artifact_type == "workflow":
        payload["format"] = 'gitlab_ci' if (decision.filename or '').lower().endswith(('.gitlab-ci.yml','.gitlab-ci.yaml')) else "github_actions"
    return payload

async def _call_agents(state: GraphState) -> GraphState:
    """Call every routed (file, agent) pair, bounded by a semaphore.

    Files routed to zero agents (binary, oversized, unsupported lockfile) make no
    calls at all -- that is the router's design, not a gap to fill.

    files and routing are paired by index, so a length mismatch would
    silently drop files under zip(). It is treated as a bug and surfaced
    rather than tolerated: a dropped file is a file nobody scanned.
    """
    files = state.get("files", [])
    routing = state.get("routing", [])
    notes = list(state.get("routing_notes", []))

    if len(files) != len(routing):
        # Defensive: _route always produces one decision per file. If this
        # ever trips, something upstream rewrote one list and not the other.
        notes.append(
            f"internal error: {len(files)} files but {len(routing)} routing "
            f"decisions; only the first {min(len(files), len(routing))} pairs "
            "were dispatched"
        )

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_AGENT_CALLS)

    async def _guarded(file_dict: dict, filename: Optional[str], agent: str):
        # The semaphore bounds how many calls are in flight, not how many
        # are created. Every pair still gets a record; they just queue.
        async def admitted():
            async with _GLOBAL_CALLS, semaphore:
                return await _call_one(client, file_dict, filename, agent)
        started = time.perf_counter()
        try:
            return await asyncio.wait_for(admitted(), SCAN_DEADLINE_SECONDS)
        except TimeoutError:
            return AgentCallRecord(file=filename, agent=agent, expected=True,
                agent_ran=False, status="error", result=None,
                elapsed_ms=int((time.perf_counter()-started)*1000),
                error_reason="global scan deadline exhausted (including queue)")

    async with httpx.AsyncClient() as client:
        tasks = [
            _guarded(canonical_request(file_dict, decision), decision.filename, agent)
            for file_dict, decision in zip(files, routing)
            for agent in decision.expected_agents
        ]
        records: list[AgentCallRecord] = list(await asyncio.gather(*tasks))

    pending = [
        PendingCallback(file=r.file, agent=r.agent, callback_id=r.callback_id)
        for r in records
        if r.status == "pending" and r.callback_id
    ]

    # `results` has an operator.add reducer: returning the new records
    # appends them to whatever is already in state.
    return {
        "results": records,
        "pending_callbacks": list(state.get("pending_callbacks", [])) + pending,
        "routing_notes": notes,
    }

async def _fuse(state: GraphState) -> GraphState:
    from app.features import append_feature_event
    result = fuse(state).model_dump()
    append_feature_event({**state, "trust_result": result})
    return {"trust_result": result, "scoring": state.get("scoring", {})}


def build_graph():
    graph = StateGraph(GraphState)
    graph.add_node("route", _route)
    graph.add_node("call_agents", _call_agents)
    graph.add_node("fuse", _fuse)
    graph.set_entry_point("route")
    graph.add_edge("route", "call_agents")
    graph.add_edge("call_agents", "fuse")
    graph.add_edge("fuse", END)
    return graph.compile()


_compiled_graph = build_graph()


async def run_full_scan_state(artifact: dict) -> GraphState:
    """
    Entrypoint used by the FastAPI /analyze endpoint.

    The public API takes a single artifact; internally it is a list of one
    file, per the routing spec ("a single file is a list of one").

    Returns the whole final GraphState, not just trust_result: /analyze
    needs request_id (to hand back to the caller) and, when an agent went
    pending, files/routing/results/pending_callbacks/routing_notes to
    persist for resumption when the callback lands.
    """
    initial: GraphState = {
        "files": [artifact],
        "routing": [],
        "results": [],
        "pending_callbacks": [],
        "routing_notes": [],
        "trust_result": {},
    }
    return await _compiled_graph.ainvoke(initial)


async def run_full_scan(artifact: dict) -> dict:
    """Backward-compatible wrapper: just the fused trust_result dict, as
    before. Kept for any caller that only wants the score."""
    final_state = await run_full_scan_state(artifact)
    return final_state["trust_result"]
