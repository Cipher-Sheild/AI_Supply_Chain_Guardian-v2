"""
FastAPI entrypoint for the workflow_cicd detector service.

Stateless — never touches Postgres. Called by trust_engine's
orchestration.py over HTTP at WORKFLOW_CICD_URL. Response body must match
AgentResult exactly (see app/schemas.py header comment).
"""

import logging
import re

import yaml
from fastapi import FastAPI

from app.schemas import AgentResult, AnalyzeRequest
from app.scanner import analyze_workflow, compute_risk_score, load_workflow

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("workflow_cicd")

AGENT_NAME = "workflow_cicd"

app = FastAPI(title="workflow_cicd", version="0.1.0")

# Filenames this agent is actually responsible for.
from app.capabilities import MATRIX, supports, unsupported_path
_WORKFLOW_SUFFIXES = tuple(MATRIX["workflow_suffixes"])


def _looks_like_workflow(parsed: dict) -> bool:
    """
    A GitHub Actions workflow always has `jobs:` and a trigger (`on:`,
    which PyYAML normalizes to the boolean True — see load_workflow).
    """
    return "jobs" in parsed and ("on" in parsed or True in parsed)


@app.get("/health")
async def health():
    from app.readiness import readiness
    return await readiness(AGENT_NAME)



@app.post("/analyze", response_model=AgentResult)
def analyze(request: AnalyzeRequest) -> AgentResult:
    """
    The orchestrator routes supported workflows here. These guards also
    protect direct calls from unsupported or malformed artifacts.

    "Not a workflow" is not a security verdict. It maps to status="stub"
    (the vocabulary's own not-applicable value), never "fail" — reporting
    failure on every non-YAML artifact would poison the fused Trust Score.
    """
    not_applicable = AgentResult(
        agent_name=AGENT_NAME,
        status="stub",
        findings=[],
        evidence={"reason": "artifact is not a GitHub Actions workflow"},
    )

    filename=request.filename or request.file_path or ''
    if filename.replace('\\','/').rsplit('/',1)[-1].lower() in {'.gitlab-ci.yml','.gitlab-ci.yaml'}:
        try:
            from app.gitlab import analyze_gitlab
            return analyze_gitlab(request.content,filename)
        except (ValueError,TypeError,yaml.YAMLError,RecursionError):
            return AgentResult(agent_name=AGENT_NAME,status='error',coverage='none',unresolved=True,
                               evidence={'error':'Malformed or unresolved GitLab configuration'})
    if unsupported_path(request.filename or request.file_path):
        return AgentResult(agent_name=AGENT_NAME,status="stub",coverage="partial",unresolved=True)
    kind = request.type or request.artifact_type
    if kind and not supports(AGENT_NAME, kind): return not_applicable
    if request.filename and not request.filename.lower().endswith(_WORKFLOW_SUFFIXES):
        return not_applicable

    try:
        parsed = load_workflow(request.content)
    except (yaml.YAMLError, ValueError) as exc:
        # Unparseable and not YAML-shaped at all -> almost certainly not our
        # artifact type, so stub rather than fail.
        logger.info("Not a parseable workflow '%s': %s", request.filename, exc)
        return AgentResult(agent_name=AGENT_NAME, status="error", coverage="none", evidence={"error": f"Malformed workflow: {exc}"})

    if not _looks_like_workflow(parsed):
        if kind == "workflow" or ".github/workflows/" in (request.filename or "").replace("\\","/"):
            return AgentResult(agent_name=AGENT_NAME,status="error",coverage="none",evidence={"error":"Missing workflow structure"})
        return not_applicable

    if not isinstance(parsed.get("jobs"), dict):
        return AgentResult(agent_name=AGENT_NAME,status="error",coverage="none",evidence={"error":"Workflow jobs must be a mapping"})

    try:
        status, findings = analyze_workflow(request.content)
        for finding in findings:
            context = finding.location or ""
            match = re.search(r"line (\d+)", context)
            finding.details["source_context"] = context
            finding.location = f"{request.filename or request.file_path or 'workflow.yml'}:{match.group(1) if match else 0}"
            finding.reason = finding.reason or finding.details.get("reason") or finding.details.get("message") or finding.category
            finding.remediation = finding.remediation or "Pin actions to commit SHAs, limit permissions and avoid executing unverified remote scripts."
        return AgentResult(
            agent_name=AGENT_NAME,
            status=status,
            findings=findings,
            # AgentResult has no dedicated score field, so the doc-specified
            # numeric score travels in evidence, which exists for exactly this.
            decision_floor="reject" if any(f.severity == "critical" for f in findings) else "accept",
            evidence={"workflow_risk_score": compute_risk_score(findings)},
        )
    except Exception as exc:  # noqa: BLE001 — never let an unhandled error 500 out
        # A scanner crash is unknown, not a completed security verdict.
        logger.exception("Scanner crashed on '%s'", request.filename)
        return AgentResult(
            agent_name=AGENT_NAME,
            status="error",
            findings=[],
            evidence={"error": str(exc), "error_type": "scanner_error"},
        )

from app.runtime import BoundsMiddleware
app.add_middleware(BoundsMiddleware)
