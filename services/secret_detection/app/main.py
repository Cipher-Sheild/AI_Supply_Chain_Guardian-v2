"""
Secret Detection microservice — Layered detection engine.
"""

import time
from fastapi import FastAPI, HTTPException
from typing import Dict, Any, List

from app.schemas import AgentResult
from app.scorer import SecretScorer

AGENT_NAME = "secret_detection"

app = FastAPI(title=f"AI Supply Chain Guardian — {AGENT_NAME}")
scorer = SecretScorer()


@app.get("/health")
async def health():
    from app.readiness import readiness
    return await readiness(AGENT_NAME)



def _extract_files(artifact: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Normalize whichever artifact shape was sent into a list of
    {"path": ..., "content": ...} dicts.

    Supports:
      - {"files": [{"path": ..., "content": ...}, ...]}   (this service's own tests)
      - {"content": ..., "filename": ...}                  (what the orchestrator actually sends)
    """
    if "files" in artifact and isinstance(artifact["files"], list):
        return artifact["files"]

    if "content" in artifact:
        return [{
            "path": artifact.get("filename") or artifact.get("file_path") or "unknown",
            "content": artifact.get("content")
        }]

    return []


def derive_status(findings: List[Any]) -> str:
    if not findings:
        return "pass"
    for f in findings:
        if f.severity in ("high", "critical"):
            return "fail"
    return "warn"

@app.post("/analyze", response_model=AgentResult)
async def analyze(artifact: Dict[str, Any]) -> AgentResult:
    start_time = time.time()

    files = _extract_files(artifact)

    # FIX (fail-closed): an artifact we could not read at all is NOT the same
    # as a clean scan. The old code left `status` at its initialized "pass"
    # value in this case, which is indistinguishable from "scanned and found
    # nothing" — the most dangerous failure mode for a secret scanner.
    if not files:
        execution_time_ms = (time.time() - start_time) * 1000.0
        return AgentResult(
            agent_name=AGENT_NAME,
            status="error",
            findings=[],
            evidence={
                "reason": "No readable content in artifact payload — expected 'files' or 'content' key.",
                "severity": None,
                "confidence": 0.0,
                "total_findings": 0,
                "execution_time_ms": round(execution_time_ms, 3),
            },
        )

    if any(not isinstance(f, dict) or not isinstance(f.get("content"), str) for f in files):
        return AgentResult(agent_name=AGENT_NAME, status="error", coverage="none", evidence={"error":"Unreadable file content"})
    all_findings = []

    for f in files:
        file_path = f.get("path", "unknown")
        content = f.get("content", "")

        # Enforce basic timeout/size constraint in a real environment
        # e.g., if len(content) > 10_000_000: continue

        findings = scorer.score_findings(content, file_path)
        all_findings.extend(findings)

    execution_time_ms = (time.time() - start_time) * 1000.0

    # Determine overall status
    status = derive_status(all_findings)
    overall_severity = None
    max_confidence = 0.0

    if all_findings:
        max_confidence = max(f.confidence for f in all_findings)

        sev_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_sev = max(all_findings, key=lambda f: sev_levels.get(f.severity, 0)).severity
        overall_severity = max_sev

    return AgentResult(
        agent_name=AGENT_NAME,
        status=status,
        findings=all_findings,
        evidence={
            "severity": overall_severity,
            "confidence": max_confidence,
            "total_findings": len(all_findings),
            "execution_time_ms": round(execution_time_ms, 3),
        },
    )

from app.runtime import BoundsMiddleware
app.add_middleware(BoundsMiddleware)
