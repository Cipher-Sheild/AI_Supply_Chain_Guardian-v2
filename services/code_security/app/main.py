"""
Code Security Agent.

Stateless scanner service. Receives source code, applies Guardian-owned
AST and syntax-tree rules by default, and returns findings in
the shared AgentResult shape. Never touches the database -- trust_engine
is the only caller and the only service that persists results.
"""

import logging
import os
from pathlib import Path

from fastapi import FastAPI

from app.capabilities import CODE_EXTENSIONS, supports
from app.schemas import AnalyzeRequest, AgentResult
from app.scanner import run_semgrep, determine_status, EXTENSION_LANGUAGE_MAP
_external_scan=run_semgrep
def run_semgrep(content,filename,timeout_seconds=None):
    if os.getenv('GUARDIAN_EXTERNAL_SCANNERS','false').lower()!='true':
        from app.native_ast import scan
        return scan(content,filename)
    return _external_scan(content,filename,timeout_seconds)

logger = logging.getLogger("code_security")

AGENT_NAME = "code_security"

app = FastAPI(
    title="Code Security Agent",
    description="Static analysis with Guardian's native source rule engines.",
    version="0.1.0",
)


_ready = False
_warm_task = None

@app.on_event("startup")
async def _warm_up_semgrep() -> None:
    import asyncio
    async def warm():
        global _ready
        try:
            # Cold setup has its own startup budget, outside request latency.
            samples=[('warmup.py','eval(input())\n'),('warmup.js','eval(input);'),
                ('warmup.ts','eval(input);'),('warmup.php','<?php eval($input);'),
                ('Warmup.java','class Warmup { void x(){ engine.eval(input); } }'),
                ('warmup.go','package main\nfunc x(user string){db.Query("SELECT " + user)}')]
            checks=[]
            for filename,content in samples:
                findings=await asyncio.to_thread(run_semgrep,content,filename,90)
                checks.append(bool(findings))
            _ready=all(checks)
        except Exception:
            logger.warning("Scanner self-test failed", exc_info=True)
    global _warm_task
    _warm_task = asyncio.create_task(warm())

@app.get("/health")
async def health():
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=200 if _ready else 503, content={
        "status": "ok" if _ready else "degraded", "agent": AGENT_NAME,
        "scanner_self_test_completed": _ready,
        "python_backend": "external" if os.getenv('GUARDIAN_EXTERNAL_SCANNERS','false').lower()=='true' else 'guardian_python_ast',
        "other_language_backend": "semgrep" if os.getenv('GUARDIAN_EXTERNAL_SCANNERS','false').lower()=='true' else 'guardian_syntax_tree',
    })


def _not_applicable(reason: str) -> AgentResult:
    """Explicit unusable result for unsupported inputs."""
    return AgentResult(
        agent_name=AGENT_NAME,
        status="stub",
        findings=[],
        evidence={"reason": reason},
    )


@app.post("/analyze", response_model=AgentResult)
async def analyze(req: AnalyzeRequest) -> AgentResult:
    kind = req.type or req.artifact_type
    if kind and not supports(AGENT_NAME, kind): return _not_applicable("unsupported artifact type")
    # Note: Path("Dockerfile").suffix is "" -- an empty string, which is
    # falsy. Guarding with `if suffix and suffix not in ...` would let every
    # extensionless file (Dockerfile, Makefile, .env) through to Semgrep,
    # which then tries to parse it as Python. Test the membership directly.
    filename = req.filename or req.file_path or "artifact.py"
    if req.filename or req.file_path:
        suffix = Path(filename).suffix.lower()
        if suffix not in CODE_EXTENSIONS:
            return _not_applicable(f"unsupported artifact type '{req.filename}'")

    try:
        from app.runtime import bounded_work
        findings = await bounded_work(run_semgrep, req.content, filename)
        global _ready
    except Exception as e:
        # Semgrep itself failed to run (crash, bad rules, timeout, etc.)
        # -- a genuine agent failure, distinct from "ran fine and found
        # high-severity issues". This path used to return "fail" because
        # the shared status vocabulary had no way to express it; "error"
        # now exists for exactly this, and the fusion layer treats it as
        # unknown-and-floor-at-Review rather than as a real finding.
        logger.exception("Source analysis failed on '%s'", filename)
        return AgentResult(
            agent_name=AGENT_NAME,
            status="error",
            findings=[],
            evidence={"error": str(e), "error_type": "scanner_error"},
        )

    return AgentResult(
        agent_name=AGENT_NAME,
        status="warn" if getattr(findings,"partial",False) and not findings else determine_status(findings),
        coverage="partial" if getattr(findings,"partial",False) else "full",
        unresolved=bool(getattr(findings,"partial",False)),
        evidence={"engine":("guardian_python_ast" if Path(filename).suffix.lower()=='.py' else 'guardian_syntax_tree') if os.getenv('GUARDIAN_EXTERNAL_SCANNERS','false').lower()!='true' else "pinned Semgrep OSS", "partial_parsing":bool(getattr(findings,"partial",False))},
        findings=findings
    )

from app.runtime import BoundsMiddleware
app.add_middleware(BoundsMiddleware)
