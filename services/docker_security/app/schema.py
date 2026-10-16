from app.contract import Finding as ContractFinding, AgentResult as ContractAgentResult
from pydantic import model_serializer, Field
from pydantic import BaseModel, Field
from typing import Optional, Literal, List, Dict, Any

class Finding(BaseModel):
    detector_id: str
    file_path: str = "Dockerfile"
    line_number: int = 1
    preview: str = ""
    confidence: float = Field(default=1.0, ge=0, le=1, allow_inf_nan=False)
    severity: Literal["low", "medium", "high", "critical"]
    reason: str
    remediation: str
    sources: List[str] = Field(default_factory=list)
    category: str = "docker_security"
    hard_block: bool = False
    risk_contribution: int = 0

    @model_serializer(mode="wrap")
    def portable(self, handler):
        raw = handler(self)
        portable = {k: raw[k] for k in ContractFinding.model_fields if k in raw}
        portable["location"] = raw.get("location") or f"{raw.get('file_path', 'unknown')}:{raw.get('line_number', 0)}"
        portable["details"] = dict(raw.get("details") or {})
        portable["details"].update({k: v for k, v in raw.items() if k not in ContractFinding.model_fields})
        return ContractFinding(**portable).model_dump()

class HardenedOutput(BaseModel):
    original: str
    hardened: str
    applied_rules: List[str]
    verification_passed: bool
    remaining_findings_count: int
    verification_kind: Literal["suggested", "build_verified"] = "suggested"
    lint_completed: bool = False
    lint_improved: bool = False

class AgentResult(ContractAgentResult):
    # Mirrors trust_engine's AgentResult exactly (agent_name, status, findings,
    # evidence). Agent-specific output -- risk_score, severity, confidence,
    # total_findings, execution_time_ms, hardened_artifact -- lives inside
    # `evidence`, because top-level fields trust_engine does not declare are
    # silently dropped by Pydantic before the Trust Engine ever sees them.
    agent_name: str = "docker_security"
    status: Literal["pass", "warn", "fail", "error", "stub", "pending"] = "pass"
    findings: List[Finding] = Field(default_factory=list)
    evidence: Optional[Dict[str, Any]] = None

class DockerArtifactInput(BaseModel):
    artifact_type: Literal["dockerfile", "compose", "auto"] = "auto"
    content: str
    file_path: Optional[str] = None
    options: Optional[Dict[str, Any]] = None
