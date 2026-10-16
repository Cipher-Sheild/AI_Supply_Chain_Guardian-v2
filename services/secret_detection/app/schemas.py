from app.contract import Finding as ContractFinding, AgentResult as ContractAgentResult
from pydantic import model_serializer, Field
from pydantic import BaseModel
from typing import Optional, Literal, List, Dict, Any

class Finding(BaseModel):
    detector_id: str
    file_path: str
    line_number: int
    preview: str
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    severity: Literal["low", "medium", "high", "critical"]
    reason: str
    remediation: str

    # FIX: trust_engine's own Finding model (services/trust_engine/app/schemas.py)
    # requires "category" as a mandatory field with no default. Without it,
    # AgentResult(**response.json()) on the trust_engine side raises a
    # ValidationError on every finding, and the ENTIRE result silently gets
    # replaced by the placeholder status="fail", empty-findings fallback --
    # even after the artifact-contract fix in main.py is applied. Docker
    # Security's Finding already carries this field for the same reason;
    # matching that convention here rather than inventing a new one.
    category: str
    location: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    @model_serializer(mode="wrap")
    def portable(self, handler):
        raw = handler(self)
        portable = {k: raw[k] for k in ContractFinding.model_fields if k in raw}
        portable["location"] = raw.get("location") or f"{raw.get('file_path', 'unknown')}:{raw.get('line_number', 0)}"
        portable["details"] = dict(raw.get("details") or {})
        portable["details"].update({k: v for k, v in raw.items() if k not in ContractFinding.model_fields})
        return ContractFinding(**portable).model_dump()

class AgentResult(ContractAgentResult):
    # Mirrors trust_engine's AgentResult (agent_name, status, findings,
    # evidence). severity / confidence / total_findings / execution_time_ms
    # live inside `evidence`: top-level fields trust_engine does not declare
    # are silently dropped by Pydantic before the Trust Engine sees them.
    agent_name: str
    status: Literal["pass", "warn", "fail", "error", "stub", "pending"] = "stub"
    findings: List[Finding] = []
    evidence: Optional[Dict[str, Any]] = None
