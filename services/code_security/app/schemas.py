"""Code findings extend the shared version 1 portable contract."""
from app.contract import Finding as ContractFinding
from typing import Literal, Optional
from pydantic import BaseModel, Field
from enum import Enum


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"
    info = "info"


class Finding(ContractFinding):
    category: str = Field(..., description="e.g. 'sql_injection', 'insecure_tls', 'command_injection'")
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    location: Optional[str] = Field(
        default=None, description="e.g. 'app.py:12'"
    )
    details: dict = Field(
        default_factory=dict,
        description=(
            "Agent-specific detail, mapped to trust_engine's shared "
            "Finding.details field. For code_security this holds "
            "message, remediation, rule_id, cwe, end_line."
        ),
    )


from app.contract import AgentResult as ContractAgentResult, ArtifactRequest
AnalyzeRequest = ArtifactRequest
class AgentResult(ContractAgentResult):
    agent_name: Literal["code_security"] = "code_security"
    findings: list[Finding] = Field(default_factory=list)
