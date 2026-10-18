"""Version 1 security boundary; copied by scripts/sync_contracts.py for standalone services."""
from typing import Literal, Optional
from pydantic import BaseModel, Field, ConfigDict, model_validator, field_validator, StrictBool

class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: str
    severity: Literal["low", "medium", "high", "critical", "info"]
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    location: Optional[str] = None
    reason: Optional[str] = None
    remediation: Optional[str] = None
    hard_block: StrictBool = False
    details: dict = Field(default_factory=dict)
    score: Optional[float] = Field(default=None, ge=0, le=100, allow_inf_nan=False)

class AgentResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    contract_version: Literal["1.0"] = "1.0"
    agent_name: str
    status: Literal["pass", "warn", "fail", "error", "stub", "pending"] = "stub"
    coverage: Literal["full", "partial", "none"] = "full"
    unresolved: StrictBool = False
    decision_floor: Literal["accept", "review", "reject"] = "accept"
    findings: list[Finding] = Field(default_factory=list)
    evidence: Optional[dict] = None
    callback_id: Optional[str] = None

    @model_validator(mode="after")
    def require_callback(self):
        if self.status == "pending" and not (self.callback_id and self.callback_id.strip()):
            raise ValueError("pending requires a nonempty callback_id")
        if self.status in {"error", "stub", "pending"} or (self.status == "fail" and not self.findings):
            self.unresolved = True
            if self.status in {"error", "stub"} and self.coverage == "full": self.coverage = "none"
            if self.status == "pending" and self.coverage == "full": self.coverage = "partial"
            if self.status == "fail" and not self.findings: self.coverage = "none"
            if self.decision_floor == "accept": self.decision_floor = "review"
        return self

class ArtifactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str
    type: Optional[str] = None
    artifact_type: Optional[str] = None
    format: Optional[str] = None
    ecosystem: Optional[str] = None
    language: Optional[str] = None
    filename: Optional[str] = None
    file_path: Optional[str] = None
    ai_tool_source: Optional[str] = None
    options: dict = Field(default_factory=dict)

    @field_validator("options")
    @classmethod
    def valid_scan_scope(cls, value):
        if "scan_scope" in value and (not isinstance(value["scan_scope"], str) or value["scan_scope"] not in {"supplied_text", "resolved_images"}):
            raise ValueError("scan_scope must be supplied_text or resolved_images")
        return value

    @field_validator("type", "artifact_type")
    @classmethod
    def supported_type(cls, value):
        from .capabilities import ARTIFACT_TYPES
        if value is None: return None
        value = value.strip().lower()
        if value == "auto": return None
        if value not in ARTIFACT_TYPES: raise ValueError("unsupported artifact type")
        return value

    @model_validator(mode="after")
    def consistent_hints(self):
        if self.type and self.artifact_type and self.type != self.artifact_type:
            raise ValueError("type and artifact_type disagree")
        return self
