from app.contract import Finding, AgentResult, ArtifactRequest
from pydantic import BaseModel, Field
from typing import Literal, Optional
class TrustScoreResult(BaseModel):
    trust_score: float = Field(default=0, ge=0, le=100, allow_inf_nan=False)
    recommendation: Literal["accept", "review", "reject"] = "accept"
    explanation: Optional[str] = None
    agent_breakdown: Optional[dict] = None
    detector_results: list[AgentResult] = Field(default_factory=list)
