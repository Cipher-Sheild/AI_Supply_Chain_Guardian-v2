"""Engine completion is separate from security findings: errors are never clean scans."""
from dataclasses import dataclass, field
from app.schema import Finding

@dataclass
class EngineResult:
    completed: bool
    error_reason: str | None = None
    duration_ms: float = 0
    findings: list[Finding] = field(default_factory=list)

    def evidence(self):
        return {"completed": self.completed, "error_reason": self.error_reason,
                "duration_ms": round(self.duration_ms, 2), "finding_count": len(self.findings)}

    @classmethod
    def cached_findings(cls, items):
        findings = []
        for item in items:
            portable = dict(item)
            details = portable.pop("details", {})
            portable.pop("location", None)
            portable.pop("score", None)
            findings.append(Finding(**{**details, **portable}))
        return cls(True, findings=findings)
