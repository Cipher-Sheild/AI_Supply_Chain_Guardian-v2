import time
from app.engines.result import EngineResult
import json
import os
import tempfile
import subprocess
from typing import List, Dict, Any, Optional
from app.schema import Finding

TRIVY_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low"
}

class TrivyConfigEngine:
    """
    Wrapper for Trivy misconfiguration analysis (Dockerfile & docker-compose).
    """

    def __init__(self, binary_path: str = "trivy", timeout_sec: float = 7.0):
        self.binary_path = binary_path
        self.timeout_sec = timeout_sec

    def analyze(self, content: str, file_path: str = "Dockerfile", is_compose: bool = False) -> EngineResult:
        started = time.perf_counter()
        findings: List[Finding] = []
        filename = "docker-compose.yml" if is_compose else "Dockerfile"

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                target_path = os.path.join(tmpdir, filename)
                with open(target_path, "w", encoding="utf-8") as f:
                    f.write(content)

                cmd = [self.binary_path, "config", "--format", "json", "--skip-check-update", target_path]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=self.timeout_sec
                )

                stdout = proc.stdout.decode("utf-8", errors="replace").strip()
                if proc.returncode != 0:
                    raise RuntimeError(f"trivy config exit {proc.returncode}")
                if not stdout.startswith("{"):
                    raise ValueError("trivy config produced invalid JSON")
                if stdout.startswith("{"):
                    data = json.loads(stdout)
                    if not isinstance(data, dict) or not isinstance(data.get("SchemaVersion"), int):
                        raise ValueError("invalid Trivy completion document")
                    results = data.get("Results", []) or []
                    for res in results:
                        misconfs = res.get("Misconfigurations", []) or []
                        for m in misconfs:
                            rule_id = m.get("ID", "TRIVY-CONFIG")
                            sev_raw = m.get("Severity", "MEDIUM").upper()
                            severity = TRIVY_SEVERITY_MAP.get(sev_raw, "medium")
                            title = m.get("Title", "Trivy Misconfiguration")
                            desc = m.get("Description", title)
                            resolution = m.get("Resolution", "Remediate according to security guidelines.")
                            cause_meta = m.get("CauseMetadata", {}) or {}
                            line_num = int(cause_meta.get("StartLine", 1) or 1)

                            findings.append(
                                Finding(
                                    detector_id=f"trivy:{rule_id}",
                                    file_path=file_path,
                                    line_number=line_num,
                                    preview=title,
                                    confidence=1.0,
                                    severity=severity,
                                    reason=f"Trivy [{rule_id}]: {desc}",
                                    remediation=f"Resolution: {resolution}",
                                    sources=[f"trivy:{rule_id}"],
                                    category="docker_security"
                                )
                            )
        except Exception as exc:
            return EngineResult(False, type(exc).__name__, (time.perf_counter()-started)*1000, findings)
        return EngineResult(True, duration_ms=(time.perf_counter()-started)*1000, findings=findings)
