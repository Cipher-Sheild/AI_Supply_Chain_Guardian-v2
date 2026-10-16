import time
from app.engines.result import EngineResult
import json
import subprocess
from typing import List, Dict, Any, Optional
from app.schema import Finding

HADOLINT_LEVEL_MAP = {
    "error": "high",
    "warning": "medium",
    "info": "low",
    "style": "low"
}

class HadolintEngine:
    """
    Wrapper for Hadolint (Dockerfile linter).
    Executes hadolint via stdin in json mode.
    """

    def __init__(self, binary_path: str = "hadolint", timeout_sec: float = 5.0):
        self.binary_path = binary_path
        self.timeout_sec = timeout_sec

    def analyze(self, content: str, file_path: str = "Dockerfile") -> EngineResult:
        started = time.perf_counter()
        findings: List[Finding] = []
        try:
            cmd = [self.binary_path, "--format", "json", "-"]
            proc = subprocess.run(
                cmd,
                input=content.encode("utf-8"),
                capture_output=True,
                timeout=self.timeout_sec
            )

            stdout = proc.stdout.decode("utf-8", errors="replace").strip()
            if proc.returncode not in (0, 1):
                raise RuntimeError(f"hadolint exit {proc.returncode}")
            if not stdout.startswith("["):
                raise ValueError("hadolint produced invalid JSON")
            if stdout.startswith("["):
                raw_items = json.loads(stdout)
                for item in raw_items:
                    rule_code = item.get("code", "HADOLINT")
                    level = item.get("level", "info").lower()
                    line = int(item.get("line", 1))
                    message = item.get("message", "Hadolint warning")

                    severity = HADOLINT_LEVEL_MAP.get(level, "low")

                    findings.append(
                        Finding(
                            detector_id=f"hadolint:{rule_code}",
                            file_path=file_path,
                            line_number=line,
                            preview=message,
                            confidence=1.0,
                            severity=severity,
                            reason=f"Hadolint [{rule_code}]: {message}",
                            remediation=f"Refer to Hadolint rule documentation for {rule_code}.",
                            sources=[f"hadolint:{rule_code}"],
                            category="docker_security"
                        )
                    )
        except Exception as exc:
            return EngineResult(False, type(exc).__name__, (time.perf_counter()-started)*1000, findings)
        return EngineResult(True, duration_ms=(time.perf_counter()-started)*1000, findings=findings)
