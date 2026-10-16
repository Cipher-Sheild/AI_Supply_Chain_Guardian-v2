import time
from app.engines.result import EngineResult
import re
import json
import subprocess
from typing import List, Optional
from app.schema import Finding
from app.cache import cache_instance

SAFE_IMAGE_REF_PATTERN = re.compile(r'^[a-zA-Z0-9_][a-zA-Z0-9_\-./:@]*$')

TRIVY_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low"
}


class TrivyImageEngine:
    """
    Wrapper for Trivy container image CVE scanning.
    Features time-boxed execution, argument injection protection, and Redis/In-memory caching.
    """

    def __init__(self, binary_path: str = "trivy", timeout_sec: float = 7.0):
        self.binary_path = binary_path
        self.timeout_sec = timeout_sec

    def scan_image(self, image_ref: str, line_number: int = 1, file_path: str = "Dockerfile") -> EngineResult:
        started = time.perf_counter()
        if not image_ref or image_ref == "scratch":
            return EngineResult(True)

        # Sanitize against argument injection (e.g. image_ref starting with '--')
        if image_ref.startswith("-") or not SAFE_IMAGE_REF_PATTERN.match(image_ref):
            return EngineResult(False, "invalid image reference")

        cache_key = f"trivy_image_cve:{image_ref}"
        cached_raw = cache_instance.get(cache_key)
        if cached_raw is not None:
            cached = EngineResult.cached_findings(cached_raw)
            for finding in cached.findings:
                finding.file_path = file_path
                finding.line_number = line_number
            return cached

        findings: List[Finding] = []

        try:
            cmd = [
                self.binary_path, "image",
                "--format", "json",
                "--severity", "HIGH,CRITICAL",
                "--timeout", f"{int(self.timeout_sec)}s",
                # FIX: without this, trivy tries to reach the remote vuln-DB
                # registry (mirror.gcr.io) to check for updates on every call.
                # A DNS/network hiccup there stalls for several seconds before
                # falling back — same root cause found in trivy_config.py's
                # missing --skip-check-update, just the DB variant of the flag.
                "--skip-db-update",
                image_ref
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout_sec
            )

            stdout = proc.stdout.decode("utf-8", errors="replace").strip()

            if proc.returncode != 0:
                raise RuntimeError(f"trivy image exit {proc.returncode}")
            if stdout and stdout.startswith("{"):
                data = json.loads(stdout)
                if not isinstance(data, dict) or not isinstance(data.get("SchemaVersion"), int):
                    raise ValueError("invalid Trivy completion document")
                results = data.get("Results", []) or []
                for res in results:
                    vulns = res.get("Vulnerabilities", []) or []
                    for v in vulns:
                        cve_id = v.get("VulnerabilityID", "CVE-UNKNOWN")
                        pkg_name = v.get("PkgName", "package")
                        installed_ver = v.get("InstalledVersion", "unknown")
                        fixed_ver = v.get("FixedVersion", "N/A")
                        sev_raw = v.get("Severity", "HIGH").upper()
                        severity = TRIVY_SEVERITY_MAP.get(sev_raw, "high")
                        title = v.get("Title", f"Vulnerability in {pkg_name}")

                        findings.append(
                            Finding(
                                detector_id=f"trivy_cve:{cve_id}",
                                file_path=file_path,
                                line_number=line_number,
                                preview=f"{cve_id} in {pkg_name}:{installed_ver}",
                                confidence=1.0,
                                severity=severity,
                                reason=f"Base image CVE [{cve_id}] in {pkg_name} ({installed_ver}): {title}",
                                remediation=f"Upgrade base image or package {pkg_name} to version {fixed_ver}.",
                                sources=[f"trivy:{cve_id}"],
                                category="cve_vulnerability"
                            )
                        )

                # Scan genuinely completed (even with zero findings) — safe to cache normally.
                cache_instance.set(cache_key, [f.model_dump() for f in findings], ttl=86400)

            else:
                # Trivy ran but produced no parseable JSON — treat this as a
                # failed scan, not as "clean". Falls through to the except
                # block's fail-closed handling below.
                raise RuntimeError(
                    f"trivy image produced no parseable output (returncode={proc.returncode}, "
                    f"stderr={proc.stderr.decode('utf-8', errors='replace')[:500]!r})"
                )

        except Exception as exc:
            return EngineResult(False, type(exc).__name__, (time.perf_counter()-started)*1000, findings)
        return EngineResult(True, duration_ms=(time.perf_counter()-started)*1000, findings=findings)
