from typing import List, Tuple
from app.schema import Finding

SEVERITY_WEIGHTS = {
    "critical": 50,
    "high": 35,
    "medium": 20,
    "low": 10
}

class RiskScorer:
    """
    Computes a continuous 0-100 risk score for Docker & Compose artifacts.
    Enforces the invariant: without a hard-block finding, score can NEVER reach 90.
    """

    @staticmethod
    def calculate_score(findings: List[Finding]) -> Tuple[int, str, str]:
        """
        Returns (risk_score, status, overall_severity)
        """
        if not findings:
            return 0, "pass", "low"

        # Check for hard block
        has_hard_block = any(f.hard_block for f in findings)
        if has_hard_block:
            return 100, "fail", "critical"

        # Calculate raw score
        raw_score = 0
        max_sev_found = "low"
        highest_weight = 0

        for f in findings:
            weight = SEVERITY_WEIGHTS.get(f.severity.lower(), 10)
            raw_score += weight
            if weight > highest_weight:
                highest_weight = weight
                max_sev_found = f.severity.lower()

        # Enforce invariant: without hard block, score is capped at 89
        final_score = min(raw_score, 89)

        # Map score to status
        if final_score < 40:
            status = "pass"
        else: # 40 <= final_score <= 89
            status = "warn"

        return final_score, status, max_sev_found
