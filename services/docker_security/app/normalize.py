from typing import List, Dict, Tuple
from app.schema import Finding

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1
}

# Mapping of external tool rule IDs to canonical concepts
RULE_CONCEPT_MAP = {
    # Untagged / latest image
    "hadolint:DL3007": "UNTAGGED_IMAGE",
    "trivy:DS-0001": "UNTAGGED_IMAGE",
    "custom:DSG-D002": "UNTAGGED_IMAGE",
    "custom:DSG-C010": "UNTAGGED_IMAGE",

    # Root user
    "hadolint:DL3002": "ROOT_USER",
    "hadolint:DL3066": "ROOT_USER",
    "trivy:DS-0002": "ROOT_USER",
    "custom:DSG-D001": "ROOT_USER",
    "custom:DSG-C011": "ROOT_USER",

    # Missing --no-install-recommends
    "hadolint:DL3015": "NO_INSTALL_RECOMMENDS",
    "trivy:DS-0029": "NO_INSTALL_RECOMMENDS",

    # Missing HEALTHCHECK
    "trivy:DS-0026": "MISSING_HEALTHCHECK",
    "custom:DSG-D010": "MISSING_HEALTHCHECK",

    # Privileged mode
    "custom:DSG-C001": "PRIVILEGED_MODE",
    "trivy:DS-0006": "PRIVILEGED_MODE",

    # Docker socket mount
    "custom:DSG-C002": "DOCKER_SOCKET_MOUNT",

    # Exposed docker daemon port
    "custom:DSG-D006": "EXPOSED_DOCKER_PORT",
}


class FindingsNormalizer:
    """
    Normalizes raw findings from Hadolint, Trivy, and Custom Rules engines into
    deduplicated canonical findings with unified sources lists.
    """

    @staticmethod
    def normalize_and_deduplicate(findings: List[Finding]) -> List[Finding]:
        if not findings:
            return []

        grouped: Dict[Tuple[int, str], List[Finding]] = {}

        for f in findings:
            concept = RULE_CONCEPT_MAP.get(f.detector_id)
            if not concept:
                # If detector_id has prefix e.g. custom:DSG-D001
                for source in f.sources:
                    if source in RULE_CONCEPT_MAP:
                        concept = RULE_CONCEPT_MAP[source]
                        break

            if not concept:
                # Fallback concept based on detector_id or line_number
                concept = f.detector_id

            # Group by (line_number, concept)
            key = (f.line_number, concept)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(f)

        deduped: List[Finding] = []

        for (line_num, concept), group in grouped.items():
            # Pick highest severity finding as primary base
            best_finding = max(group, key=lambda item: (SEVERITY_RANK.get(item.severity.lower(), 1), item.confidence))

            # --- FIX: one entry per raw finding, no double-counting ---
            # Previously this loop added every string in item.sources, THEN also
            # added item.detector_id separately even when detector_id (unprefixed)
            # already existed in sources with a prefix (e.g. "custom:DSG-D001").
            # That produced duplicate entries like ['custom:DSG-D001', 'DSG-D001']
            # for a single raw finding, inflating len(sources) beyond the true
            # number of raw findings merged and breaking the dedup-count math.
            all_sources = []
            for item in group:
                if item.sources:
                    for src in item.sources:
                        if src not in all_sources:
                            all_sources.append(src)
                else:
                    # Only fall back to detector_id when the finding has no
                    # sources at all (nothing to duplicate against).
                    if item.detector_id not in all_sources:
                        all_sources.append(item.detector_id)

            # Hard block if any in group is hard block
            is_hard_block = any(item.hard_block for item in group)

            canonical_finding = Finding(
                detector_id=best_finding.detector_id,
                file_path=best_finding.file_path,
                line_number=best_finding.line_number,
                preview=best_finding.preview,
                confidence=best_finding.confidence,
                severity=best_finding.severity,
                reason=best_finding.reason,
                remediation=best_finding.remediation,
                sources=all_sources,
                category=best_finding.category,
                hard_block=is_hard_block,
                risk_contribution=best_finding.risk_contribution
            )
            deduped.append(canonical_finding)

        # Sort deduped findings by severity rank descending, then line number ascending
        deduped.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity.lower(), 1), f.line_number))
        return deduped