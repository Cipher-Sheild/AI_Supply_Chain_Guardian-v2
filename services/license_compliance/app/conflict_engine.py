"""
Stage 3 — the Conflict Engine, plus Fusion.

This is where a dependency's *identified* license (Stage 1) actually
gets compared against the project's *policy* (Stage 2) to produce a
verdict. This comparison — "is GPL-3.0-only allowed under a
no-copyleft policy, and if not, why not" — is genuinely different work
from license identification, and it's the part of this agent that
isn't just ScanCode's output reformatted.

Per-dependency verdicts are one of:
  - "compliant"    — license identified with reasonable confidence and
                      allowed by policy
  - "conflict"      — license identified and explicitly disallowed
  - "needs_review"  — license unknown/missing, or identification was
                       too low-confidence to act on, or (per policy)
                       dual-licensed in a way that needs a human call

Dual/multi-licensed packages ("MIT OR GPL-3.0") are evaluated
permissively when combined with OR — the consumer can choose whichever
license branch they want to use, so if *any* branch is compliant, the
dependency is compliant (with a note identifying which branch). An AND
expression must satisfy every branch, since both apply simultaneously.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.extraction import Dependency
from app.license_lookup import LicenseResult
from app.policy import Policy, classify_family

# Below this confidence, even a policy-compliant-looking match is
# routed to needs_review rather than a confident "compliant" — a low-
# confidence guess shouldn't silently pass review.
_MIN_CONFIDENT_MATCH = 0.5


@dataclass
class DependencyVerdict:
    dependency: Dependency
    verdict: str  # "compliant" | "conflict" | "needs_review"
    confidence: float
    spdx_expressions: list[str]
    reason: str
    policy_rule: Optional[str] = None
    expression_tree: Optional[dict] = None
    source: str = "unknown"  # "registry_classifier" | "registry_field" | "scancode_fallback" | "unknown"


def _evaluate_single_license(spdx_id: str, policy: Policy) -> tuple[str, str, Optional[str]]:
    """Returns (verdict, reason, policy_rule) for one concrete SPDX id."""
    family = classify_family(spdx_id)

    if policy.is_explicitly_denied(spdx_id):
        return (
            "conflict",
            f"{spdx_id} is explicitly denied by project policy.",
            f"denied_licenses matches {spdx_id}",
        )

    if policy.is_always_flagged(spdx_id):
        return (
            "conflict",
            f"{spdx_id} is on the project's always-flag list regardless of policy mode.",
            f"always_flag: {spdx_id}",
        )

    if policy.mode == "permissive-only":
        if policy.is_explicitly_allowed(spdx_id):
            return "compliant", f"{spdx_id} is on the project's permissive allowlist.", None
        return (
            "conflict",
            f"{spdx_id} is not on the project's allowlist (mode: permissive-only).",
            "not in allowed_licenses (permissive-only mode)",
        )

    if policy.mode == "no-copyleft":
        if family == "copyleft":
            return (
                "conflict",
                f"{spdx_id} is copyleft; project policy disallows copyleft dependencies.",
                "no-copyleft mode",
            )
        if family == "weak-copyleft":
            return (
                "needs_review",
                f"{spdx_id} is weak-copyleft ({family}); this typically only affects modified "
                "copies of the dependency itself, but the project's policy doesn't have an explicit "
                "rule for it — flagging for a human decision.",
                "no-copyleft mode: weak-copyleft not explicitly ruled on",
            )
        if policy.is_explicitly_allowed(spdx_id) or family == "permissive":
            return "compliant", f"{spdx_id} is permissive and not copyleft.", None
        return "needs_review", f"{spdx_id} did not match a known family; flagging for review.", None

    # mode == "custom": rely purely on allow/deny lists, already checked above.
    if policy.is_explicitly_allowed(spdx_id):
        return "compliant", f"{spdx_id} is on the project's custom allowlist.", None
    return (
        "needs_review",
        f"{spdx_id} is neither explicitly allowed nor denied under the project's custom policy.",
        None,
    )


def evaluate_dependency(dependency: Dependency, license_result: LicenseResult, policy: Policy) -> DependencyVerdict:
    verdict = _evaluate_dependency_inner(dependency, license_result, policy)
    verdict.source = license_result.source
    from app.license_lookup import _tree_for
    verdict.expression_tree = license_result.expression_tree or _tree_for(license_result.spdx_expressions, license_result.expression_op)
    return verdict


def _evaluate_dependency_inner(dependency: Dependency, license_result: LicenseResult, policy: Policy) -> DependencyVerdict:
    if not license_result.spdx_expressions:
        reason = "Could not determine a usable SPDX license for this dependency."
        if license_result.warnings:
            reason += " " + " ".join(license_result.warnings)
        return DependencyVerdict(
            dependency=dependency,
            verdict="conflict" if policy.unknown_handling == "conflict" else "needs_review",
            confidence=license_result.confidence,
            spdx_expressions=[],
            reason=reason,
        )

    from app.license_lookup import _tree_for
    tree = license_result.expression_tree or _tree_for(license_result.spdx_expressions, license_result.expression_op)
    def evaluate(node):
        if node["op"] == "license":
            if policy.is_explicitly_denied(node['id']):
                return _evaluate_single_license(node['id'], policy)
            if not node.get("known", False):
                return "needs_review", f"Unrecognized license {node['id']}", None
            return _evaluate_single_license(node["id"], policy)
        if node["op"] == "WITH":
            base = evaluate(node["license"])
            if base[0] == "conflict": return base
            return "needs_review", f"License exception {node['exception']} needs policy review", None
        branches = [evaluate(c) for c in node["children"]]
        if node["op"] == "AND":
            return next((b for b in branches if b[0] == "conflict" and b[2] and b[2].startswith("denied_licenses")), next((b for b in branches if b[0] == "conflict"), next((b for b in branches if b[0] == "needs_review"), ("compliant", "All required licenses satisfy policy", None))))
        # An OR expression retains any non-denied alternative for human review.
        return next((b for b in branches if b[0] == "needs_review"), next((b for b in branches if b[0] == "compliant"), next((b for b in branches if not (b[2] and b[2].startswith("denied_licenses"))), branches[0])))
    verdict, reason, rule = evaluate(tree)
    if license_result.warnings and verdict == "compliant":
        verdict, reason = "needs_review", "Expression or identification remains unresolved: " + "; ".join(license_result.warnings)
    return DependencyVerdict(dependency=dependency, verdict=verdict, confidence=license_result.confidence,
        spdx_expressions=license_result.spdx_expressions, reason=reason, policy_rule=rule)


def _confidence_gate(verdict: DependencyVerdict) -> DependencyVerdict:
    """A low-confidence identification shouldn't produce a confident 'compliant'."""
    if verdict.verdict == "compliant" and verdict.confidence < _MIN_CONFIDENT_MATCH:
        return DependencyVerdict(
            dependency=verdict.dependency,
            verdict="needs_review",
            confidence=verdict.confidence,
            spdx_expressions=verdict.spdx_expressions,
            reason=f"License identification confidence ({verdict.confidence}) too low to trust a 'compliant' "
            f"verdict outright, even though {', '.join(verdict.spdx_expressions)} would otherwise pass. "
            + verdict.reason,
            policy_rule=verdict.policy_rule,
            source=verdict.source,
        )
    return verdict


def evaluate_all(
    dependencies: list[Dependency], license_results: dict[str, LicenseResult], policy: Policy
) -> list[DependencyVerdict]:
    verdicts = []
    for dep in dependencies:
        key = f"{dep.ecosystem}:{dep.name}:{dep.version or 'unresolved'}"
        result = license_results.get(key)
        if result is None:
            verdicts.append(
                DependencyVerdict(
                    dependency=dep,
                    verdict="needs_review",
                    confidence=0.0,
                    spdx_expressions=[],
                    reason="License lookup did not complete for this dependency.",
                )
            )
            continue
        verdicts.append(_confidence_gate(evaluate_dependency(dep, result, policy)))
    return verdicts


# ---------------------------------------------------------------------------
# Fusion — combine per-dependency verdicts into the final AgentResult payload
# ---------------------------------------------------------------------------

def fuse(verdicts: list[DependencyVerdict]) -> dict:
    """
    Returns the dict used to populate AgentResult.

    IMPORTANT (Phase A audit fix): the real trust_engine `AgentResult`
    schema has no top-level `severity`/`confidence` field -- only
    `agent_name`/`status`/`findings`/`evidence`. Pydantic silently drops
    unrecognized top-level keys rather than raising, which is exactly
    why the old shape here got the whole result discarded downstream.
    `severity` and `confidence` now live per-Finding instead (required
    fields on the real `Finding` model), and each Finding is shaped as
    `{category, severity, confidence, location, details}` with
    everything that used to be a flat top-level key (package, version,
    ecosystem, verdict, license, policy_rule, reason, source, transitive,
    via) moved into `details`. Only conflict/needs_review verdicts
    produce a Finding -- compliant verdicts never do (unchanged).
    """
    if not verdicts:
        return {
            "status": "pass",
            "findings": [],
            "evidence": {"dependencies_scanned": 0},
        }

    conflicts = [v for v in verdicts if v.verdict == "conflict"]
    reviews = [v for v in verdicts if v.verdict == "needs_review"]

    if conflicts:
        status = "fail"
    elif reviews:
        status = "warn"
    else:
        status = "pass"

    findings = []
    for v in conflicts + reviews:
        dep = v.dependency
        severity = "high" if v.verdict == "conflict" else "medium"
        # A hard denylist/always-flag match is escalated to critical --
        # this is a categorical policy violation, not a judgment call.
        if v.verdict == "conflict" and v.policy_rule and (
            v.policy_rule.startswith("denied_licenses")
        ):
            severity = "critical"
        findings.append(
            {
                "category": "license_conflict" if v.verdict == "conflict" else "license_review",
                "severity": severity,
                "confidence": v.confidence,
                "location": f"{dep.filename or 'unknown'}:{dep.line_number}",
                "reason": v.reason,
                "remediation": "Resolve the license expression or replace the dependency with one allowed by project policy.",
                "hard_block": v.verdict == "conflict" and bool(v.policy_rule and v.policy_rule.startswith("denied_licenses")),
                "details": {
                    "package": dep.name,
                    "version": dep.version,
                    "ecosystem": dep.ecosystem,
                    "verdict": v.verdict,
                    "license": ", ".join(v.spdx_expressions) if v.spdx_expressions else "unknown",
                    "expression_tree": v.expression_tree,
                    "policy_rule": v.policy_rule,
                    "reason": v.reason,
                    "source": v.source,
                    "confidence": v.confidence,
                    "transitive": not dep.direct,
                    "via": dep.via,
                },
            }
        )

    evidence = {
        "dependencies_scanned": len(verdicts),
        "compliant_count": len(verdicts) - len(conflicts) - len(reviews),
        "conflict_count": len(conflicts),
        "needs_review_count": len(reviews),
        # Full per-dependency audit trail, including compliant results —
        # `findings` above only lists conflicts/needs_review (what a
        # reviewer needs to act on), but license *identification source*
        # (registry_classifier / registry_field / scancode_fallback /
        # unknown) is useful to see for every dependency, not just
        # flagged ones, e.g. to confirm the ScanCode fallback path
        # actually ran on a given package.
        "all_dependencies": [
            {
                "package": v.dependency.name,
                "version": v.dependency.version,
                "license": ", ".join(v.spdx_expressions) if v.spdx_expressions else "unknown",
                "verdict": v.verdict,
                "expression_tree": v.expression_tree,
                "source": v.source,
                "confidence": v.confidence,
            }
            for v in verdicts
        ],
    }

    return {
        "unresolved": bool(reviews),
        "decision_floor": "reject" if any(v.policy_rule and v.policy_rule.startswith("denied_licenses") for v in conflicts) else ("review" if conflicts or reviews else "accept"),
        "status": status,
        "findings": findings,
        "evidence": evidence,
    }