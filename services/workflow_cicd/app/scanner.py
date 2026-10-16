"""
Workflow / CI-CD rule engine.

Fully rule-based, no ML/LLM — per project doc §7.5: "pinning is a binary
check, not a judgment call." Scope: GitHub Actions only for v1 (GitLab CI
deferred — see workflow_cicd_reference.md).

Three checks, matching the doc's implementation steps 2-4:
  1. check_unpinned_actions      -> unpinned/mutable-ref `uses:` values
  2. check_broad_permissions     -> write-all / broad perms + pull_request_target
  3. check_curl_pipe_bash        -> remote script piped straight into a shell

Real-world basis for test fixtures: the 2025 tj-actions supply-chain
compromise (unpinned third-party action), per project doc §8.2.
"""

import re
from typing import Optional

import yaml

from app.schemas import Finding

# A full 40-char lowercase-hex commit SHA is the only "safe" pin.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# A version tag: v4, v4.1.1, 1.2.3. Anything that is neither a SHA nor this
# shape is treated as a mutable branch ref. Detecting tags POSITIVELY (rather
# than blacklisting {main, master, ...}) means an arbitrary branch such as
# @develop or @release/v2 is correctly scored high, not medium.
_TAG_RE = re.compile(r"^v?\d+(?:\.\d+)*$", re.IGNORECASE)

# `curl ... | bash` and friends. Allows intermediate pipe stages, sudo with
# flags, and non-shell interpreters (python/perl/node/ruby).
_CURL_PIPE_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n]*?\|[^\n]*?\b"
    r"(?:sudo\s+(?:-\w+\s+)*)?"
    r"(?:[\w./-]*(?:ba|z|k|da|fi)?sh|python[\d.]*|perl|ruby|node)\b",
    re.IGNORECASE,
)

# PowerShell equivalent: iwr/irm piped into Invoke-Expression.
_IWR_IEX_RE = re.compile(
    r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl)\b[^\n]*?\|"
    r"[^\n]*?\b(?:iex|invoke-expression)\b",
    re.IGNORECASE,
)

# Permission scopes that count as "broad" when set to write, beyond the
# blanket `write-all` shorthand.
_BROAD_SCOPES = {"contents", "packages", "actions", "deployments", "id-token"}

# Triggers that run in the context of the base repo with access to secrets,
# while checking out attacker-controlled fork code.
_DANGEROUS_TRIGGERS = {"pull_request_target", "workflow_run"}


def load_workflow(content: str) -> dict:
    """
    Parse workflow YAML into a plain dict.

    GOTCHA: PyYAML follows YAML 1.1, which treats the bare scalar `on` as
    the boolean True — so a workflow's top-level `on:` key parses as the
    Python key `True`, not the string "on". GitHub Actions workflows always
    have this key, so we normalize it back to "on" here rather than
    special-casing it at every call site.
    """
    from app.bounded_yaml import load
    parsed = load(content)
    if not isinstance(parsed, dict):
        raise ValueError("Workflow YAML did not parse to a mapping at the top level")
    if True in parsed and "on" not in parsed:
        parsed["on"] = parsed.pop(True)
    return parsed


class LineFinder:
    """
    Best-effort 1-indexed line lookup against the raw YAML text, since
    safe_load discards positions.

    Tracks how many times each needle has already been resolved, so the same
    `uses:` value appearing in two jobs reports two different lines instead of
    both pointing at the first occurrence. One instance per analysis run.
    """

    def __init__(self, content: str):
        self._lines = content.splitlines()
        self._seen: dict[str, int] = {}

    def find(self, needle: str) -> Optional[int]:
        skip = self._seen.get(needle, 0)
        for i, line in enumerate(self._lines):
            if needle in line:
                if skip:
                    skip -= 1
                    continue
                self._seen[needle] = self._seen.get(needle, 0) + 1
                return i + 1
        return None


def _classify_ref(ref: str) -> tuple[Optional[str], str]:
    """Return (severity, ref_type). severity is None when correctly pinned."""
    if _SHA_RE.fullmatch(ref):
        return None, "sha"
    if _TAG_RE.fullmatch(ref):
        return "medium", "tag"
    return "high", "branch"


def _iter_action_refs(workflow: dict):
    """
    Yield (job_name, label, uses) for every action reference.

    Covers BOTH step-level `uses:` and job-level `uses:` (reusable workflow
    calls). A job-level `uses: org/repo/.github/workflows/x.yml@main` with
    `secrets: inherit` hands your secrets to a mutable ref — same risk class
    as an unpinned step.
    """
    jobs = workflow.get("jobs") or {}
    if not isinstance(jobs, dict):
        return
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        if isinstance(job.get("uses"), str):
            yield job_name, "reusable workflow", job["uses"]
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for idx, step in enumerate(steps):
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                yield job_name, f"step {idx}", step["uses"]


def _iter_steps(workflow: dict):
    """Yield (job_name, step_index, step_dict) for every step in every job."""
    jobs = workflow.get("jobs") or {}
    if not isinstance(jobs, dict):
        return
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for idx, step in enumerate(steps):
            if isinstance(step, dict):
                yield job_name, idx, step


def check_unpinned_actions(workflow: dict, finder: LineFinder) -> list[Finding]:
    findings: list[Finding] = []
    for job_name, label, uses in _iter_action_refs(workflow):
        # Local actions (./path) live in this repo — nothing to pin.
        if uses.startswith("./"):
            continue

        if "@" not in uses:
            line = finder.find(uses)
            findings.append(Finding(
                category="unpinned-action",
                severity="high",
                confidence=1.0,
                location=f"job '{job_name}', {label}" + (f", line {line}" if line else ""),
                details={
                    "message": f"Action '{uses}' has no ref pinned at all",
                    "remediation": "Pin to a full commit SHA, e.g. owner/action@<40-char-sha>",
                    "rule_id": "unpinned-action-no-ref",
                    "ref_type": "none",
                },
            ))
            continue

        action, ref = uses.rsplit("@", 1)
        severity, ref_type = _classify_ref(ref)
        if severity is None:
            continue  # correctly pinned to a SHA

        if ref_type == "branch":
            message = f"Action '{action}' pinned to mutable branch ref '@{ref}'"
        else:
            message = f"Action '{action}' pinned to tag '@{ref}', not a commit SHA"

        line = finder.find(uses)
        findings.append(Finding(
            category="unpinned-action",
            severity=severity,
            confidence=1.0,
            location=f"job '{job_name}', {label}" + (f", line {line}" if line else ""),
            details={
                "message": message,
                "remediation": f"Pin to a full commit SHA, e.g. {action}@<40-char-sha>",
                "rule_id": "unpinned-action",
                "ref_type": ref_type,
            },
        ))
    return findings


def _extract_triggers(workflow: dict) -> set[str]:
    on = workflow.get("on")
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(t) for t in on}
    if isinstance(on, dict):
        return {str(k) for k in on.keys()}
    return set()


def _permissions_are_broad(permissions) -> Optional[str]:
    """Return a human description if broad, else None."""
    if isinstance(permissions, str):
        if permissions.strip() == "write-all":
            return "'write-all'"
        return None
    if isinstance(permissions, dict):
        granted = sorted(
            scope for scope, perm in permissions.items()
            if scope in _BROAD_SCOPES and str(perm).lower() == "write"
        )
        if granted:
            return "write access to " + ", ".join(granted)
    return None


def _iter_permission_scopes(workflow: dict):
    """Yield (label, permissions_value) for workflow-level AND job-level blocks."""
    if "permissions" in workflow:
        yield "workflow", workflow["permissions"]
    jobs = workflow.get("jobs") or {}
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if isinstance(job, dict) and "permissions" in job:
                yield f"job '{job_name}'", job["permissions"]


def check_broad_permissions(workflow: dict, finder: LineFinder) -> list[Finding]:
    findings: list[Finding] = []
    triggers = _extract_triggers(workflow)
    risky = sorted(triggers & _DANGEROUS_TRIGGERS)
    if not risky:
        return findings  # this check only fires for the dangerous trigger combo

    trigger = risky[0]
    trigger_line = finder.find(trigger)
    scopes = list(_iter_permission_scopes(workflow))

    if not scopes:
        # No permissions block anywhere: the repo-default token scope applies,
        # which on many repos is still read/write.
        findings.append(Finding(
            category="missing-permissions-block",
            severity="high",
            confidence=1.0,
            location=f"line {trigger_line}" if trigger_line else None,
            details={
                "message": (
                    f"Trigger is '{trigger}' with no explicit 'permissions:' block — "
                    "the repository-default token scope is exposed to fork PRs"
                ),
                "remediation": "Declare an explicit least-privilege permissions block",
                "rule_id": "missing-permissions-block",
                "trigger": trigger,
            },
        ))
        return findings

    for label, permissions in scopes:
        description = _permissions_are_broad(permissions)
        if not description:
            continue
        # Point at the permissions line the developer must change, not the
        # trigger line. The trigger line travels in details for context.
        perm_line = finder.find("permissions")
        findings.append(Finding(
            category="broad-permissions-plus-pull-request-target",
            severity="critical",
            confidence=1.0,
            location=f"line {perm_line}" if perm_line else None,
            details={
                "message": (
                    f"Permissions at {label} scope grant {description} and the trigger "
                    f"is '{trigger}', which exposes secrets and a write-capable "
                    "GITHUB_TOKEN to fork PRs"
                ),
                "remediation": (
                    "Scope permissions to least-privilege (e.g. contents: read), "
                    "or switch the trigger to 'pull_request' if fork write access "
                    "is not required"
                ),
                "rule_id": "broad-permissions-plus-pull-request-target",
                "scope": label,
                "trigger": trigger,
                "trigger_location": f"line {trigger_line}" if trigger_line else None,
            },
        ))
    return findings


def check_curl_pipe_bash(workflow: dict, finder: LineFinder) -> list[Finding]:
    findings: list[Finding] = []
    for job_name, idx, step in _iter_steps(workflow):
        run = step.get("run")
        if not isinstance(run, str):
            continue
        for raw_line in run.splitlines() or [run]:
            match = _CURL_PIPE_SHELL_RE.search(raw_line) or _IWR_IEX_RE.search(raw_line)
            if not match:
                continue
            line = finder.find(raw_line.strip())
            findings.append(Finding(
                category="curl-pipe-bash",
                severity="high",
                confidence=1.0,
                location=f"job '{job_name}', step {idx}" + (f", line {line}" if line else ""),
                details={
                    "message": "Remote script piped directly into a shell without integrity verification",
                    "remediation": (
                        "Download the script, verify its checksum/signature, then "
                        "execute - or vendor the install script into the repo"
                    ),
                    "rule_id": "curl-pipe-bash",
                    "snippet": raw_line.strip()[:200],
                },
            ))
    return findings

# --- Numeric workflow risk score (project doc 7.5) ------------------------
#
# The doc specifies this agent outputs "a workflow risk score plus specific
# line-level flags". The findings are the flags; this is the score.
#
# Deterministic weighted penalty from a clean 100, mirroring the severity
# ladder the status uses. Confidence multiplies the penalty, so a rule-based
# match at 1.0 costs full weight while a lower-confidence finding costs
# proportionally less. Weights are a starting point and are tunable in
# config.yml -- they are not calibrated against labelled data yet.
SEVERITY_RISK_WEIGHT = {
    "critical": 40,
    "high": 20,
    "medium": 8,
    "low": 3,
    "info": 0,
}


def compute_risk_score(findings: list[Finding]) -> int:
    """0-100, where 100 is a clean workflow. Floored at 0."""
    penalty = sum(
        SEVERITY_RISK_WEIGHT.get(f.severity, 0) * f.confidence for f in findings
    )
    return max(0, round(100 - penalty))

def determine_status(findings: list[Finding]) -> str:
    """
    Mirrors code_security's determine_status() pattern:
    no findings -> pass; any high/critical -> fail; otherwise -> warn.
    """
    if not findings:
        return "pass"
    if any(f.severity in ("high", "critical") for f in findings):
        return "fail"
    return "warn"


def analyze_workflow(content: str) -> tuple[str, list[Finding]]:
    """
    Run all 3 checks against raw workflow YAML text.
    Returns (status, findings). Raises ValueError/yaml.YAMLError on unparsable input —
    caller (main.py) is responsible for turning that into a status="fail" response.
    """
    workflow = load_workflow(content)
    finder = LineFinder(content)
    findings: list[Finding] = []
    findings.extend(check_unpinned_actions(workflow, finder))
    findings.extend(check_broad_permissions(workflow, finder))
    findings.extend(check_curl_pipe_bash(workflow, finder))
    return determine_status(findings), findings
