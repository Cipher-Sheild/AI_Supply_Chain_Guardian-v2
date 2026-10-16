"""
Artifact router for trust_engine.

A pure, deterministic function: given one file, decide which detector
agents should be called for it. No network calls, no LLM, no side
effects, so it is testable in isolation and cheap to reason about.

Resolution is driven by an ordered rule table rather than scattered
if/else branches, so adding a rule is a data change rather than a
control-flow change.

Scope: this module decides WHO runs. It does not call anybody and it
does not score anything. Dispatch lives in orchestration.py; fusion
consumes the records this module produces.
"""

from __future__ import annotations

from app.capabilities import MATRIX, CODE_EXTENSIONS, ARTIFACT_TYPES
import json
import re
from typing import Literal, Optional

from pydantic import BaseModel, Field

ArtifactType = Literal["code", "dockerfile", "compose", "markdown", "workflow", "dependency", "license", "unknown"]
RoutingSource = Literal["explicit", "inferred", "sniffed", "fallback"]
Coverage = Literal["full", "partial", "none"]

VALID_ARTIFACT_TYPES = ARTIFACT_TYPES


class InvalidArtifactType(ValueError):
    """Raised when an explicitly supplied artifact_type is not in the enum.

    The API layer turns this into HTTP 422 -- an explicit value that the
    system does not recognise is a client error, not something to guess
    around.
    """


# --- Routing table --------------------------------------------------------
#
# secret_detection appears under every recognised type: a hardcoded
# credential turns up in source, in a Dockerfile ENV line and in a workflow
# env: block alike.
#
# prompt_injection is code-only for now. Whether it can extract comments and
# string literals from Dockerfiles and workflow YAML is an open question with
# the agent owner, so it is a single constant here -- extending it later is a
# one-line edit, not a restructure.

PROMPT_INJECTION_TYPES = {"code"}

ROUTING_TABLE = MATRIX["types"]

# --- Filename and path rules (checked in order; first match wins) ----------
#
# Specific paths are tested before generic extensions, so a .yml inside
# .github/workflows/ resolves as a workflow while the same extension
# elsewhere does not. Patterns are matched against a lowercased,
# forward-slash-normalised path.

_PATH_RULES: list[tuple[re.Pattern, str]] = [
    # Workflow definitions -- path-specific, must precede the generic .yml rule.
    (re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$"), "workflow"),
    (re.compile(r"(^|/)\.gitlab-ci\.ya?ml$"), "workflow"),
    # Container definitions.
    (re.compile(r"(^|/)dockerfile$"), "dockerfile"),
    (re.compile(r"(^|/)dockerfile\.[^/]+$"), "dockerfile"),
    (re.compile(r"\.dockerfile$"), "dockerfile"),
    (re.compile(r"(^|/)containerfile$"), "dockerfile"),
    # Dependency manifests that CipherGuard and License Compliance can parse.
    (re.compile(r"(^|/)requirements[^/]*\.txt$"), "dependency"),
    (re.compile(r"(^|/)requirements/[^/]+\.txt$"), "dependency"),
    (re.compile(r"(^|/)package\.json$"), "dependency"),
]

_CODE_EXTENSIONS = CODE_EXTENSIONS | set(MATRIX["unsupported_code_extensions"])

# Known lockfile names are resolved against the capability matrix first.
# Remaining unsupported lockfile formats are kept out of text-secret scans.
_LOCKFILES = {
    "poetry.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "pipfile.lock", "cargo.lock", "composer.lock", "gemfile.lock",
}

# Text artifacts above this size are not dispatched at all. Configurable;
# the value is a starting point pending a team decision.
MAX_ARTIFACT_BYTES = 1_000_000


class RoutingDecision(BaseModel):
    """What the router decided for one file.

    Consumed by the fusion layer, so the field names here are an agreed
    interface -- see the Router/Orchestrator/Fusion interface agreement.
    Changes go through that agreement rather than being made unilaterally.
    """

    filename: Optional[str] = None
    artifact_type: ArtifactType = "unknown"
    routing_source: RoutingSource = "fallback"
    expected_agents: list[str] = Field(default_factory=list)
    coverage: Coverage = "none"
    notes: list[str] = Field(default_factory=list)


# --- Type resolution ------------------------------------------------------


def _normalise_path(filename: Optional[str]) -> Optional[str]:
    if not filename:
        return None
    return filename.replace("\\", "/").strip().lower()


def _infer_from_path(path: str) -> Optional[str]:
    """Resolve an artifact type from a normalised path, or None."""
    basename = path.rsplit("/", 1)[-1]
    if basename in MATRIX.get("license_filenames", []):
        return "license"
    if basename in MATRIX["compose_filenames"]:
        return "compose"
    if any(basename.endswith(ext) for ext in MATRIX["markdown_extensions"]):
        return "markdown"
    if basename in MATRIX['dependency_filenames']:
        return 'dependency'
    if basename in MATRIX["unsupported_manifests"]:
        return "unsupported_dependency"
    if basename in {'package-lock.json','npm-shrinkwrap.json'}:
        return "dependency"
    if basename in _LOCKFILES:
        return "lockfile"  # sentinel: recognised, but deliberately unrouted
    for pattern, artifact_type in _PATH_RULES:
        if pattern.search(path):
            return artifact_type
    for extension in _CODE_EXTENSIONS:
        if basename.endswith(extension):
            return "code"
    return None


def _sniff_content(content: str) -> Optional[str]:
    """Resolve a type from content alone, used only when no filename exists.

    Deliberately conservative: it returns a type only on an unambiguous
    signal. Guessing here would be worse than returning unknown, because an
    unknown artifact is routed defensively while a wrong guess sends the
    file to an agent that cannot read it.
    """
    stripped = content.strip()
    if not stripped:
        return None

    # A Dockerfile's first meaningful instruction is FROM.
    for line in stripped.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^FROM\s+\S", line, re.IGNORECASE):
            return "dockerfile"
        break

    # A workflow has both a trigger and jobs at the top level. Checked as
    # text rather than parsed YAML: `on:` is the YAML 1.1 boolean trap, and
    # the router must stay dependency-free and side-effect free.
    has_trigger = re.search(r"^(on|true)\s*:", stripped, re.MULTILINE | re.IGNORECASE)
    has_jobs = re.search(r"^jobs\s*:", stripped, re.MULTILINE)
    if has_trigger and has_jobs:
        return "workflow"

    # Compose definitions.
    if re.search(r"^services\s*:", stripped, re.MULTILINE):
        return "compose"

    # A dependency manifest in JSON form.
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except (ValueError, TypeError):
            return None
        if isinstance(parsed, dict) and (
            "dependencies" in parsed or "devDependencies" in parsed
        ):
            return "dependency"

    return None


def _is_probably_binary(content: str) -> bool:
    """Null bytes are the clearest signal that this is not text."""
    return "\x00" in content


# --- Public entry point ---------------------------------------------------


def route_file(
    content: str,
    filename: Optional[str] = None,
    artifact_type: Optional[str] = None,
) -> RoutingDecision:
    """Decide which agents should analyse one file.

    Precedence: an explicit artifact_type wins; then path and filename
    rules; then a content sniff, used only when there is no filename; then
    unknown.
    """
    notes: list[str] = []
    path = _normalise_path(filename)

    # Guard clauses first -- an artifact nobody can read is routed to nobody,
    # which is a different outcome from one whose type is merely unrecognised.
    if _is_probably_binary(content):
        notes.append("binary content: no agents dispatched")
        return RoutingDecision(
            filename=filename, artifact_type="unknown",
            routing_source="fallback", expected_agents=[],
            coverage="none", notes=notes,
        )

    if len(content.encode("utf-8", errors="ignore")) > MAX_ARTIFACT_BYTES:
        notes.append(
            f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes: no agents dispatched"
        )
        return RoutingDecision(
            filename=filename, artifact_type="unknown",
            routing_source="fallback", expected_agents=[],
            coverage="none", notes=notes,
        )

    resolved: Optional[str] = None
    source: RoutingSource = "fallback"

    # 1. Explicit type always wins, but is validated rather than trusted.
    if artifact_type is not None:
        candidate = artifact_type.strip().lower()
        if candidate not in VALID_ARTIFACT_TYPES:
            raise InvalidArtifactType(
                f"artifact_type {artifact_type!r} is not one of "
                f"{sorted(VALID_ARTIFACT_TYPES)}"
            )
        resolved, source = candidate, "explicit"
        # A conflict is recorded rather than silently resolved: the explicit
        # value still wins, but the disagreement is visible downstream.
        if path:
            inferred = _infer_from_path(path)
            if inferred and inferred not in {"lockfile", "unsupported_dependency"} and inferred != candidate:
                notes.append(
                    f"explicit type '{candidate}' conflicts with filename "
                    f"inference '{inferred}'; explicit value used"
                )

    # 2. Path and filename rules.
    if resolved is None and path:
        inferred = _infer_from_path(path)
        if inferred == "unsupported_dependency":
            return RoutingDecision(filename=filename, artifact_type="dependency", routing_source="inferred", expected_agents=["secret_detection"], coverage="partial", notes=["unsupported manifest: dependency checks unavailable"])
        if inferred == "lockfile":
            notes.append(
                "lockfile: not a dependency manifest for CipherGuard, and "
                "hash-heavy content causes entropy false positives in "
                "secret_detection; no agents dispatched"
            )
            return RoutingDecision(
                filename=filename, artifact_type="unknown",
                routing_source="inferred", expected_agents=[],
                coverage="none", notes=notes,
            )
        if inferred:
            resolved, source = inferred, "inferred"

    # 3. Content sniff, only when there is no filename to go on.
    if resolved is None and not path:
        sniffed = _sniff_content(content)
        if sniffed:
            resolved, source = sniffed, "sniffed"
            notes.append(f"type sniffed from content as '{sniffed}' (no filename)")

    # 4. Fallback.
    if resolved is None:
        resolved, source = "unknown", "fallback"
        notes.append(
            "artifact type not recognised: only secret_detection dispatched, "
            "coverage is partial"
        )

    agents = list(ROUTING_TABLE.get(resolved, ROUTING_TABLE["unknown"]))
    if resolved not in {"code", "markdown", "license"}:
        agents = [a for a in agents if a != "prompt_injection"]
    if resolved == "code" and "code" not in PROMPT_INJECTION_TYPES:
        agents = [a for a in agents if a != "prompt_injection"]

    coverage: Coverage = "full" if resolved != "unknown" else "partial"
    if path and path.rsplit("/", 1)[-1] in MATRIX["unsupported_manifests"]:
        coverage = "partial"
        notes.append("specialist support unavailable for this format")
        agents = ["secret_detection"]
    if any("conflicts with filename" in note for note in notes):
        coverage = "partial"
    if not agents:
        coverage = "none"

    return RoutingDecision(
        filename=filename, artifact_type=resolved, routing_source=source,
        expected_agents=agents, coverage=coverage, notes=notes,
    )


def route_files(files: list[dict]) -> list[RoutingDecision]:
    """Route a list of files. A single-file request is a list of one."""
    return [
        route_file(
            content=f.get("content", ""),
            filename=f.get("filename") or f.get("file_path"),
            artifact_type=f.get("artifact_type") or f.get("type"),
        )
        for f in files
    ]
