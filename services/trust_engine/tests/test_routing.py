"""
Tests for the artifact router.

The spec's test list is reproduced here as executable assertions: every
routing-table row, the precedence cases, explicit-versus-inferred, and the
cases that must dispatch nobody.
"""

import pytest

from app.routing import (
    InvalidArtifactType,
    MAX_ARTIFACT_BYTES,
    ROUTING_TABLE,
    route_file,
    route_files,
)

PY = "import os\nprint('x')\n"


# --- Routing table: every row asserts its exact agent set -----------------


@pytest.mark.parametrize(
    "artifact_type,expected",
    [
        ("code", {"code_security", "secret_detection", "prompt_injection"}),
        ("dockerfile", {"docker_security", "secret_detection"}),
        ("workflow", {"workflow_cicd", "secret_detection"}),
        ("dependency", {"cipherguard", "license_compliance", "secret_detection"}),
        ("unknown", {"secret_detection"}),
    ],
)
def test_routing_table_rows(artifact_type, expected):
    decision = route_file(content="x", filename="f", artifact_type=artifact_type)
    assert set(decision.expected_agents) == expected


def test_secret_detection_runs_on_every_recognised_type():
    for artifact_type in ("code", "dockerfile", "workflow", "dependency"):
        decision = route_file(content="x", artifact_type=artifact_type)
        assert "secret_detection" in decision.expected_agents, artifact_type


def test_prompt_injection_runs_on_code_only():
    assert "prompt_injection" in route_file(content=PY, artifact_type="code").expected_agents
    for artifact_type in ("dockerfile", "workflow", "dependency", "unknown"):
        decision = route_file(content="x", artifact_type=artifact_type)
        assert "prompt_injection" not in decision.expected_agents, artifact_type


# --- Precedence: specific paths beat generic extensions -------------------


@pytest.mark.parametrize(
    "filename,expected_type",
    [
        (".github/workflows/a.yml", "workflow"),
        (".github/workflows/deploy.yaml", "workflow"),
        ("repo/.github/workflows/ci.yml", "workflow"),
        (".gitlab-ci.yml", "workflow"),
        ("config.yml", "unknown"),          # a .yml outside a workflow path is NOT a workflow
        ("k8s/deployment.yaml", "unknown"),
        ("Dockerfile", "dockerfile"),
        ("Dockerfile.dev", "dockerfile"),
        ("build/prod.Dockerfile", "dockerfile"),
        ("Containerfile", "dockerfile"),
        ("requirements.txt", "dependency"),
        ("requirements-dev.txt", "dependency"),
        ("Requirements-Dev.TXT", "dependency"),   # case-insensitive
        ("requirements/base.txt", "dependency"),
        ("package.json", "dependency"),
        ("app.py", "code"),
        ("src/index.ts", "code"),
        ("main.go", "code"),
        ("notes.md", "markdown"),
    ],
)
def test_path_inference(filename, expected_type):
    assert route_file(content="x", filename=filename).artifact_type == expected_type


def test_windows_path_separators_are_normalised():
    decision = route_file(content="x", filename=r"repo\.github\workflows\ci.yml")
    assert decision.artifact_type == "workflow"


# --- Lockfiles: recognised, deliberately unrouted -------------------------


@pytest.mark.parametrize(
    "filename", ["yarn.lock", "composer.lock"]
)
def test_lockfiles_dispatch_nobody(filename):
    decision = route_file(content="{}", filename=filename)
    assert decision.expected_agents == []
    assert decision.coverage == "none"
    assert decision.notes, "a lockfile skip must be explained in notes"


def test_lockfile_is_not_treated_as_dependency_manifest():
    """Supported lockfiles route through dependency verification."""
    decision=route_file(content='{}',filename='package-lock.json')
    assert decision.artifact_type=='dependency'
    assert set(decision.expected_agents)=={'cipherguard','license_compliance','secret_detection'}
    assert "cipherguard" in route_file(content="{}", filename="package.json").expected_agents


# --- Explicit versus inferred --------------------------------------------


def test_explicit_type_overrides_inference():
    decision = route_file(content=PY, filename="app.py", artifact_type="dockerfile")
    assert decision.artifact_type == "dockerfile"
    assert decision.routing_source == "explicit"


def test_conflict_between_explicit_and_inferred_is_noted():
    decision = route_file(content=PY, filename="app.py", artifact_type="workflow")
    assert any("conflict" in n for n in decision.notes)


def test_agreement_between_explicit_and_inferred_adds_no_note():
    decision = route_file(content=PY, filename="app.py", artifact_type="code")
    assert not any("conflict" in n for n in decision.notes)


def test_invalid_explicit_type_raises():
    with pytest.raises(InvalidArtifactType):
        route_file(content="x", filename="app.py", artifact_type="yaml")


def test_routing_source_is_recorded():
    assert route_file(content="x", artifact_type="code").routing_source == "explicit"
    assert route_file(content="x", filename="app.py").routing_source == "inferred"
    assert route_file(content="FROM python:3.11\n").routing_source == "sniffed"
    assert route_file(content="hello world").routing_source == "fallback"


# --- Content sniffing: only without a filename, only when confident -------


def test_sniff_dockerfile():
    decision = route_file(content="# comment\nFROM python:3.11-slim\nUSER root\n")
    assert decision.artifact_type == "dockerfile"
    assert decision.routing_source == "sniffed"


def test_sniff_workflow_requires_both_trigger_and_jobs():
    workflow = "on:\n  push:\njobs:\n  build:\n    steps: []\n"
    assert route_file(content=workflow).artifact_type == "workflow"
    # A trigger alone is not enough to call something a workflow.
    assert route_file(content="on:\n  push:\n").artifact_type == "unknown"


def test_sniff_dependency_manifest():
    manifest = '{"name": "x", "dependencies": {"left-pad": "1.0.0"}}'
    assert route_file(content=manifest).artifact_type == "dependency"


def test_sniff_is_skipped_when_a_filename_exists():
    """A filename that resolves to nothing must not fall through to sniffing."""
    decision = route_file(content="FROM python:3.11\n", filename="notes.txt")
    assert decision.artifact_type == "unknown"
    assert decision.routing_source == "fallback"


def test_ambiguous_content_is_not_guessed():
    assert route_file(content="just some prose here").artifact_type == "unknown"


# --- Unrouted inputs ------------------------------------------------------


def test_binary_content_dispatches_nobody():
    decision = route_file(content="PK\x03\x04\x00binary", filename="a.zip")
    assert decision.expected_agents == []
    assert decision.coverage == "none"


def test_oversized_content_dispatches_nobody():
    decision = route_file(content="x" * (MAX_ARTIFACT_BYTES + 1), filename="big.py")
    assert decision.expected_agents == []
    assert decision.coverage == "none"


def test_unknown_type_routes_to_secret_detection_with_partial_coverage():
    decision = route_file(content="hello", filename="notes.txt")
    assert decision.expected_agents == ["secret_detection"]
    assert decision.coverage == "partial"
    assert decision.notes


def test_recognised_types_report_full_coverage():
    for artifact_type in ("code", "dockerfile", "workflow", "dependency"):
        assert route_file(content="x", artifact_type=artifact_type).coverage == "full"


# --- Purity ---------------------------------------------------------------


def test_router_is_deterministic():
    first = route_file(content=PY, filename="app.py")
    second = route_file(content=PY, filename="app.py")
    assert first.model_dump() == second.model_dump()


# --- Multi-file -----------------------------------------------------------


def test_route_files_handles_a_mixed_request():
    decisions = route_files([
        {"filename": "app.py", "content": PY},
        {"filename": "Dockerfile", "content": "FROM python:3.11\n"},
        {"filename": ".github/workflows/ci.yml", "content": "on: push\njobs: {}\n"},
        {"filename": "composer.lock", "content": "[[package]]\n"},
    ])
    assert [d.artifact_type for d in decisions] == [
        "code", "dockerfile", "workflow", "unknown",
    ]
    assert decisions[3].expected_agents == []


def test_route_files_accepts_either_type_key():
    """Requests in the wild use 'type'; the spec names 'artifact_type'."""
    assert route_files([{"content": "x", "type": "code"}])[0].artifact_type == "code"
    assert route_files([{"content": "x", "artifact_type": "code"}])[0].artifact_type == "code"


def test_single_file_request_is_a_list_of_one():
    assert len(route_files([{"filename": "app.py", "content": PY}])) == 1


def test_license_files_have_dedicated_policy_route():
    for filename in ('LICENSE','COPYING.txt','docs/LICENCE.md'):
        decision=route_file(content='MIT License',filename=filename)
        assert decision.artifact_type=='license'
        assert set(decision.expected_agents)=={'license_compliance','secret_detection'}
