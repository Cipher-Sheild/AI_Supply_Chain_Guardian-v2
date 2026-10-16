"""
Runs our agent's real pipeline (imported directly from
../../services/license_compliance/app -- same code, live PyPI/npm
calls, no mocking) against pip-licenses and license-checker on the same
real dependency sets, and prints a comparison.

Why "import directly" instead of a real HTTP call to the running
Docker service (as originally planned): this service's docker-compose
entry does not currently publish port 8000 to the host (confirmed
during earlier live testing -- `docker ps` showed `8000/tcp`, not
`0.0.0.0:8000->8000/tcp`), and per the task scope, this evaluation
script must not modify docker-compose.yml to add that mapping. Since
`services/license_compliance/app/{extraction,license_lookup,policy,
conflict_engine}.py` contain zero FastAPI-specific logic (that's
main.py's job, which we don't need here), importing them directly is
a direct-dependency approximation of Stage 0-3, omitting the HTTP
contract, caching, extraction error handling and main.py's transitive pass (which is a pure performance optimization, not a
correctness difference -- see that module's own docstring). If you
DO publish port 8000 in your own environment later, this script can be
trivially adapted to call the real HTTP endpoint instead; the
comparison results must be re-measured; equivalence with the deployed
service has not been established.

Usage:
    cd evaluation/license_compliance_baseline
    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    npm install -g license-checker
    which license-checker   # confirm it's actually on PATH before running
    python run_comparison.py

Note: the large-scan case (see run_large_scan_case below) installs ~53
real packages into a throwaway venv for the pip-licenses side, so it
takes noticeably longer (a few minutes) than the 5 small cases.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
from pathlib import Path

# Import our agent's real modules directly from the service folder.
_SERVICE_APP_PATH = Path(__file__).resolve().parents[2] / "services" / "license_compliance"
sys.path.insert(0, str(_SERVICE_APP_PATH))

import httpx  # noqa: E402
import yaml  # noqa: E402

from app.extraction import Dependency, extract_dependencies  # noqa: E402
from app.license_lookup import identify_license  # noqa: E402
from app.policy import load_policy  # noqa: E402
from app.conflict_engine import evaluate_all, fuse  # noqa: E402

from test_cases import (  # noqa: E402
    TEST_CASES,
    LARGE_SCAN_REQUIREMENTS_TXT,
    LARGE_SCAN_EXCLUDED_FROM_BASELINE_INSTALL,
)

# Load the exact same rulebook the real service uses -- config.yml
# merged with app/data/default_policy.json (see app/policy.py's own
# load_policy() for the merge logic) -- rather than reimplementing or
# guessing at policy defaults here. This is the real, current public
# API of app/policy.py: load_policy(config: dict) -> Policy.
_CONFIG_PATH = _SERVICE_APP_PATH / "config.yml"
with open(_CONFIG_PATH, "r", encoding="utf-8") as _f:
    _config = yaml.safe_load(_f) or {}
POLICY = load_policy(_config)


async def run_our_agent(artifact: dict) -> dict:
    """Runs Stage 0-3 directly, exactly like the real service's /analyze does."""
    async with httpx.AsyncClient() as client:
        deps, skipped = extract_dependencies(artifact)
        results = await asyncio.gather(
            *[identify_license(client, d.name, d.version, d.ecosystem) for d in deps]
        )
        license_results = {
            f"{d.ecosystem}:{d.name}:{d.version or 'unresolved'}": r
            for d, r in zip(deps, results)
        }

        # Same single-level, capped transitive check as the real service.
        seen = {d.name.lower() for d in deps}
        candidates = []
        for d in deps:
            key = f"{d.ecosystem}:{d.name}:{d.version or 'unresolved'}"
            r = license_results.get(key)
            if r is None:
                continue
            for sub in r.declared_transitive_names:
                if sub.lower() in seen or len(candidates) >= 10:
                    continue
                candidates.append(
                    Dependency(name=sub, version=None, ecosystem=d.ecosystem, direct=False, via=d.name)
                )
                seen.add(sub.lower())
        if candidates:
            tr_results = await asyncio.gather(
                *[identify_license(client, d.name, d.version, d.ecosystem) for d in candidates]
            )
            for d, r in zip(candidates, tr_results):
                license_results[f"{d.ecosystem}:{d.name}:{d.version or 'unresolved'}"] = r

        all_deps = deps + candidates
        verdicts = evaluate_all(all_deps, license_results, POLICY)
        fused = fuse(verdicts)
        fused["evidence"]["skipped"] = [
            {"raw": s.raw, "ecosystem": s.ecosystem, "reason": s.reason} for s in skipped
        ]
        return fused


def run_pip_licenses(pip_install_targets: list[str]) -> dict:
    """
    Installs the real package(s) into a throwaway venv, then runs
    pip-licenses against it. Returns {"installed": bool, ...}. Never
    raises -- a missing tool or failed install is reported in the
    returned dict, so one bad case doesn't kill the whole comparison run.
    """
    if shutil.which("pip-licenses") is None:
        return {
            "installed": False,
            "error": "'pip-licenses' not found on PATH. Install it with: pip install -r requirements.txt "
                     "(inside this folder's own venv), then confirm with: which pip-licenses",
        }

    import tempfile
    import venv

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            venv_dir = Path(tmpdir) / "venv"
            venv.create(venv_dir, with_pip=True)
            pip_bin = venv_dir / "bin" / "pip"
            python_bin = venv_dir / "bin" / "python"

            install = subprocess.run(
                [str(pip_bin), "install", "--quiet", *pip_install_targets],
                capture_output=True, text=True, timeout=300,
            )
            if install.returncode != 0:
                return {"installed": False, "install_error": install.stderr.strip()[-500:]}

            result = subprocess.run(
                ["pip-licenses", "--python", str(python_bin), "--format=json"],
                capture_output=True, text=True, timeout=60,
            )
            try:
                parsed = json.loads(result.stdout)
            except json.JSONDecodeError:
                parsed = {"raw": result.stdout}
            return {"installed": True, "packages": parsed}
        except subprocess.TimeoutExpired as exc:
            return {"installed": False, "error": f"Timed out: {exc}"}
        except FileNotFoundError as exc:
            return {"installed": False, "error": f"Command not found: {exc}"}


def run_license_checker(npm_install_targets: list[str]) -> dict:
    """
    Installs the real package(s) into a throwaway npm project, then runs
    license-checker. Never raises -- see run_pip_licenses docstring for why.
    """
    if shutil.which("license-checker") is None:
        return {
            "installed": False,
            "error": "'license-checker' not found on PATH. Install it globally with: "
                     "npm install -g license-checker -- then confirm with: which license-checker "
                     "(if that prints nothing even after installing, npm's global bin directory "
                     "likely isn't on your PATH -- run 'npm config get prefix' and add "
                     "'<that path>/bin' to your PATH).",
        }

    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            subprocess.run(["npm", "init", "-y"], cwd=tmpdir, capture_output=True, text=True, timeout=30)
            install = subprocess.run(
                ["npm", "install", *npm_install_targets],
                cwd=tmpdir, capture_output=True, text=True, timeout=180,
            )
            if install.returncode != 0:
                return {"installed": False, "install_error": install.stderr.strip()[-500:]}

            result = subprocess.run(
                ["license-checker", "--json"], cwd=tmpdir, capture_output=True, text=True, timeout=60,
            )
            try:
                parsed = json.loads(result.stdout)
            except json.JSONDecodeError:
                parsed = {"raw": result.stdout}
            return {"installed": True, "packages": parsed}
        except subprocess.TimeoutExpired as exc:
            return {"installed": False, "error": f"Timed out: {exc}"}
        except FileNotFoundError as exc:
            return {"installed": False, "error": f"Command not found: {exc}"}


async def run_large_scan_case() -> None:
    """
    The large, realistic 55-dependency scan (see test_cases.py). Two
    packages are excluded from the pip-licenses side's real `pip
    install` only -- see LARGE_SCAN_EXCLUDED_FROM_BASELINE_INSTALL's
    definition in test_cases.py for why (a native build failure
    unrelated to licensing, and a package that doesn't exist). Our own
    agent's run uses the FULL, unmodified manifest, since it never
    installs anything and is unaffected by either issue -- that
    contrast is itself part of what this case demonstrates.
    """
    print(f"\n{'=' * 70}\nLarge realistic scan (55 dependencies)\n{'=' * 70}")

    artifact = {
        "type": "python",
        "filename": "requirements.txt",
        "content": LARGE_SCAN_REQUIREMENTS_TXT,
    }
    our_result = await run_our_agent(artifact)
    print("\n--- Our agent (full, unmodified 55-line manifest) ---")
    print(json.dumps(our_result, indent=2, default=str))

    installable_lines = [
        line for line in LARGE_SCAN_REQUIREMENTS_TXT.splitlines()
        if line.strip() and line.strip() not in LARGE_SCAN_EXCLUDED_FROM_BASELINE_INSTALL
    ]
    print(
        f"\n--- pip-licenses (installing {len(installable_lines)} of 55 packages; "
        f"excluded: {LARGE_SCAN_EXCLUDED_FROM_BASELINE_INSTALL}) ---"
    )
    baseline = run_pip_licenses(installable_lines)
    if baseline.get("installed") and isinstance(baseline.get("packages"), list):
        print(json.dumps({"installed": True, "package_count": len(baseline["packages"])}, indent=2))
        gpl_like = [p for p in baseline["packages"] if "GPL" in p.get("License", "")]
        print("Packages with 'GPL' anywhere in their license string:")
        print(json.dumps(gpl_like, indent=2))
    else:
        print(json.dumps(baseline, indent=2, default=str))


async def main():
    for case in TEST_CASES:
        print(f"\n{'=' * 70}\n{case['name']}\n{'=' * 70}")

        artifact = {
            "type": case["ecosystem"],
            "filename": case["manifest_filename"],
            "content": case["manifest_content"],
        }
        our_result = await run_our_agent(artifact)
        print("\n--- Our agent ---")
        print(json.dumps(our_result, indent=2, default=str))

        if case["ecosystem"] == "python":
            print("\n--- pip-licenses ---")
            baseline = run_pip_licenses(case["pip_install_targets"])
            print(json.dumps(baseline, indent=2, default=str))
        elif case["ecosystem"] == "node":
            print("\n--- license-checker ---")
            baseline = run_license_checker(case["npm_install_targets"])
            print(json.dumps(baseline, indent=2, default=str))

    await run_large_scan_case()


if __name__ == "__main__":
    asyncio.run(main())