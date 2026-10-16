"""
Runs ScanCode Toolkit standalone (via its own CLI, `scancode --license`)
as an independent third-party comparison point -- separate from, and in
addition to, its use as our own agent's internal fallback engine (see
app/license_lookup.py's _run_scancode_fallback).

Unlike our agent's internal usage (which only ever hands ScanCode a
short metadata text snippet, for speed), this script gives ScanCode a
fair, full shot at each package's real files: real installed
.dist-info metadata directories for Python packages, and real unpacked
npm package directories for Node packages -- the way a team would
realistically use ScanCode standalone.

Methodology notes (see RESULTS.md for the full writeup):
  - Python packages: every .dist-info directory found after a real
    `pip install` is scanned in one batch (this naturally picks up
    transitive dependencies too, e.g. PyQt6 when pyspread is
    installed). The "correct license ID" signal is extracted
    specifically from each package's own METADATA file, not from
    COPYING/LICENSE/other files scanned -- this avoids counting a GPL
    mention found anywhere in bundled/vendored text as if it were the
    package's own top-level license (a real false-positive risk
    documented in RESULTS.md for numpy/scipy/pillow/django/docutils).
  - Node packages: ScanCode is pointed at the named package's own
    directory inside node_modules (full real source, including any
    bundled vendored files) -- NOT the entire node_modules tree, since
    that would scan every transitive dependency's full source too and
    take a very long time.

Usage:
    cd evaluation/license_compliance_baseline
    source .venv/bin/activate   # same venv as run_comparison.py
    pip install -r requirements.txt   # scancode-toolkit is already listed
    which scancode   # confirm it's actually on PATH before running
    python run_scancode_standalone.py

This takes several minutes end-to-end. ScanCode's own one-time
rules-index load costs several seconds per invocation, the ccnetviz
case scans real vendored third-party JS files bundled inside that
package (60-100+ seconds observed), and the large-scan case scans
~130 real metadata directories in one pass (~3 minutes observed).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
import venv
from pathlib import Path

from test_cases import (
    TEST_CASES,
    LARGE_SCAN_REQUIREMENTS_TXT,
    LARGE_SCAN_EXCLUDED_FROM_BASELINE_INSTALL,
)

SCANCODE_LICENSE_SCORE_THRESHOLD = 90.0  # only count a detection as "confident" at/above this


def _find_scancode() -> str:
    path = shutil.which("scancode")
    if path is None:
        print(
            "ERROR: 'scancode' not found on PATH. Install it with:\n"
            "  pip install -r requirements.txt\n"
            "(scancode-toolkit is already listed there), then confirm with: which scancode",
            file=sys.stderr,
        )
        sys.exit(1)
    return path


SCANCODE_BIN = _find_scancode()


def run_scancode(target_dir: Path, output_json: Path, relative_inputs: list[str] | None = None, cwd: Path | None = None) -> dict:
    """
    Runs `scancode --license` against target_dir, or against a list of
    relative_inputs inside cwd for multi-input scans (ScanCode requires
    relative paths when scanning more than one input at once -- this
    was discovered the hard way; passing absolute paths for multiple
    inputs fails with "all input paths must be relative"). Returns
    {"elapsed_seconds": float, "output_path": str} on success, or
    {"error": str} on failure. Never raises.
    """
    args = [SCANCODE_BIN, "--license", "--json-pp", str(output_json)]
    if relative_inputs is not None:
        args += relative_inputs
    else:
        args += [str(target_dir)]

    start = time.perf_counter()
    try:
        result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return {"error": "ScanCode timed out after 600s"}
    elapsed = time.perf_counter() - start

    if result.returncode != 0:
        return {"error": f"scancode exited {result.returncode}: {result.stderr.strip()[-500:]}"}
    if not output_json.exists():
        return {"error": "scancode ran but produced no output file", "stderr": result.stderr.strip()[-500:]}

    return {"elapsed_seconds": round(elapsed, 4), "output_path": str(output_json)}


def extract_metadata_level_licenses(scan_json_path: Path, dist_info_marker: str = ".dist-info") -> dict:
    """
    For Python packages: extracts, per package, the highest-confidence
    license detection found specifically in that package's own
    METADATA file -- the fair standalone-ScanCode equivalent of "what
    license does this package declare itself as."
    """
    data = json.loads(scan_json_path.read_text())
    per_package: dict[str, dict] = {}
    for f in data.get("files", []):
        parts = f.get("path", "").split("/")
        metadata_idx = None
        for i, part in enumerate(parts):
            if dist_info_marker in part and i + 1 < len(parts) and parts[i + 1] == "METADATA":
                metadata_idx = i
                break
        if metadata_idx is None:
            continue
        pkg = parts[metadata_idx].replace(dist_info_marker, "")
        dets = f.get("license_detections", [])
        if not dets:
            per_package.setdefault(pkg, {"expression": "NO DETECTION", "score": 0.0})
            continue
        best = max(dets, key=lambda dd: max((m.get("score", 0) for m in dd.get("matches", [])), default=0))
        score = max((m.get("score", 0) for m in best.get("matches", [])), default=0)
        prev = per_package.get(pkg)
        if prev is None or score > prev["score"]:
            per_package[pkg] = {"expression": best.get("license_expression_spdx"), "score": score}
    return per_package


def extract_all_file_licenses(scan_json_path: Path) -> list[dict]:
    """Raw, per-file detections -- used for the npm cases (no dist-info/METADATA structure to key off)."""
    data = json.loads(scan_json_path.read_text())
    out = []
    for f in data.get("files", []):
        for det in f.get("license_detections", []) or []:
            score = max((m.get("score", 0) for m in det.get("matches", [])), default=0)
            out.append({"path": f.get("path"), "expression": det.get("license_expression_spdx"), "score": score})
    return out


def scan_python_case(pip_install_targets: list[str], label: str) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        venv_dir = Path(tmpdir) / "venv"
        venv.create(venv_dir, with_pip=True)
        pip_bin = venv_dir / "bin" / "pip"

        install_start = time.perf_counter()
        install = subprocess.run(
            [str(pip_bin), "install", "--quiet", *pip_install_targets],
            capture_output=True, text=True, timeout=300,
        )
        install_elapsed = round(time.perf_counter() - install_start, 4)
        if install.returncode != 0:
            return {"label": label, "installed": False, "install_error": install.stderr.strip()[-500:]}

        site_packages_matches = list(venv_dir.glob("lib/python*/site-packages"))
        if not site_packages_matches:
            return {"label": label, "installed": True, "install_seconds": install_elapsed, "error": "site-packages not found"}
        site_packages = site_packages_matches[0]

        dist_infos = sorted(p.name for p in site_packages.glob("*.dist-info"))
        if not dist_infos:
            return {"label": label, "installed": True, "install_seconds": install_elapsed, "error": "no .dist-info dirs found"}

        output_json = Path(tmpdir) / "scan.json"
        scan_result = run_scancode(target_dir=site_packages, output_json=output_json, relative_inputs=dist_infos, cwd=site_packages)
        if "error" in scan_result:
            return {"label": label, "installed": True, "install_seconds": install_elapsed, **scan_result}

        per_package = extract_metadata_level_licenses(output_json)
        return {
            "label": label,
            "installed": True,
            "install_seconds": install_elapsed,
            "scan_seconds": scan_result["elapsed_seconds"],
            "total_seconds": round(install_elapsed + scan_result["elapsed_seconds"], 4),
            "dist_info_count": len(dist_infos),
            "per_package_metadata_license": per_package,
        }


def scan_node_case(npm_install_targets: list[str], package_dir_name: str, label: str) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        subprocess.run(["npm", "init", "-y"], cwd=tmpdir, capture_output=True, text=True, timeout=30)

        install_start = time.perf_counter()
        install = subprocess.run(
            ["npm", "install", *npm_install_targets],
            cwd=tmpdir, capture_output=True, text=True, timeout=180,
        )
        install_elapsed = round(time.perf_counter() - install_start, 4)
        if install.returncode != 0:
            return {"label": label, "installed": False, "install_error": install.stderr.strip()[-500:]}

        pkg_dir = Path(tmpdir) / "node_modules" / package_dir_name
        if not pkg_dir.exists():
            return {"label": label, "installed": True, "install_seconds": install_elapsed, "error": f"{pkg_dir} not found after install"}

        output_json = Path(tmpdir) / "scan.json"
        scan_result = run_scancode(target_dir=pkg_dir, output_json=output_json)
        if "error" in scan_result:
            return {"label": label, "installed": True, "install_seconds": install_elapsed, **scan_result}

        detections = extract_all_file_licenses(output_json)
        confident = [d for d in detections if d["score"] >= SCANCODE_LICENSE_SCORE_THRESHOLD]
        distinct_expressions = sorted({d["expression"] for d in confident if d["expression"]})
        return {
            "label": label,
            "installed": True,
            "install_seconds": install_elapsed,
            "scan_seconds": scan_result["elapsed_seconds"],
            "total_seconds": round(install_elapsed + scan_result["elapsed_seconds"], 4),
            "files_with_detections": len(detections),
            "distinct_confident_expressions": distinct_expressions,
        }


def scan_large_case() -> dict:
    installable_lines = [
        line for line in LARGE_SCAN_REQUIREMENTS_TXT.splitlines()
        if line.strip() and line.strip() not in LARGE_SCAN_EXCLUDED_FROM_BASELINE_INSTALL
    ]
    result = scan_python_case(installable_lines, label="Large scan (53 installable packages)")
    if result.get("per_package_metadata_license"):
        gpl_family = {
            pkg: v for pkg, v in result["per_package_metadata_license"].items()
            if isinstance(v.get("expression"), str) and "GPL" in v["expression"]
        }
        result["gpl_family_packages_at_metadata_level"] = gpl_family
    return result


def main():
    print(f"Using scancode binary: {SCANCODE_BIN}\n")

    for case in TEST_CASES:
        print(f"\n{'=' * 70}\n{case['name']}\n{'=' * 70}")
        if case["ecosystem"] == "python":
            if "pip_install_targets" not in case:
                print("(skipped -- no pip_install_targets for this case)")
                continue
            result = scan_python_case(case["pip_install_targets"], label=case["name"])
        elif case["ecosystem"] == "node":
            pkg_name = case["npm_install_targets"][0].split("@")[0]
            result = scan_node_case(case["npm_install_targets"], pkg_name, label=case["name"])
        else:
            continue
        print(json.dumps(result, indent=2, default=str))

    print(f"\n{'=' * 70}\nLarge scan (55-dependency manifest, 53 installable)\n{'=' * 70}")
    large_result = scan_large_case()
    summary = {k: v for k, v in large_result.items() if k != "per_package_metadata_license"}
    summary["total_packages_scanned"] = len(large_result.get("per_package_metadata_license", {}))
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()