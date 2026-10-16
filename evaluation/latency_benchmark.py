"""
End-to-end latency benchmark for the Trust Engine.

Measures p50 and p95 wall-clock latency per artifact type, plus per-agent
elapsed_ms where the agent reports it. Project doc section 4 states an
under-three-second target for the synchronous path; section 8 commits to
reporting p50/p95 per agent. This produces both.

Latency is measured per artifact type rather than as a single figure
because routing now dispatches a different agent set per type: a code
file calls three agents, a dependency manifest calls three different
ones. A single aggregate number would average over paths that have
little to do with each other.

Usage, with the stack up:

    python latency_benchmark.py                 # 30 runs per type
    python latency_benchmark.py --runs 50
    python latency_benchmark.py --url http://localhost:8000/analyze

A short warm-up runs first and is excluded from the statistics: the
first call after container start pays one-off costs (Semgrep rule
compilation, model loading) that are not representative of steady state.
"""

from __future__ import annotations

import argparse
import json
import statistics
import math
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from guardian_http import wait_final
import time
import urllib.error
import urllib.request

DEFAULT_URL = "http://localhost:8000/analyze"
WARMUP_RUNS = 3

# One artifact per type. Each is deliberately small: the aim is to measure
# orchestration and agent overhead, not parsing throughput on a large file.
ARTIFACTS = {
    "code": {
        "type": "code",
        "filename": "app.py",
        "content": (
            "import os\n"
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            "def run(target):\n"
            '    os.system("tar -czf b.tar.gz " + target)\n'
        ),
    },
    "dockerfile": {
        "type": "dockerfile",
        "filename": "Dockerfile",
        "content": "FROM ubuntu:latest\nUSER root\nEXPOSE 22\nRUN apt-get update\n",
    },
    "workflow": {
        "type": "workflow",
        "filename": "deploy.yml",
        "content": (
            "on:\n  pull_request_target:\n    branches: [main]\n"
            "permissions: write-all\njobs:\n  build:\n    steps:\n"
            "      - uses: some-org/action@main\n"
            "      - run: curl -sSL https://get.sh | bash\n"
        ),
    },
    "dependency": {
        "type": "dependency",
        "filename": "requirements.txt",
        "content": "requests==2.31.0\nparamiko==3.4.0\nrequets==1.0.0\n",
    },
}


def percentile(values: list[float], p: float) -> float:
    """Nearest-rank percentile.

    Chosen over interpolation because it always returns a latency that
    was actually observed, which is easier to defend than a synthesised
    value when the sample is small.
    """
    if not values:
        return 0.0
    if not 0<=p<=100: raise ValueError("percentile must be 0–100")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(p / 100 * len(ordered)) - 1))
    return ordered[index]


def call(url: str, artifact: dict, timeout: float = 60.0) -> tuple[float, dict]:
    """POST one artifact, returning (wall-clock ms, parsed response)."""
    payload = json.dumps(artifact).encode("utf-8")
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    started = time.perf_counter()
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read())
    return (time.perf_counter() - started) * 1000.0, body


def agent_timings(body: dict) -> dict[str, float]:
    """Pull per-agent elapsed_ms out of a response, where reported.

    Agents report their own timing inconsistently -- some use
    execution_time_ms in evidence, some elapsed_ms, some report nothing.
    Whatever is found is recorded; absence is reported rather than
    guessed at.
    """
    timings: dict[str, float] = {}
    for result in body.get("detector_results", []):
        evidence = result.get("evidence") or {}
        for key in ("execution_time_ms", "elapsed_ms"):
            if key in evidence:
                timings[result["agent_name"]] = float(evidence[key])
                break
    return timings


def summarise(label: str, samples: list[float], agents: dict[str, list[float]],
              called: list[str], target_ms: float) -> None:
    p50 = percentile(samples, 50)
    p95 = percentile(samples, 95)
    verdict = "within target" if p95 < target_ms else "EXCEEDS target"

    print(f"\n  {label}")
    print(f"    agents called : {', '.join(called) if called else 'none'}")
    print(f"    runs          : {len(samples)}")
    print(f"    min / max     : {min(samples):8.1f} / {max(samples):8.1f} ms")
    print(f"    mean          : {statistics.fmean(samples):8.1f} ms")
    print(f"    p50           : {p50:8.1f} ms")
    print(f"    p95           : {p95:8.1f} ms   ({verdict} of {target_ms:.0f} ms)")

    if agents:
        print("    per-agent elapsed_ms (p50 / p95):")
        for name in sorted(agents):
            values = agents[name]
            print(f"      {name:20} {percentile(values, 50):8.1f} / "
                  f"{percentile(values, 95):8.1f}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--wait-seconds", type=float, default=240)
    parser.add_argument("--target-ms", type=float, default=3000.0)
    parser.add_argument("--types", nargs="*", default=list(ARTIFACTS))
    args = parser.parse_args()
    if args.runs<1 or args.wait_seconds<=0: parser.error("runs and wait-seconds must be positive")

    print("Trust Engine end-to-end latency benchmark")
    print(f"  endpoint : {args.url}")
    print(f"  runs     : {args.runs} per artifact type "
          f"(plus {WARMUP_RUNS} warm-up runs, excluded)")
    print(f"  target   : under {args.target_ms:.0f} ms, project doc section 4")

    all_samples: list[float] = []
    all_errors = 0
    all_degraded = 0

    for label in args.types:
        artifact = ARTIFACTS.get(label)
        if artifact is None:
            print(f"\n  {label}: unknown artifact type, skipped")
            continue

        try:
            for _ in range(WARMUP_RUNS):
                _,warm = call(args.url, artifact, timeout=10)
                wait_final(args.url.rsplit('/analyze',1)[0], warm, args.wait_seconds)
        except Exception as exc:
            print(f"\n  Cannot reach {args.url}: {exc}")
            print("  Is the stack up? docker compose up -d")
            return

        final_samples: list[float] = []
        errors = 0
        provisional = 0
        degraded = 0
        samples: list[float] = []
        agents: dict[str, list[float]] = {}
        called: list[str] = []

        for _ in range(args.runs):
            started=time.perf_counter()
            try:
                elapsed, body = call(args.url, artifact, timeout=10)
                samples.append(elapsed)
                provisional += body.get("scan_status") == "provisional"
                body = wait_final(args.url.rsplit('/analyze',1)[0], body, args.wait_seconds)
                final_samples.append((time.perf_counter()-started)*1000)
                degraded += any(r.get("status") in {"error","stub","pending"} or r.get("unresolved") for r in body.get("detector_results",[]))
            except Exception as exc:
                errors += 1
                print(f"    request/finalization failed: {type(exc).__name__}: {exc}")
                continue
            if not called:
                called = [r["agent_name"] for r in body.get("detector_results", [])]
            for name, value in agent_timings(body).items():
                agents.setdefault(name, []).append(value)

        all_samples.extend(samples)
        all_errors += errors
        all_degraded += degraded
        print(f"    errors: {errors}; provisional initial: {provisional}; incomplete/degraded final: {degraded}")
        if samples: summarise(label + " initial response", samples, agents, called, args.target_ms)
        if final_samples: summarise(label + " time to final (including callbacks/polling)", final_samples, {}, called, args.target_ms)

    if all_samples:
        print("\n  ---")
        print(f"  All artifact types combined ({len(all_samples)} runs)")
        print(f"    p50 : {percentile(all_samples, 50):8.1f} ms")
        print(f"    p95 : {percentile(all_samples, 95):8.1f} ms")
        met = percentile(all_samples, 95) < args.target_ms and not all_errors and not all_degraded
        print(f"    Failed requests: {all_errors}; incomplete/degraded finals: {all_degraded}")
        print(f"    Successful-response initial p95 target {'observed' if met else 'NOT established'}; this is not a production latency guarantee.")
        print("\n  Note: these figures are for a single concurrent request.")
        print("  Latency under concurrent load is a separate measurement and")
        print("  degrades non-linearly where an agent spawns a subprocess per call.")


if __name__ == "__main__":
    main()