"""
Side-by-side comparison across 4 tools against the same 6 test cases:
  - Our agent (the real, running services/prompt_injection service, via HTTP)
  - llm-guard's PromptInjection scanner (real classifier model)
  - Rebuff's heuristic-only detector (real, local, no API key needed --
    see notes below on why only this one of Rebuff's 3 checks is used)
  - Vigil-LLM's bundled YARA rules (real, local -- see notes below on
    why we use the raw rule files directly rather than the full Vigil
    app class)

Usage:
    1. In one terminal, have the real service running:
         cd services/prompt_injection
         source .venv/bin/activate
         uvicorn app.main:app --reload --port 8000

    2. Get Vigil-LLM's YARA rules (small, local, no install needed):
         git clone https://github.com/deadbits/vigil-llm.git vendor/vigil-llm

    3. In another terminal, from this evaluation folder:
         pip install -r requirements.txt
         python run_comparison.py

Notes on partial/adapted tool usage (documented here, not silently
worked around):

- llm-guard: used as intended, its actual PromptInjection scanner
  against the raw content. Requires real internet access to
  huggingface.co to download the classifier model on first run.

- Rebuff: its full SDK (RebuffSdk.detect_injection) requires an OpenAI
  API key AND a Pinecone vector database API key/environment for its
  other two checks (LLM-based and vector-similarity-based). Neither
  was available. Rebuff DOES ship a fully local, no-API-key heuristic
  function (rebuff.detect_pi_heuristics.detect_prompt_injection_using_heuristic_on_input),
  used here directly. This is a real, documented, standalone component
  of the library -- not a workaround -- but it means we are testing
  ONE of Rebuff's three detection layers, not the full product.

- Vigil-LLM: is not on PyPI under any working package name ("vigil-llm"
  doesn't exist on PyPI; plain "vigil" on PyPI is an unrelated,
  different package entirely -- a Python testing tool, not a security
  scanner). The real project must be cloned from GitHub. Its main
  `Vigil` class unconditionally initializes a vector database and an
  embedder in its constructor (see vigil/vigil.py), even if you only
  want the YARA scanner -- this requires either an OpenAI API key or a
  local sentence-transformers model download from huggingface.co,
  neither of which was available in a way that let us stand up the
  full app. Vigil DOES ship its YARA rule files as plain, standalone
  data files (data/yara/*.yar) that can be loaded directly with the
  `yara` library with no other dependency, which is what this script
  does. This tests Vigil's YARA/heuristic layer only, not its vector
  database or transformer-model layers.
"""

from __future__ import annotations

import os
import statistics
import time

import requests

from test_cases import TEST_CASES

OUR_AGENT_URL = "http://127.0.0.1:8000/analyze"
VIGIL_YARA_RULES_DIR = os.path.join("vendor", "vigil-llm", "data", "yara")
REBUFF_HEURISTIC_THRESHOLD = 0.75  # Rebuff SDK's own documented default for max_heuristic_score


# --- Our agent -----------------------------------------------------------

def run_our_agent(case: dict):
    payload = {"type": case["type"], "filename": case["filename"], "content": case["content"]}
    try:
        start = time.perf_counter()
        response = requests.post(OUR_AGENT_URL, json=payload, timeout=120)
        elapsed_ms = (time.perf_counter() - start) * 1000
        response.raise_for_status()
        data = response.json()
        status = data.get("status")
        findings = data.get("findings", [])
        flagged = status == "fail" or status == "warn"
        top_conf = max((f.get("confidence", 0) for f in findings), default=0.0)
        return {"flagged": flagged, "score": top_conf, "elapsed_ms": elapsed_ms, "error": None}
    except requests.exceptions.ConnectionError:
        return {"flagged": None, "score": None, "elapsed_ms": None,
                 "error": f"Could not connect to {OUR_AGENT_URL} -- start the service first."}
    except Exception as exc:  # noqa: BLE001
        return {"flagged": None, "score": None, "elapsed_ms": None, "error": f"{type(exc).__name__}: {exc}"}


# --- llm-guard -------------------------------------------------------------

_llm_guard_scanner = None

def run_llm_guard(content: str):
    global _llm_guard_scanner
    try:
        from llm_guard.input_scanners import PromptInjection
    except ImportError as exc:
        return {"flagged": None, "score": None, "elapsed_ms": None, "error": f"not installed: {exc}"}

    try:
        if _llm_guard_scanner is None:
            _llm_guard_scanner = PromptInjection()
        start = time.perf_counter()
        _sanitized, is_valid, risk_score = _llm_guard_scanner.scan(content)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return {"flagged": not is_valid, "score": risk_score, "elapsed_ms": elapsed_ms, "error": None}
    except Exception as exc:  # noqa: BLE001
        return {"flagged": None, "score": None, "elapsed_ms": None, "error": f"{type(exc).__name__}: {exc}"}


# --- Rebuff (heuristic-only, see module docstring) --------------------------

def run_rebuff(content: str):
    try:
        from rebuff.detect_pi_heuristics import detect_prompt_injection_using_heuristic_on_input
    except ImportError as exc:
        return {"flagged": None, "score": None, "elapsed_ms": None, "error": f"not installed: {exc}"}

    try:
        start = time.perf_counter()
        score = detect_prompt_injection_using_heuristic_on_input(content)
        elapsed_ms = (time.perf_counter() - start) * 1000
        flagged = score > REBUFF_HEURISTIC_THRESHOLD
        return {"flagged": flagged, "score": score, "elapsed_ms": elapsed_ms, "error": None}
    except Exception as exc:  # noqa: BLE001
        return {"flagged": None, "score": None, "elapsed_ms": None, "error": f"{type(exc).__name__}: {exc}"}


# --- Vigil-LLM (YARA rules only, see module docstring) -----------------------

_vigil_compiled_rules = None

def run_vigil(content: str):
    global _vigil_compiled_rules
    try:
        import yara
    except ImportError as exc:
        return {"flagged": None, "score": None, "elapsed_ms": None, "error": f"yara-python not installed: {exc}"}

    if not os.path.isdir(VIGIL_YARA_RULES_DIR):
        return {"flagged": None, "score": None, "elapsed_ms": None,
                 "error": f"Vigil rules not found at {VIGIL_YARA_RULES_DIR} -- clone vigil-llm first, see module docstring."}

    try:
        if _vigil_compiled_rules is None:
            yara_paths = {
                f: os.path.join(VIGIL_YARA_RULES_DIR, f)
                for f in os.listdir(VIGIL_YARA_RULES_DIR)
                if f.endswith((".yar", ".yara"))
            }
            _vigil_compiled_rules = yara.compile(filepaths=yara_paths)

        start = time.perf_counter()
        matches = _vigil_compiled_rules.match(data=content)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return {"flagged": len(matches) > 0, "score": len(matches), "elapsed_ms": elapsed_ms,
                 "error": None, "matched_rules": [m.rule for m in matches]}
    except Exception as exc:  # noqa: BLE001
        return {"flagged": None, "score": None, "elapsed_ms": None, "error": f"{type(exc).__name__}: {exc}"}


# --- Metrics ---------------------------------------------------------------

def compute_metrics(results: list[dict]):
    """
    results: one dict per test case, in TEST_CASES order, each with a
    "flagged" key (True/False/None). Case 0 (index 0) is the sole
    true-negative case; cases 1-5 are true-positive cases.
    """
    if any(r["flagged"] is None for r in results):
        return None  # can't compute metrics if any case errored out

    tp = sum(1 for r in results[1:] if r["flagged"])
    fn = sum(1 for r in results[1:] if not r["flagged"])
    tn = 1 if not results[0]["flagged"] else 0
    fp = 1 if results[0]["flagged"] else 0

    precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
    recall = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) > 0 else float("nan")
    latencies = [r["elapsed_ms"] for r in results if r["elapsed_ms"] is not None]
    avg_latency = statistics.mean(latencies) if latencies else float("nan")
    obfuscated_catch = results[2]["flagged"]  # case index 2 = "3_obfuscated_spaced_keyword"

    return {
        "precision": precision, "recall": recall, "fpr": fpr,
        "avg_latency_ms": avg_latency, "obfuscated_catch": obfuscated_catch,
        "tp": tp, "fn": fn, "tn": tn, "fp": fp,
    }


def main():
    tools = {
        "Our Agent": run_our_agent,
        "llm-guard": lambda case: run_llm_guard(case["content"]),
        "Rebuff": lambda case: run_rebuff(case["content"]),
        "Vigil-LLM (YARA)": lambda case: run_vigil(case["content"]),
    }

    all_results = {name: [] for name in tools}

    print(f"{'Case':35}", end="")
    for name in tools:
        print(f"{name:22}", end="")
    print()
    print("-" * (35 + 22 * len(tools)))

    for case in TEST_CASES:
        print(f"{case['name']:35}", end="")
        for name, fn in tools.items():
            result = fn(case)
            all_results[name].append(result)
            if result["error"]:
                cell = f"ERROR"
            else:
                cell = f"{'FLAG' if result['flagged'] else 'ok'} ({result['score']}, {result['elapsed_ms']:.0f}ms)" if result["elapsed_ms"] is not None else f"{'FLAG' if result['flagged'] else 'ok'}"
            print(f"{cell:22}", end="")
        print()

    print()
    print("=" * 100)
    print("QUANTITATIVE METRICS (preliminary, n=6 -- see RESULTS.md caveat)")
    print("=" * 100)
    print(f"{'Tool':20} {'Precision':>10} {'Recall':>10} {'FPR':>8} {'AvgLatMs':>10} {'ObfCatch':>10}")
    for name, results in all_results.items():
        m = compute_metrics(results)
        if m is None:
            print(f"{name:20} could not compute metrics -- one or more cases errored, see table above")
            continue
        print(f"{name:20} {m['precision']:>10.2f} {m['recall']:>10.2f} {m['fpr']:>8.2f} "
              f"{m['avg_latency_ms']:>10.1f} {str(m['obfuscated_catch']):>10}")

    print()
    print("Full raw detail (for RESULTS.md):")
    for name, results in all_results.items():
        print(f"\n{name}:")
        for case, result in zip(TEST_CASES, results):
            print(f"  {case['name']}: {result}")


if __name__ == "__main__":
    main()