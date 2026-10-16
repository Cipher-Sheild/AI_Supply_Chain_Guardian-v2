"""
Stage 1 — license identification.

Design decision (documented per project doc §3 — "this is a genuine
design decision, not a settled one")
------------------------------------------------------------------------
ScanCode-toolkit is built to scan actual file/source content, not a bare
"package name + version". Downloading and unpacking every dependency's
full source distribution just to identify its license would be both slow
(directly working against the "time of execution matters a lot"
requirement) and, for this pass, unnecessary: package registries already
carry a structured declared-license field.

So the approach here is two-tier:

  Fast path  — query the package registry's JSON API (PyPI / npm) for
               the package's declared license metadata. For PyPI this
               strongly prefers the Trove classifiers
               ("License :: OSI Approved :: MIT License") over the
               freeform `info.license` string, since classifiers are a
               controlled vocabulary and the freeform field is
               frequently empty, wrong, or holds prose instead of an
               identifier. For npm, the registry's `license` field
               supports SPDX expressions directly (npm >=5) or the
               legacy `licenses` array.

  Fallback   — when the fast path yields nothing usable (missing,
               empty, or text we can't confidently normalize to SPDX),
               we still use ScanCode's Python API (not subprocess/CLI)
               as the identification engine: whatever free-text license
               string we *did* get (however messy) is written to a
               temporary file and passed to
               `scancode.api.get_licenses()`, which runs ScanCode's real
               license-detection engine against it and returns SPDX
               matches with confidence scores. This is deliberately a
               text-level fallback, not a full source-tree scan — see
               README "Known limitations" for why full sdist/tarball
               scanning was judged out of scope for this pass, and what
               a real "deep scan" upgrade would look like.

If the team lead's clarification (mentioned in the implementation
prompt) turns out to want ScanCode's source vendored into this repo
rather than pip-installed, only `_run_scancode_fallback`'s import needs
to change — the rest of the pipeline is unaffected.
"""

from __future__ import annotations

from app.license_expression import parse_expression, render
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("license_compliance.license_lookup")

_SCANCODE_IMPORT_ERROR: Optional[str] = None
try:
    if os.getenv('GUARDIAN_EXTERNAL_SCANNERS','false').lower()!='true':
        raise ImportError('external scanners disabled')
    from scancode.api import get_licenses as _scancode_get_licenses  # type: ignore
except Exception as exc:  # noqa: BLE001 — scancode-toolkit is a heavy optional dependency
    _scancode_get_licenses = None
    _SCANCODE_IMPORT_ERROR = str(exc)


@dataclass
class LicenseResult:
    spdx_expressions: list[str] = field(default_factory=list)  # e.g. ["MIT"] or ["MIT", "Apache-2.0"] for dual
    expression_tree: Optional[dict] = None
    expression_op: Optional[str] = None  # "OR" | "AND" | None (single license)
    source: str = "unknown"  # "registry_classifier" | "registry_field" | "scancode_fallback" | "unknown"
    confidence: float = 0.0
    raw_license_text: Optional[str] = None
    declared_transitive_names: list[str] = field(default_factory=list)  # best-effort, names only
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# SPDX normalization
# ---------------------------------------------------------------------------

# Common free-text / classifier license strings -> normalized SPDX id.
# Not exhaustive by design (see README) — covers the licenses that
# actually show up across the vast majority of PyPI/npm packages.
_SPDX_ALIASES: dict[str, str] = {
    "mit": "MIT",
    "mit license": "MIT",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "simplified bsd license": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "isc": "ISC",
    "isc license": "ISC",
    "python software foundation license": "PSF-2.0",
    "mpl-2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "lgpl-2.1": "LGPL-2.1-only",
    "gnu lesser general public license v2.1": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "gnu lesser general public license v3": "LGPL-3.0-only",
    "gpl-2.0": "GPL-2.0-only",
    "gnu general public license v2": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gnu general public license v3": "GPL-3.0-only",
    "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gnu general public license v3 or later": "GPL-3.0-or-later",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.0-or-later",
    "gplv3": "GPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "gnu affero general public license v3": "AGPL-3.0-only",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "public domain": "Unlicense",
    "0bsd": "0BSD",
    "wtfpl": "WTFPL",
    "cc0-1.0": "CC0-1.0",
    # Already-valid SPDX ids seen verbatim in real PyPI classifiers/fields
    # (added after checking live PyPI data against ~90 common packages —
    # see conversation history for the batch check) — these packages
    # state a specific, unambiguous SPDX id directly, so no "family"
    # guessing is involved, just recognizing the id as itself.
    "mit-cmu": "MIT-CMU",
    "mit-0": "MIT-0",
    "zpl-2.1": "ZPL-2.1",
    "zpl-2.0": "ZPL-2.0",
    "3-clause bsd license": "BSD-3-Clause",
}

# Free-text strings that are inherently ambiguous or mean "no real open
# license" — always routed to needs_review rather than guessed at.
_AMBIGUOUS_OR_PROPRIETARY = {
    "bsd",  # could be 2-clause, 3-clause, or 4-clause — materially different obligations
    "bsd license",
    "unlicensed",  # npm convention: "you may NOT use this without permission" — opposite of Unlicense
    "proprietary",
    "unknown",
    "",
}

_PYPI_CLASSIFIER_RE = re.compile(r"^License :: OSI Approved(?:\s*::\s*(.+))?$")


_TRAILING_PARENS_RE = re.compile(r"\s*\([^)]*\)\s*$")


def _normalize_single(text: str) -> Optional[str]:
    """Best-effort normalization of one free-text license string to an SPDX id."""
    if not text:
        return None
    key = text.strip().lower().rstrip(".")
    if key in _AMBIGUOUS_OR_PROPRIETARY:
        return None
    if key in _SPDX_ALIASES:
        return _SPDX_ALIASES[key]
    # PyPI classifiers commonly carry a trailing abbreviation in
    # parens, e.g. "GNU General Public License v3 (GPLv3)" -- strip it
    # and retry before giving up.
    stripped_parens = _TRAILING_PARENS_RE.sub("", key).strip()
    if stripped_parens and stripped_parens in _SPDX_ALIASES:
        return _SPDX_ALIASES[stripped_parens]
    # Already looks like a valid-ish SPDX id (e.g. "MIT", "Apache-2.0" typed directly).
    if re.match(r"^[A-Za-z0-9.\-]+$", text.strip()) and any(
        text.strip().lower() == v.lower() for v in _SPDX_ALIASES.values()
    ):
        return text.strip()
    return None


def _split_expression(text: str) -> tuple[list[str], Optional[str]]:
    """
    Split an SPDX-style expression ("MIT OR Apache-2.0") into parts + operator.

    Deliberately case-SENSITIVE: real SPDX license-expression syntax
    requires the operators literally uppercase ("OR"/"AND"). Matching
    case-insensitively was a real bug -- it misfired on ordinary English
    phrasing like "GNU Lesser General Public License v2 or later",
    incorrectly splitting a single license name in two at the word "or"
    (found via live testing against pygobject's real PyPI classifier).
    """
    if " OR " in text:
        parts = re.split(r"\s+OR\s+", text)
        return [p.strip() for p in parts], "OR"
    if " AND " in text:
        parts = re.split(r"\s+AND\s+", text)
        return [p.strip() for p in parts], "AND"
    return [text.strip()], None


def normalize_license_text(raw_texts: list[str]) -> tuple[list[str], Optional[str], list[str]]:
    """
    Normalize one or more raw license strings (e.g. several PyPI
    classifiers, or a single npm license field) into a list of SPDX
    ids + an operator describing how they combine, plus any strings
    that couldn't be normalized (returned as warnings).

    Multiple *separate* input strings (e.g. two classifiers) are always
    treated as dual-licensing alternatives ("OR") — that's what it
    means for a package to carry more than one OSI-approved classifier.
    A single input string containing an explicit " OR "/" AND " is
    parsed as an SPDX expression.
    """
    if not raw_texts:
        return [], None, []
    converted = [_normalize_single(t) or t.strip() for t in raw_texts]
    expression = " OR ".join(f"({t})" for t in converted) if len(converted) > 1 else converted[0]
    try:
        tree = parse_expression(expression, _normalize_single)
    except ValueError:
        return [expression], None, [expression]
    def unknown(node):
        if node["op"] == "license": return [] if node["known"] else [node["id"]]
        if node["op"] == "WITH": return [render(node)]
        return [v for c in node["children"] for v in unknown(c)]
    # Retain every node including unrecognized required branches.
    if tree["op"] in {"AND", "OR"} and all(c["op"] == "license" for c in tree["children"]):
        return list(dict.fromkeys(c["id"] for c in tree["children"])), tree["op"], unknown(tree)
    return [render(tree)], None, unknown(tree)


# ---------------------------------------------------------------------------
# Registry metadata fetchers
# ---------------------------------------------------------------------------

async def _fetch_pypi_metadata(client: httpx.AsyncClient, name: str, version: Optional[str]) -> Optional[dict]:
    url = f"https://pypi.org/pypi/{name}/{version}/json" if version else f"https://pypi.org/pypi/{name}/json"
    try:
        resp = await client.get(url, timeout=8.0)
        if resp.status_code != 200:
            return None
        return resp.json()
    except (httpx.HTTPError, ValueError):
        return None


def _license_from_pypi_payload(payload: dict) -> tuple[list[str], str, Optional[str]]:
    """Returns (raw_license_texts, source_label, raw_license_field_for_evidence)."""
    info = payload.get("info", {}) or {}

    # PEP 639's `license_expression` (newer metadata field, populated by
    # recently-published packages using core-metadata >=2.4) already IS
    # a valid SPDX expression -- prefer it outright when present, since
    # it's more reliable than either classifiers or the legacy freeform
    # `license` field.
    license_expression = (info.get("license_expression") or "").strip()
    if license_expression:
        return [license_expression], "registry_classifier", license_expression

    classifiers = info.get("classifiers", []) or []
    osi_classifiers = []
    for c in classifiers:
        m = _PYPI_CLASSIFIER_RE.match(c)
        if m and m.group(1):
            osi_classifiers.append(m.group(1))
    if osi_classifiers:
        return osi_classifiers, "registry_classifier", info.get("license")
    freeform = (info.get("license") or "").strip()
    if freeform:
        return [freeform], "registry_field", freeform
    return [], "registry_field", freeform or None


def _declared_deps_from_pypi_payload(payload: dict, limit: int = 15) -> list[str]:
    """Best-effort direct sub-dependency names, for the basic transitive check."""
    info = payload.get("info", {}) or {}
    requires = info.get("requires_dist") or []
    names: list[str] = []
    for entry in requires:
        if not entry:
            continue
        if ";" in entry and "extra ==" in entry:
            continue  # skip optional/extras-only sub-dependencies
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", entry)
        if m:
            names.append(m.group(1))
        if len(names) >= limit:
            break
    return names


async def _fetch_npm_metadata(client: httpx.AsyncClient, name: str, version: Optional[str]) -> Optional[dict]:
    encoded_name = name.replace("/", "%2F")
    url = f"https://registry.npmjs.org/{encoded_name}/{version}" if version else f"https://registry.npmjs.org/{encoded_name}/latest"
    try:
        resp = await client.get(url, timeout=8.0)
        if resp.status_code != 200:
            return None
        return resp.json()
    except (httpx.HTTPError, ValueError):
        return None


def _license_from_npm_payload(payload: dict) -> tuple[list[str], str, Optional[str]]:
    license_field = payload.get("license")
    if isinstance(license_field, str) and license_field.strip():
        return [license_field.strip()], "registry_field", license_field.strip()
    legacy = payload.get("licenses")  # older convention: [{"type": "MIT", ...}, ...]
    if isinstance(legacy, list) and legacy:
        types = [entry.get("type", "").strip() for entry in legacy if isinstance(entry, dict) and entry.get("type")]
        if types:
            return types, "registry_field", ", ".join(types)
    return [], "registry_field", None


def _declared_deps_from_npm_payload(payload: dict, limit: int = 15) -> list[str]:
    deps = payload.get("dependencies")
    if not isinstance(deps, dict):
        return []
    return list(deps.keys())[:limit]


# ---------------------------------------------------------------------------
# ScanCode fallback (Python API, not CLI/subprocess)
# ---------------------------------------------------------------------------

def _run_scancode_fallback(text: str) -> tuple[list[str], Optional[str], float, list[str]]:
    """
    Run ScanCode's real license-detection engine, via its Python API,
    against whatever free-text license string we have. Returns
    (spdx_ids, operator, confidence, warnings).

    This is intentionally a text-level fallback (see module docstring)
    -- it gives ScanCode's actual detection logic a shot at strings the
    registry-metadata fast path couldn't normalize (typos, unusual
    phrasing, "SEE LICENSE IN LICENSE.md", etc.), without paying the
    cost of downloading and scanning full package source for every
    dependency on every request.
    """
    if _scancode_get_licenses is None:
        return [], None, 0.0, [
            f"ScanCode-toolkit not available ({_SCANCODE_IMPORT_ERROR}); "
            "classified from registry metadata only."
        ]
    if not text or not text.strip():
        return [], None, 0.0, ["No license text available to scan."]

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".LICENSE", delete=False, encoding="utf-8") as tmp:
            tmp.write(text)
            tmp_path = tmp.name
        try:
            result = _scancode_get_licenses(tmp_path)
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001 — never let a scanner crash take the request down
        logger.warning("ScanCode fallback scan failed: %s", exc)
        return [], None, 0.0, [f"ScanCode scan failed: {exc}"]

    detections = result.get("license_detections") or result.get("licenses") or []
    spdx_ids: list[str] = []
    for detection in detections:
        expr = detection.get("license_expression_spdx") or detection.get("spdx_license_key")
        if expr:
            if expr not in spdx_ids: spdx_ids.append(expr)

    if not spdx_ids:
        return [], None, 0.0, ["ScanCode ran but found no confident license match in the available text."]

    # Confidence basis: prefer ScanCode's own `percentage_of_license_text`
    # (how much of the text we handed it was actually explained by a
    # license match) over picking a single match's `score` — that field
    # lives nested inside each detection's `matches` list, not on the
    # detection itself (a bug fixed here after inspecting ScanCode
    # 32.5's real output directly), and even when read correctly, a
    # single match's own score can be misleadingly high on a short,
    # low-coverage hit (e.g. a keyword-only "aho" match). The overall
    # text-coverage percentage is a steadier signal for a short
    # free-text fallback scan like this one.
    overall_percentage = result.get("percentage_of_license_text")
    if overall_percentage is None:
        # Older/different ScanCode output shapes: fall back to the best
        # single match score we can find across all detections.
        all_scores = [
            m.get("score", 0.0)
            for d in detections
            for m in (d.get("matches") or [])
            if isinstance(m, dict)
        ]
        overall_percentage = max(all_scores) if all_scores else 0.0

    # ScanCode's percentage is 0-100; normalize to 0-1 and scale down a
    # bit relative to a clean registry-classifier match, since this is
    # a text snippet rather than a full licensed file/source scan.
    confidence = round(min(float(overall_percentage) / 100.0, 1.0) * 0.75, 2)
    full_expression = result.get("detected_license_expression_spdx")
    if full_expression:
        spdx_ids, op, unmatched = normalize_license_text([full_expression])
        return spdx_ids, op, confidence, unmatched
    expression = " AND ".join(f"({expr})" for expr in spdx_ids)
    ids, op, unknown = normalize_license_text([expression])
    return ids, op, confidence, unknown


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

async def identify_license(client: httpx.AsyncClient, name: str, version: Optional[str], ecosystem: str) -> LicenseResult:
    if ecosystem == "python":
        payload = await _fetch_pypi_metadata(client, name, version)
        if payload is None:
            return LicenseResult(source="unknown", confidence=0.0, warnings=[f"Could not reach PyPI for '{name}'."])
        raw_texts, source, raw_field = _license_from_pypi_payload(payload)
        transitive = _declared_deps_from_pypi_payload(payload)
    elif ecosystem == "node":
        payload = await _fetch_npm_metadata(client, name, version)
        if payload is None:
            return LicenseResult(source="unknown", confidence=0.0, warnings=[f"Could not reach npm registry for '{name}'."])
        raw_texts, source, raw_field = _license_from_npm_payload(payload)
        transitive = _declared_deps_from_npm_payload(payload)
    elif ecosystem in {'rust','go'}:
        from app.registry_metadata import metadata
        result=await metadata(client,ecosystem,name,version or '')
        if result['status']!=200:
            return LicenseResult(source='unknown',confidence=0,warnings=['Public registry metadata unavailable or version unresolved.'])
        raw_field=result.get('license');raw_texts=[raw_field] if raw_field else [];source='registry_field';transitive=[]
    else:
        return LicenseResult(source="unknown", confidence=0.0, warnings=[f"Unsupported ecosystem '{ecosystem}'."])

    spdx_ids, op, unmatched = normalize_license_text(raw_texts)

    if spdx_ids:
        confidence = 1.0 if source == "registry_classifier" else 0.85
        if op:  # dual/multi-license — genuinely more ambiguous for policy purposes
            confidence = round(confidence * 0.9, 2)
        return LicenseResult(
            spdx_expressions=spdx_ids,
            expression_tree=_tree_for(spdx_ids, op),
            expression_op=op,
            source=source,
            confidence=confidence,
            raw_license_text=raw_field,
            declared_transitive_names=transitive,
            warnings=[f"Could not normalize additional text: {u!r}" for u in unmatched],
        )

    # Fast path found nothing usable — fall back to ScanCode on whatever
    # raw text we have (may be empty, in which case ScanCode will say so).
    fallback_text = raw_field or (raw_texts[0] if raw_texts else "")
    external=os.getenv('GUARDIAN_EXTERNAL_SCANNERS','false').lower()=='true'
    from app.native_license import identify_text
    spdx_ids, op, confidence, warnings = (_run_scancode_fallback if external else identify_text)(fallback_text)
    return LicenseResult(
        spdx_expressions=spdx_ids,
        expression_tree=_tree_for(spdx_ids, op),
        expression_op=op,
        source=("scancode_fallback" if external else "guardian_spdx_text") if spdx_ids else "unknown",
        confidence=confidence,
        raw_license_text=raw_field,
        declared_transitive_names=transitive,
        warnings=warnings,
    )


def _tree_for(ids, op):
    if not ids: return None
    try:
        return parse_expression(f" {op or 'AND'} ".join(f"({x})" for x in ids), _normalize_single)
    except ValueError:
        return {"op":"license","id":"invalid-expression","known":False}
