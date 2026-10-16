"""
Focused unit tests for app/license_lookup.py internals.

These two cases were both real bugs found via live testing against the
actual running service (not caught by the original test_analyze.py
suite, which only exercised the fast path and a mocked ScanCode
fallback) -- kept here as regression tests so they can't silently
reappear.
"""

from __future__ import annotations

from unittest.mock import patch

from app.license_lookup import normalize_license_text, _run_scancode_fallback


def test_or_expression_split_is_case_sensitive():
    """
    Regression test: `_split_expression` used to match " or " and " and "
    case-INSENSITIVELY, which meant ordinary English license names
    containing the word "or" (e.g. "... v2 or later") were incorrectly
    chopped in half as if "or" were an SPDX boolean operator. Found via
    live testing against pygobject's real PyPI classifier:
    "GNU Lesser General Public License v2 or later (LGPLv2+)".
    """
    spdx_ids, op, unmatched = normalize_license_text(
        ["GNU Lesser General Public License v2 or later (LGPLv2+)"]
    )
    assert spdx_ids == ["LGPL-2.0-or-later"]
    assert op is None
    assert unmatched == []

    # A genuine SPDX OR expression (uppercase, per spec) must still split correctly.
    spdx_ids, op, unmatched = normalize_license_text(["MIT OR Apache-2.0"])
    assert spdx_ids == ["MIT", "Apache-2.0"]
    assert op == "OR"


def test_scancode_fallback_confidence_is_nonzero_on_real_match():
    """
    Regression test: the ScanCode fallback used to read `score` directly
    off each detection dict (`detection.get("score", 0.0)`), but
    ScanCode 32.5's real output nests match scores inside
    `detection["matches"][i]["score"]` instead -- so confidence always
    silently defaulted to 0.0 even on a correct, confident match. Found
    via live testing in the running container; this fixture is the
    actual raw dict ScanCode returned for that case.
    """
    real_scancode_output = {
        "detected_license_expression": "lgpl-3.0",
        "detected_license_expression_spdx": "LGPL-3.0-only",
        "license_detections": [
            {
                "license_expression": "lgpl-3.0",
                "license_expression_spdx": "LGPL-3.0-only",
                "matches": [
                    {"score": 50.0, "matched_length": 10, "match_coverage": 50.0},
                    {"score": 100.0, "matched_length": 1, "match_coverage": 100.0},
                ],
            }
        ],
        "license_clues": [],
        "percentage_of_license_text": 78.57,
    }

    with patch("app.license_lookup._scancode_get_licenses", lambda path: real_scancode_output):
        spdx_ids, op, confidence, warnings = _run_scancode_fallback(
            "This project is licensed under the GNU Lesser General Public License v3.0 (LGPLv3)."
        )

    assert spdx_ids == ["LGPL-3.0-only"]
    assert confidence > 0.0, "confidence must not be 0.0 on a real, confident ScanCode match"
    assert confidence == round(78.57 / 100 * 0.75, 2)
    assert warnings == []
