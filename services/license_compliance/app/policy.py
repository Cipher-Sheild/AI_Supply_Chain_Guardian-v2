"""
Stage 2 — the Policy Engine.

This is deliberately *just* a configuration reader + classifier — all
of the actual conflict reasoning (comparing a dependency's identified
license against the policy) lives in `conflict_engine.py`. Keeping
policy definition and conflict logic in separate modules is what makes
"change the policy by editing config.yml, not Python" actually true —
nothing here hardcodes which licenses are OK.

Policy is loaded from `config.yml`'s `license_policy` section, falling
back to `app/data/default_policy.json` for any key the user's
`config.yml` doesn't override. This means a `config.yml` that only sets
`mode: "no-copyleft"` still gets sensible allow/deny lists rather than
empty ones.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_DEFAULT_POLICY_PATH = Path(__file__).parent / "data" / "default_policy.json"

# License families used for "no-copyleft" mode and for explanatory
# reasons (e.g. "GPL-3.0-only is copyleft"). Matched by SPDX id prefix
# so we don't need to enumerate every "-only"/"-or-later" variant.
_COPYLEFT_PREFIXES = ("GPL-", "AGPL-")
_WEAK_COPYLEFT_PREFIXES = ("LGPL-", "MPL-", "EPL-", "CDDL-")


def classify_family(spdx_id: str) -> str:
    """Returns 'copyleft' | 'weak-copyleft' | 'permissive' | 'unknown'."""
    if not spdx_id:
        return "unknown"
    if spdx_id.startswith(_COPYLEFT_PREFIXES):
        return "copyleft"
    if spdx_id.startswith(_WEAK_COPYLEFT_PREFIXES):
        return "weak-copyleft"
    # SPDX identification establishes identity, not permissiveness. Unclassified
    # licenses (including noncommercial/source-available terms) require review.
    if spdx_id in {'MIT','Apache-2.0','BSD-2-Clause','BSD-3-Clause','ISC',
                  'PSF-2.0','0BSD','Unlicense','CC0-1.0','Zlib','BSL-1.0'}:
        return 'permissive'
    return "unknown"


@dataclass
class Policy:
    mode: str = "no-copyleft"  # "permissive-only" | "no-copyleft" | "custom"
    allowed_licenses: list[str] = field(default_factory=list)
    denied_licenses: list[str] = field(default_factory=list)
    always_flag: list[str] = field(default_factory=list)
    unknown_handling: str = "needs_review"  # "needs_review" | "conflict" | "allow"
    cache_ttl_days: int = 3
    transitive_enabled: bool = True
    transitive_max_candidates: int = 10

    def is_always_flagged(self, spdx_id: str) -> bool:
        return any(spdx_id.upper() == f.upper() or spdx_id.upper().startswith(f.upper()) for f in self.always_flag)

    def is_explicitly_allowed(self, spdx_id: str) -> bool:
        return any(spdx_id.upper() == a.upper() for a in self.allowed_licenses)

    def is_explicitly_denied(self, spdx_id: str) -> bool:
        # Supports plain ids ("GPL-3.0-only") and simple wildcard
        # prefixes ("GPL-*") for denylist entries.
        for d in self.denied_licenses:
            if d.endswith("*"):
                if spdx_id.upper().startswith(d[:-1].upper()):
                    return True
            elif spdx_id.upper() == d.upper():
                return True
        return False


def _load_default_policy() -> dict:
    with open(_DEFAULT_POLICY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_policy(config: dict) -> Policy:
    defaults = _load_default_policy()
    cfg_policy = (config or {}).get("license_policy", {}) or {}
    cfg_cache = (config or {}).get("cache", {}) or {}
    cfg_transitive = (config or {}).get("transitive_dependency_check", {}) or {}

    merged = {**defaults, **cfg_policy}

    return Policy(
        mode=merged.get("mode", "no-copyleft"),
        allowed_licenses=list(merged.get("allowed_licenses", [])),
        denied_licenses=list(merged.get("denied_licenses", [])),
        always_flag=list(merged.get("always_flag", [])),
        unknown_handling=merged.get("unknown_handling", "needs_review"),
        cache_ttl_days=cfg_cache.get("ttl_days", defaults.get("cache_ttl_days", 3)),
        transitive_enabled=cfg_transitive.get("enabled", True),
        transitive_max_candidates=cfg_transitive.get("max_candidates", 10),
    )
