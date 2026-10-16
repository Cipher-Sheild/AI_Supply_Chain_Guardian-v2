import json
import os
import jellyfish
from typing import Set

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))

_TOP_PYPI = {}
_TOP_NPM = {}

def load_top_pypi():
    if not _TOP_PYPI:
        path = os.path.join(ROOT, "top_pypi_packages.json")
        try:
            with open(path, "r") as f:
                data = json.load(f)
            # The structure is {"rows": [{"project": "name", "download_count": 123}, ...]}
            for i, row in enumerate(data.get("rows", [])):
                if i >= 10000:
                    break
                name = row["project"]
                _TOP_PYPI.setdefault(len(name), set()).add(name)
        except Exception:
            pass

def load_top_npm():
    if not _TOP_NPM:
        path = os.path.join(ROOT, "top_npm_packages.json")
        try:
            with open(path, "r") as f:
                data = json.load(f)
            for i, name in enumerate(data):
                if i >= 10000:
                    break
                _TOP_NPM.setdefault(len(name), set()).add(name)
        except Exception:
            pass

import functools

@functools.lru_cache(maxsize=30000)
def get_min_edit_distance(pkg_name: str, ecosystem: str):
    """
    Returns (minimum_raw_levenshtein_distance, minimum_normalized_edit_distance)
    between pkg_name and top 10k packages in the ecosystem.
    normalized_edit_distance = dist / max(len(pkg_name), len(top_pkg))
    """
    if ecosystem == "python":
        load_top_pypi()
        top_set = _TOP_PYPI
    elif ecosystem=='javascript':
        load_top_npm()
        top_set = _TOP_NPM
    else:
        return 999,1.0

    if not top_set:
        return 999, 1.0

    pkg_len = len(pkg_name)
    if pkg_len == 0:
        return 999, 1.0

    min_dist = 999
    min_norm_dist = 1.0
    abs_min_norm = 1.0 / (pkg_len + 2)
    
    # Only check lengths pkg_len - 2 to pkg_len + 2
    for target_len in range(max(1, pkg_len - 2), pkg_len + 3):
        if target_len not in top_set:
            continue
            
        if pkg_name in top_set[target_len]:
            return 0, 0.0
            
        for top_pkg in top_set[target_len]:
            dist = jellyfish.levenshtein_distance(pkg_name, top_pkg)
            max_l = max(pkg_len, len(top_pkg))
            norm = dist / max_l if max_l > 0 else 1.0
            if norm < min_norm_dist:
                min_norm_dist = norm
                min_dist = dist
                if min_norm_dist <= abs_min_norm:
                    return min_dist, min_norm_dist
                
    return min_dist, min_norm_dist

