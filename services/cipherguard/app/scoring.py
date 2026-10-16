from typing import Dict, Any, List

def calculate_score(existence: Dict[str, Any], metadata_signals: List[str], typosquat_dist: int, norm_dist: float = 1.0, pkg_name: str = "") -> int:
    score = 0
    
    # 1. Hard Block Signals (Existence / Network Errors)
    status = existence.get("status", 200)
    if status == 404 or status >= 500:
        return 100 # Immediate max score
        
    # 2. Heuristic Signals
    pkg_len = len(pkg_name)
    age_days = existence.get("age_days", -1)
    
    is_typosquat = False
    if typosquat_dist > 0:
        # High confidence normalized typosquat
        if 0.0 < norm_dist <= 0.20:
            is_typosquat = True
        # Raw distance 1-2 or norm_dist <= 0.25 on confirmed young packages (< 365 days)
        elif (1 <= typosquat_dist <= 2) or (0.0 < norm_dist <= 0.25):
            if not (pkg_len <= 3 and norm_dist > 0.34):
                if 0 <= age_days < 365:
                    is_typosquat = True

    if is_typosquat:
        score += 32
        
    if "AGE_UNDER_120_DAYS" in metadata_signals:
        score += 25
        
    if "SINGLE_MAINTAINER" in metadata_signals:
        score += 8
        
    if "LOW_DOWNLOAD_VOLUME" in metadata_signals:
        score += 9
        
    # 3. Cap heuristic-only scores to 89 to ensure 200 OK packages never hit the 90-100 Hard Block tier
    if score > 89:
        score = 89
        
    return score
