from typing import Dict, Any, List

def check_metadata_risk(metadata: Dict[str, Any]) -> List[str]:
    """
    Evaluates metadata signals from the registry payload and returns a list of active risk signals.
    These string signals map to the scoring engine.
    """
    signals = []
    
    age = metadata.get("age_days", -1)
    if age != -1 and age < 120:
        signals.append("AGE_UNDER_120_DAYS")
        
    maintainers = metadata.get("maintainer_count", 0)
    if maintainers == 1:
        signals.append("SINGLE_MAINTAINER")
        
    downloads = metadata.get("downloads_last_month", -1)
    if downloads != -1 and downloads < 100:
        signals.append("LOW_DOWNLOAD_VOLUME")
        
    # Edge case: If registry data was completely missing/404, 
    # we don't apply these metadata heuristics because the existence check will hard-block it.
    
    return signals
