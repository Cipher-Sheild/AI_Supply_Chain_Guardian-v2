"""Privacy-conscious, versioned observations for offline feature engineering.
No artifact content, snippets, reasons, package names, credentials or raw evidence.
"""
import json
import logging
import math
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from app.capabilities import MATRIX

_LOCK = threading.Lock()
logger = logging.getLogger(__name__)
CATEGORY_GROUPS={
    "execution_risk":{"unsafe_eval","command_injection","insecure_deserialization","remote_code_execution"},
    "data_access_risk":{"sql_injection","ssrf","xss","path_traversal","xxe","open_redirect"},
    "credential_risk":{"connection_string","secret_leak","hardcoded_secret"},
    "privilege_risk":{"container_escape","privilege_escalation","capability_abuse","broad-permissions-plus-pull-request-target"},
    "policy_risk":{"license_review","unpinned-action","supply_chain","weak_auth","insecure_tls"},
}
AGENTS = sorted({agent for agents in MATRIX["types"].values() for agent in agents})
_SCORE_KEYS = {"risk_score", "workflow_risk_score", "score", "heuristic_score", "embedding_similarity"}

def numeric(value):
    return value if isinstance(value, (int,float)) and not isinstance(value,bool) and math.isfinite(value) else None

def feature_event(state, phase="initial"):
    files=[]
    records=state.get("results", [])
    for index, decision in enumerate(state.get("routing", [])):
        agents={name:None for name in AGENTS}
        for name in decision.expected_agents:
            matches=[r for r in records if r.file == decision.filename and r.agent == name and r.expected]
            if not matches: continue
            record=matches[-1]; result=record.result
            counts={severity:0 for severity in ("critical","high","medium","low","info")} if result else None
            scores={}
            if result:
                for key in _SCORE_KEYS:
                    value=numeric((result.evidence or {}).get(key))
                    if value is not None: scores[key]=value
                finding_scores=[]
                for finding in result.findings:
                    counts[finding.severity]+=1
                    value=numeric(finding.score)
                    if value is not None: finding_scores.append(value)
                if finding_scores: scores["finding_scores"]=finding_scores
                # Clean observations belong to evidence and do not become synthetic risks.
                package_scores=[numeric(p.get("score")) for p in (result.evidence or {}).get("packages", []) if isinstance(p,dict)]
                if package_scores: scores["package_scores"]=package_scores
            agents[name]={"ran":record.agent_ran,"status":record.status,
                "coverage":result.coverage if result else None,
                "unresolved":result.unresolved if result else True,
                "decision_floor":result.decision_floor if result else None,
                "category_group_counts":{key:sum(f.category in categories for f in result.findings) for key,categories in CATEGORY_GROUPS.items()} if result else None,
                "severity_counts":counts,"max_confidence":max((f.confidence for f in result.findings),default=0) if result else None,
                "agent_specific_scores":scores if result else None,"elapsed_ms":record.elapsed_ms,
                "hard_blocks":sum(f.hard_block for f in result.findings) if result else None}
        files.append({"file_index":index,"artifact_type":decision.artifact_type,
            "routing_source":decision.routing_source,"routing_coverage":decision.coverage,"agents":agents})
    return {"feature_version":"2.0","contract_version":"1.0","request_id":state["request_id"],
        "timestamp":datetime.now(timezone.utc).isoformat(),"phase":phase,"files":files,
        "outcome":{key:state.get("trust_result",{}).get(key) for key in ("trust_score","recommendation")}}

def append_feature_event(state, phase="initial"):
    path=os.getenv("FEATURE_LOG_PATH","/tmp/guardian-features.jsonl")
    if not path: return
    try:
        data=json.dumps(feature_event(state,phase),allow_nan=False,separators=(",",":"))+"\n"
        target=Path(path)
        target.parent.mkdir(parents=True,exist_ok=True)
        with _LOCK:
            descriptor=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
            with os.fdopen(descriptor,"w",encoding="utf-8") as handle: handle.write(data)
    except (OSError,ValueError,TypeError):
        logger.warning("Feature observation could not be persisted",exc_info=False)
