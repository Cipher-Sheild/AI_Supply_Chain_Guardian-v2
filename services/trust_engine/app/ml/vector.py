"""Risk-only features shared by offline training and online inference.
No outcome, recommendation, artifact content, identity or latency predictors.
"""
import math
AGENTS=('cipherguard','code_security','docker_security','license_compliance','prompt_injection','secret_detection','workflow_cicd')
FIELDS=('critical','high','medium','low','info','max_confidence','hard_blocks','score_max','unavailable','execution_risk','data_access_risk','credential_risk','privilege_risk','policy_risk')
FEATURE_VERSION='guardian-risk-v2'
FEATURE_NAMES=[f'{agent}.{field}' for agent in AGENTS for field in FIELDS]
MONOTONIC_CONSTRAINTS=[-1]*len(FEATURE_NAMES)

def vector_from_event(event):
    if event.get('feature_version')!='2.0' or event.get('contract_version')!='1.0':
        raise ValueError('unsupported observation contract')
    values=[]
    for agent in AGENTS:
        observations=[f.get('agents',{}).get(agent) for f in event.get('files',[])]
        observations=[o for o in observations if o is not None]
        if not observations:
            values.extend([float('nan')]*8+[0.0]+[float('nan')]*5);continue
        counts=[sum((o.get('severity_counts') or {}).get(field,0) for o in observations) for field in FIELDS[:5]]
        confidence=max((o.get('max_confidence') or 0 for o in observations),default=0)
        hard=sum(o.get('hard_blocks') or 0 for o in observations)
        scores=[]
        for o in observations:
            for key,value in (o.get('agent_specific_scores') or {}).items():
                if key not in {'risk_score','workflow_risk_score','score','heuristic_score','embedding_similarity','finding_scores','package_scores'}:continue
                for number in value if isinstance(value,list) else [value]:
                    if isinstance(number,(int,float)) and not isinstance(number,bool) and math.isfinite(number):scores.append(max(0,float(number)))
        unavailable=sum(not o.get('ran') or o.get('status') in {'error','pending','stub'} or o.get('unresolved') or o.get('coverage')!='full' for o in observations)
        category_counts=[sum((o.get('category_group_counts') or {}).get(key,0) for o in observations) for key in FIELDS[9:]]
        values.extend([float(x) for x in counts+[confidence,hard,max(scores,default=0),unavailable]+category_counts])
    return values

def vector_from_state(state):
    from app.features import feature_event
    return vector_from_event(feature_event(state))
