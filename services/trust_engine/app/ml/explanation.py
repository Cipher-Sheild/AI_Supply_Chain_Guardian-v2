"""Persist additive model explanation separately from detector evidence."""
import os

def scoring_details(state,result):
    details=dict(state.pop('_model_scoring',{}) or {})
    override=result.agent_breakdown.get('_override')
    if override:
        details={'method':'hard_override','override':str(override),'model_invoked':False}
    elif not details:details={'method':'weighted','model_invoked':False}
    if details.get('method')=='xgboost' and details.get('shap'):
        details['weighted_risk_breakdown']=dict(result.agent_breakdown or {})
        shap=details['shap']
        result.agent_breakdown={**shap['agent_contributions'],'_baseline':shap['base_value'],
            '_score_adjustment':result.trust_score-shap['base_value']-sum(shap['agent_contributions'].values())}
        details['agent_breakdown_basis']='Exact TreeSHAP trust points plus baseline and score clipping, rounding, and floating-point adjustment'
        strongest=sorted(shap['agent_contributions'].items(),key=lambda item:abs(item[1]),reverse=True)[:3]
        effects='; '.join(f'{agent} {value:+.3f}' for agent,value in strongest)
        result.explanation+=f" Model explanation: TreeSHAP baseline {shap['base_value']:.3f} trust points; contributions {effects}. Safety gates remain authoritative."
    else:
        details['agent_breakdown_basis']='Severity-weighted detector risk; hard override when present'
    details['configured_scorer']=os.getenv('TRUST_SCORER','weighted')
    details['final_score']=result.trust_score
    details['final_recommendation']=result.recommendation
    details['policy_gates_authoritative']=True
    details['notice']='Model contributions explain numerical prediction, not policy overrides or causation.'
    return details
