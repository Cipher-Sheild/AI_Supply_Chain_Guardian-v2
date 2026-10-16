"""Safety regressions for the learned numerical seam and persisted explanations."""
import json,math
from pathlib import Path
import pytest
from app.ml.vector import vector_from_event,FEATURE_NAMES
from app.scorers import ConfiguredScorer
from app.fusion import fuse
from app.routing import route_files
from app.state import AgentCallRecord
from app.schemas import AgentResult,Finding
from app.pending_store import StoredScan,serialize,deserialize

def state(status='pass',findings=None):
    routing=route_files([{'filename':'config.cfg','content':'x=1'}])
    result=AgentResult(agent_name='secret_detection',status=status,findings=findings or [])
    return {'request_id':'ml-test','files':[{'filename':'config.cfg','content':'x=1'}],'routing':routing,'results':[AgentCallRecord(file='config.cfg',agent='secret_detection',expected=True,agent_ran=True,status=status,result=result)],'pending_callbacks':[],'routing_notes':[]}

def test_missing_features_and_outcome_do_not_leak():
    event={'feature_version':'2.0','contract_version':'1.0','files':[{'agents':{}}],'outcome':{'trust_score':100}}
    first=vector_from_event(event);event['outcome']={'trust_score':0};second=vector_from_event(event)
    assert len(first)==len(FEATURE_NAMES)
    assert all((math.isnan(a) and math.isnan(b)) or a==b for a,b in zip(first,second))
    assert math.isnan(first[0])

def test_unavailable_model_falls_back_without_accepting_partial(monkeypatch,tmp_path):
    monkeypatch.setenv('TRUST_SCORER','ml');monkeypatch.setenv('TRUST_MODEL_PATH',str(tmp_path/'missing.json'))
    sample=state();result=fuse(sample,scorer=ConfiguredScorer())
    assert result.recommendation=='review'
    assert sample['scoring']['method']=='weighted_fallback'
    saved=deserialize(serialize(StoredScan(state=sample)))
    assert saved.state['scoring']==sample['scoring']

def test_override_never_calls_model(monkeypatch):
    class MustNotRun:
        def score(self,*args):raise AssertionError('override invoked model')
    sample=state('fail',[Finding(category='secret',severity='critical',confidence=1,hard_block=True,reason='fabricated test')])
    result=fuse(sample,scorer=MustNotRun())
    assert result.recommendation=='reject'
    assert sample['scoring']['method']=='hard_override'
    assert sample['scoring']['model_invoked'] is False

def test_real_model_shap_and_checksum(monkeypatch,tmp_path):
    pytest.importorskip('xgboost')
    from app.ml.predictor import Predictor
    path=Path(__file__).resolve().parents[1]/'models/guardian.json'
    if not path.exists():pytest.skip('trained artifact not generated yet')
    prediction=Predictor(path).infer(state())
    shap=prediction['shap']
    assert shap['agent_selected']['secret_detection'] is True
    assert shap['agent_selected']['cipherguard'] is False
    assert abs(shap['base_value']+sum(shap['agent_contributions'].values())-prediction['raw_model_score'])<.01
    bad=tmp_path/'bad.json';bad.write_bytes(path.read_bytes()+b' ')
    bad.with_suffix('.metadata.json').write_bytes(path.with_suffix('.metadata.json').read_bytes())
    with pytest.raises(ValueError,match='checksum'):Predictor(bad)


def test_unsolicited_unselected_result_cannot_change_decision():
    from app.routing import route_file
    decision=route_file('# no external dependencies','requirements.txt')
    sample={'request_id':'unselected','routing':[decision],'results':[AgentCallRecord(file='requirements.txt',agent=a,expected=True,agent_ran=True,status='pass',result=AgentResult(agent_name=a,status='pass')) for a in decision.expected_agents],'pending_callbacks':[]}
    sample['results'].append(AgentCallRecord(file='requirements.txt',agent='code_security',expected=False,agent_ran=True,status='fail',result=AgentResult(agent_name='code_security',status='fail',findings=[Finding(category='irrelevant',severity='critical',confidence=1,hard_block=True)])))
    output=fuse(sample)
    assert output.trust_score==100 and output.recommendation=='accept'

def test_claimed_clean_result_without_execution_never_accepts():
    sample=state();sample['routing'][0].coverage='full';sample['results'][0].agent_ran=False
    assert fuse(sample).recommendation=='review'


def test_public_scan_masks_secret_evidence_but_preserves_snapshot():
    from app.main import _scan_response
    sample=state();sample['results'][0].result.evidence={'url':'postgresql://admin:FabricatedPasswordOnly@db/app'}
    sample['trust_result']=fuse(sample).model_dump()
    response=_scan_response(sample).model_dump()
    assert 'FabricatedPasswordOnly' not in str(response)
    assert 'FabricatedPasswordOnly' in str(sample['trust_result'])


def test_public_ml_breakdown_is_additive_shap_and_preserves_detector_risk():
    class Explained:
        def score(self,sample,total_risk):
            sample['_model_scoring']={'method':'xgboost','raw_model_score':110.,'model_score':100.,
                'shap':{'base_value':90.,'agent_contributions':{'secret_detection':20.}}}
            return 100.
    sample=state()
    result=fuse(sample,scorer=Explained())
    assert result.agent_breakdown['secret_detection']==20
    assert result.agent_breakdown['_baseline']==90
    assert result.agent_breakdown['_score_adjustment']==-10
    assert sum(result.agent_breakdown.values())==result.trust_score
    assert sample['scoring']['weighted_risk_breakdown']=={'secret_detection':0.0}
    assert 'TreeSHAP baseline' in result.explanation
    assert result.recommendation=='review'  # Unknown routing still floors the decision.

@pytest.mark.parametrize('mode',['ml','mistyped-mode'])
def test_missing_or_invalid_configured_model_never_auto_accepts_full_clean_scan(monkeypatch,tmp_path,mode):
    monkeypatch.setenv('TRUST_SCORER',mode)
    monkeypatch.setenv('TRUST_MODEL_PATH',str(tmp_path/'missing.json'))
    routing=route_files([{'filename':'safe.py','content':'print(1)'}])
    records=[AgentCallRecord(file='safe.py',agent=agent,expected=True,agent_ran=True,status='pass',result=AgentResult(agent_name=agent,status='pass')) for agent in routing[0].expected_agents]
    sample={'request_id':'full-fallback','routing':routing,'results':records,'pending_callbacks':[],'routing_notes':[]}
    result=fuse(sample,scorer=ConfiguredScorer())
    assert result.trust_score==100 and result.recommendation=='review'
    assert 'weighted fallback requires review' in result.explanation
    assert sample['scoring']['method']=='weighted_fallback'
