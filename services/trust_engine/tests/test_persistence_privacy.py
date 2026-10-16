from app.pending_store import StoredScan,serialize,deserialize
from app.state import AgentCallRecord
from app.schemas import AgentResult
from app.routing import route_file


def test_durable_callback_state_keeps_results_without_source_or_credentials():
    credential='gsk_'+'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0'
    source='Unique private implementation body '+credential
    state={'request_id':'privacy-case','files':[{'filename':'README.md','content':source,'options':{'secret':credential}}],
           'routing':[route_file(content=source,filename='README.md')],
           'results':[AgentCallRecord(file='README.md',agent='prompt_injection',expected=True,agent_ran=True,status='pass',result=AgentResult(agent_name='prompt_injection',status='pass',evidence={'text':'Credential '+credential}))],
           'pending_callbacks':[],'trust_result':{'recommendation':'accept','trust_score':100}}
    raw=serialize(StoredScan(state))
    assert credential not in raw and 'Unique private implementation body' not in raw
    restored=deserialize(raw)
    assert restored.state['files']==[{'filename':'README.md'}]
    assert restored.state['results'][0].result.status=='pass'
    assert restored.state['trust_result']['trust_score']==100
