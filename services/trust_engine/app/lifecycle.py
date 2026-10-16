"""Scan updates and timeout finalization, outside the scorer/feature seam."""
import os
from fastapi import HTTPException
from app.schemas import AgentResult
from app.fusion import fuse
from app.pending_store import now_ms

PENDING_TIMEOUT_SECONDS = int(os.getenv('PENDING_TIMEOUT_SECONDS','180'))

def finalize_overdue(stored):
    stamp=now_ms()
    overdue={p.callback_id for p in stored.state.get('pending_callbacks',[])
        if stamp-stored.pending_since.get(p.callback_id,stamp) >= PENDING_TIMEOUT_SECONDS*1000}
    if not overdue: return False
    results=[]
    for record in stored.state.get('results',[]):
        if record.callback_id in overdue:
            result=AgentResult(agent_name=record.agent,status='error',coverage='none',
                unresolved=True,decision_floor='review',callback_id=record.callback_id,
                evidence={'error':'pending callback deadline exceeded','error_type':'callback_timeout'})
            record=record.model_copy(update={'status':'error','result':result,
                'error_reason':'pending callback deadline exceeded','elapsed_ms':stamp-stored.pending_since[record.callback_id]})
        results.append(record)
    stored.state['results']=results
    stored.state['pending_callbacks']=[p for p in stored.state['pending_callbacks'] if p.callback_id not in overdue]
    stored.state['trust_result']=fuse(stored.state).model_dump()
    from app.interfaces import per_file_outcomes
    stored.state['per_file_outcomes']=per_file_outcomes(stored.state)
    return True

def apply_callback(stored, callback_id, body):
    results=list(stored.state.get('results',[]))
    index=next((i for i,r in enumerate(results) if r.callback_id==callback_id),None)
    if index is None: raise HTTPException(409,detail={'error':'callback_record_missing'})
    record=results[index]
    if body.agent_name != record.agent: raise HTTPException(422,detail={'error':'agent_mismatch'})
    if record.status!='pending': return False
    resolved=body.model_copy(update={'callback_id':callback_id})
    results[index]=record.model_copy(update={'agent_ran':True,'status':resolved.status,'result':resolved,
        'elapsed_ms':max(0,now_ms()-stored.pending_since.get(callback_id,now_ms())),
        'error_reason':str((resolved.evidence or {}).get('error') or 'agent reported error') if resolved.status=='error' else None})
    stored.state['results']=results
    stored.state['pending_callbacks']=[p for p in stored.state.get('pending_callbacks',[]) if p.callback_id!=callback_id]
    stored.state['trust_result']=fuse(stored.state).model_dump()
    from app.interfaces import per_file_outcomes
    stored.state['per_file_outcomes']=per_file_outcomes(stored.state)
    return True
