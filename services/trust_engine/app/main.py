"""Public scan lifecycle. Persistence failures return 503; unknown never Accepts."""
import asyncio
import hmac
import logging
import os
from fastapi import Depends, FastAPI, HTTPException, Request, Query
from pydantic import ValidationError
from redis.exceptions import WatchError
from app.orchestration import run_full_scan_state
from app.pending_store import StoredScan, get_store, now_ms, close_store
from app.schemas import ArtifactRequest, AgentResult
from app.state import GraphState, RoutingSummary, ScanResponse, achieved_coverage
from app.routing import InvalidArtifactType
from app.lifecycle import finalize_overdue, apply_callback
from app.features import append_feature_event
AGENT_NAME='trust_engine'
CALLBACK_TOKEN_ENV_VAR='CALLBACK_TOKEN'
CALLBACK_TOKEN_HEADER='X-Callback-Token'
logger=logging.getLogger('trust_engine.main')
app=FastAPI(title='AI Supply Chain Guardian')
from app.security import AccessMiddleware, validate_configuration
_sweeper=None

@app.on_event('startup')
async def startup():
    validate_configuration()
    global _sweeper
    async def sweep():
        while True:
            try:
                store=get_store()
                from app.security import current_tenant
                refs=await store.pending_refs() if hasattr(store,'pending_refs') else [(rid,'owner') for rid in await store.pending_ids()]
                for rid,tenant in refs:
                    token=current_tenant.set(tenant)
                    try:
                        async with store.locked(rid) as stored:
                            changed=stored is not None and finalize_overdue(stored)
                        if changed: append_feature_event(stored.state,'callback')
                    finally:current_tenant.reset(token)
                if hasattr(store,'purge_expired'):await store.purge_expired(int(os.getenv('SCAN_RETENTION_DAYS','30')))
            except asyncio.CancelledError: raise
            except Exception:
                logger.warning('pending sweep unavailable',exc_info=False)
            await asyncio.sleep(10)
    _sweeper=asyncio.create_task(sweep())

@app.on_event('shutdown')
async def shutdown():
    if _sweeper:
        _sweeper.cancel()
        await asyncio.gather(_sweeper,return_exceptions=True)
    await close_store()

@app.get('/health')
async def health():
    from fastapi.responses import JSONResponse
    from app.orchestration import DETECTOR_URL_ENV_VARS
    checks={'callback_auth':bool(os.getenv('CALLBACK_TOKEN'))}
    mode=os.getenv('TRUST_SCORER','weighted')
    checks['scorer_configuration']=mode in {'weighted','ml'}
    if mode=='ml':
        try:
            from app.scorers import DEFAULT_SCORER
            await asyncio.to_thread(DEFAULT_SCORER.load_model)
            checks['predictive_model']=True
        except Exception:checks['predictive_model']=False
    try:
        await asyncio.wait_for(get_store().ping(),1)
        checks['database']=True
    except Exception: checks['database']=False
    import httpx
    async with httpx.AsyncClient(timeout=0.7) as client:
        async def check(agent,key):
            url=os.getenv(key,'')
            try:
                response=await client.get(url.rsplit('/analyze',1)[0]+'/health')
                checks[agent]=response.is_success
            except Exception: checks[agent]=False
        await asyncio.gather(*(check(a,k) for a,k in DETECTOR_URL_ENV_VARS.items()))
    ok=all(checks.values())
    return JSONResponse(status_code=200 if ok else 503,content={'service':AGENT_NAME,'status':'ok' if ok else 'degraded','checks':checks,
        'storage':'postgresql' if os.getenv('DATABASE_URL','').startswith('postgresql') else 'local_sqlite'})

def _scan_response(state: GraphState, extra_notes: list[str] | None = None) -> ScanResponse:
    routing = list(state.get("routing", []) or [])
    pending = list(state.get("pending_callbacks", []) or [])
    summary = RoutingSummary(
        overall_coverage=achieved_coverage(state),
        routing=routing,
        pending_callbacks=pending,
        routing_notes=list(state.get("routing_notes", []) or []) + list(extra_notes or []),
    )
    from app.interfaces import per_file_outcomes
    output = ScanResponse(
        scoring=state.get("scoring",{}),
        per_file=state["per_file_outcomes"] if "per_file_outcomes" in state else per_file_outcomes(state),
        **state["trust_result"],
        request_id=state["request_id"],
        scan_status="provisional" if pending else "final",
        routing=summary,
    )
    from app.redaction import redact
    return ScanResponse.model_validate(redact(output.model_dump()))


async def save_state(state,store):
    from app.interfaces import per_file_outcomes
    state['per_file_outcomes']=per_file_outcomes(state)
    stored=StoredScan(state=state,pending_since={p.callback_id:now_ms() for p in state.get('pending_callbacks',[])})
    try: await store.save(stored)
    except Exception as exc:
        logger.warning('scan persistence failed: %s',type(exc).__name__)
        raise HTTPException(503,detail={'error':'scan_store_unavailable'}) from exc
    return _scan_response(state)

@app.post('/analyze',response_model=ScanResponse)
async def analyze(artifact:ArtifactRequest,store=Depends(get_store)):
    from app.interfaces import MAX_FILE_BYTES
    if len(artifact.content.encode('utf-8'))>MAX_FILE_BYTES:
        raise HTTPException(413,detail='file exceeds 256 KiB work limit')
    try: state=await run_full_scan_state(artifact.model_dump(exclude_none=True))
    except InvalidArtifactType as exc: raise HTTPException(422,detail=str(exc)) from exc
    return await save_state(state,store)

def _check_callback_token(request: Request) -> None:
    """Authenticate a callback. Raises HTTPException; never returns detail
    that depends on the callback_id, and never echoes or logs the token.

    Fail closed: if trust_engine has no CALLBACK_TOKEN configured, every
    callback is refused with 503 ("callback auth not configured") -- a
    server misconfiguration, distinct from the caller's 401, and never a
    silent accept.
    """
    expected = os.getenv(CALLBACK_TOKEN_ENV_VAR, "")
    if not expected:
        logger.error("%s is not set; refusing all callbacks", CALLBACK_TOKEN_ENV_VAR)
        raise HTTPException(status_code=503, detail={
            "error": "callback_auth_not_configured",
            "message": "callback authentication is not configured on trust_engine",
        })
    supplied = request.headers.get(CALLBACK_TOKEN_HEADER)
    # Compare bytes, not str: hmac.compare_digest raises TypeError on
    # non-ASCII str, which would turn a junk header into a 500.
    if supplied is None or not hmac.compare_digest(
        supplied.encode("utf-8", "surrogateescape"), expected.encode("utf-8")
    ):
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": f"missing or invalid {CALLBACK_TOKEN_HEADER}"},
        )



@app.post('/callback/{callback_id}')
async def callback(callback_id:str,request:Request,store=Depends(get_store)):
    _check_callback_token(request)
    try: body=AgentResult(**(await request.json()))
    except (ValueError,TypeError,ValidationError) as exc: raise HTTPException(422,detail={'error':'invalid_body'}) from exc
    if body.callback_id is not None and body.callback_id!=callback_id:
        raise HTTPException(422,detail={'error':'callback_id_mismatch'})
    if body.status=='pending': raise HTTPException(422,detail={'error':'unresolved_status'})
    try:
        rid=await store.request_id_for_callback(callback_id)
        if rid is None: raise HTTPException(404,detail={'error':'unknown_or_expired_callback','callback_id':callback_id,'message':'unknown or expired callback'})
        for attempt in range(5):
            try:
                async with store.locked(rid) as stored:
                    if stored is None: raise HTTPException(404,detail={'error':'scan_state_expired'})
                    timed_out=finalize_overdue(stored)
                    changed=apply_callback(stored,callback_id,body)
                break
            except WatchError:
                if attempt==4: raise HTTPException(409,detail={'error':'callback_conflict_retry'})
        if changed or timed_out: append_feature_event(stored.state,'callback')
        pending=stored.state.get('pending_callbacks',[])
        return {'status':'accepted' if changed else 'already_resolved','request_id':rid,'callback_id':callback_id,
            'scan_status':'provisional' if pending else 'final','remaining_callbacks':len(pending),
            'recommendation':stored.state['trust_result']['recommendation']}
    except HTTPException: raise
    except Exception as exc: raise HTTPException(503,detail={'error':'scan_store_unavailable'}) from exc

@app.get('/scans/{request_id}',response_model=ScanResponse)
async def get_scan(request_id:str,store=Depends(get_store)):
    try:
        async with store.locked(request_id) as stored:
            if stored is None: raise HTTPException(404,detail={'error':'unknown_or_expired_scan','request_id':request_id})
            changed=finalize_overdue(stored)
        if changed: append_feature_event(stored.state,'callback')
        return _scan_response(stored.state)
    except HTTPException: raise
    except Exception as exc: raise HTTPException(503,detail={'error':'scan_store_unavailable'}) from exc

@app.get('/scans')
async def history(limit:int=Query(20,ge=1,le=100),offset:int=Query(0,ge=0),store=Depends(get_store)):
    try:
        from app.redaction import redact
        return redact(await store.history(limit,offset))
    except Exception as exc: raise HTTPException(503,detail={'error':'scan_store_unavailable'}) from exc

from app.runtime import BoundsMiddleware
app.add_middleware(BoundsMiddleware)
app.add_middleware(AccessMiddleware)

from app.interfaces import router
app.include_router(router)
