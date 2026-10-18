"""Durable native image jobs and authenticated callback delivery.

Tokens are read from configuration at delivery time and never persisted.
The trusted callback endpoint is configured by the operator, not the artifact.
"""
import asyncio
import json
import logging
import stat
import os
from pathlib import Path
import sqlite3
import time
from uuid import uuid4
import httpx
from app.contract import AgentResult,Finding
from app.engines.native_image import analyze_image

_task=None
_logger=logging.getLogger(__name__)


def connect():
    path=Path(os.getenv('DOCKER_CALLBACK_OUTBOX_PATH','/tmp/guardian-docker-jobs.sqlite3'))
    path.parent.mkdir(parents=True,exist_ok=True)
    descriptor=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        metadata=os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.getuid():
            raise ValueError('unsafe image job journal ownership or file type')
        os.fchmod(descriptor,0o600)
        connection=sqlite3.connect(path,timeout=2)
    finally:os.close(descriptor)
    connection.execute('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, payload TEXT NOT NULL, due REAL NOT NULL, created REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)')
    connection.commit();path.chmod(0o600);return connection


def enqueue(images,path,base_result):
    callback=uuid4().hex
    url=os.getenv('TRUST_ENGINE_CALLBACK_URL','')
    token=os.getenv('CALLBACK_TOKEN','')
    if not url or not token:raise ValueError('image callback configuration unavailable')
    payload={'phase':'job','url':url.format(callback_id=callback),'images':images,'path':path,'base':base_result}
    connection=connect()
    try:
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            if connection.execute('SELECT count(*) FROM jobs').fetchone()[0]>=64:raise ValueError('image job capacity exhausted')
            connection.execute('INSERT INTO jobs(id,payload,due,created) VALUES(?,?,?,?)',(callback,json.dumps(payload),time.time(),time.time()))
    finally:connection.close()
    return callback


def claim():
    connection=connect()
    try:
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            connection.execute('DELETE FROM jobs WHERE created<?',(time.time()-86400,))
            row=connection.execute('SELECT id,payload FROM jobs WHERE due<=? ORDER BY created LIMIT 1',(time.time(),)).fetchone()
            if row:connection.execute('UPDATE jobs SET due=? WHERE id=?',(time.time()+150,row[0]))
            return (row[0],json.loads(row[1])) if row else None
    finally:connection.close()


def update(callback,payload=None,acknowledged=False):
    connection=connect()
    try:
        with connection:
            if acknowledged:connection.execute('DELETE FROM jobs WHERE id=?',(callback,))
            elif payload is not None:connection.execute('UPDATE jobs SET payload=?,due=? WHERE id=?',(json.dumps(payload),time.time(),callback))
            else:
                row=connection.execute('SELECT attempts FROM jobs WHERE id=?',(callback,)).fetchone()
                if row:connection.execute('UPDATE jobs SET attempts=attempts+1,due=? WHERE id=?',(time.time()+min(60,2**min(row[0]+1,6)),callback))
    finally:connection.close()


async def process(callback,payload):
    if payload['phase']=='job':
        result=AgentResult.model_validate(payload['base']);findings=list(result.findings);evidence=dict(result.evidence or {})
        incomplete=result.unresolved
        try:
            async def scan_all():
                nonlocal incomplete
                image_results=[]
                evidence['native_image_scans']=image_results
                for image in payload['images']:
                    engine,inventory=await analyze_image(image['reference'],payload['path'],image['line'])
                    findings.extend(Finding.model_validate(item.model_dump()) for item in engine.findings)
                    incomplete=incomplete or not engine.completed
                    image_results.append({'image':inventory['image_ref'],'manifest_digest':inventory['manifest_digest'],
                        'content_manifest_digest':inventory.get('content_manifest_digest'),'platform':inventory['platform'],'os_release':inventory['os_release'],'layers_verified':inventory['layers_verified'],
                        'package_count':len(inventory['packages']),'scope':inventory['package_inventory_scope'],**engine.evidence()})
                evidence['native_image_scans']=image_results
            await asyncio.wait_for(scan_all(),timeout=120)
        except Exception as error:
            incomplete=True;evidence['native_image_error']=type(error).__name__
            if isinstance(error,httpx.HTTPStatusError):evidence['native_image_http_status']=error.response.status_code
        blocked=any(item.hard_block or item.severity=='critical' for item in findings)
        from app.scoring import RiskScorer
        risk,_,severity=RiskScorer.calculate_score(findings)
        evidence.update({'total_findings':len(findings),'risk_score':risk,'severity':severity})
        result=result.model_copy(update={'findings':findings,'status':'fail' if blocked else 'error' if incomplete else 'warn' if findings else 'pass',
            'coverage':'partial' if incomplete else 'full','unresolved':incomplete,'callback_id':callback,
            'decision_floor':'reject' if blocked else 'review' if incomplete else 'accept','evidence':evidence})
        payload={'phase':'result','url':payload['url'],'result':result.model_dump(mode='json')}
        update(callback,payload=payload)
    async with httpx.AsyncClient(timeout=4,follow_redirects=False) as client:
        try:
            response=await client.post(payload['url'],json=payload['result'],headers={'X-Callback-Token':os.getenv('CALLBACK_TOKEN','')})
            if response.is_success:update(callback,acknowledged=True)
            else:update(callback)
        except httpx.HTTPError:update(callback)


async def worker():
    last_error=0
    while True:
        try:
            job=claim()
            if job:await process(*job)
        except asyncio.CancelledError:raise
        except Exception:
            if time.monotonic()-last_error>60:
                _logger.exception("Native image job processing failed")
                last_error=time.monotonic()
        await asyncio.sleep(1)


async def start():
    global _task
    connection=connect();connection.close()
    _task=asyncio.create_task(worker())


async def stop():
    if _task:
        _task.cancel();await asyncio.gather(_task,return_exceptions=True)
