"""Transactional scan repository. PostgreSQL in Compose, SQLite for local use.
Snapshots and normalized findings/executions/score commit together. A database
row lock serializes updates across workers; SQLite uses BEGIN IMMEDIATE.
"""
import asyncio
import hashlib
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime,timedelta
from uuid import uuid4
from sqlalchemy import select, delete, text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.db.models import Base, Artifact, Scan, Agent, Finding, TrustScore, ScanSnapshot, AgentExecution,DependencyDetail,SecretDetail,DockerDetail
from app.security import current_tenant
from app.pending_store import serialize, deserialize

AGENTS = ['cipherguard','code_security','secret_detection','docker_security','workflow_cicd','license_compliance','prompt_injection']

class ScanStore:
    def __init__(self, url):
        self.url = url
        self.engine = create_async_engine(url, pool_pre_ping=True, echo=False)
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
        self.initialized = False
        self._initialization_lock = asyncio.Lock()
        self._local_lock = asyncio.Lock()

    async def initialize(self):
        async with self._initialization_lock:
            if self.initialized: return
            if self.url.startswith('sqlite'):
                async with self.engine.begin() as conn:
                    await conn.run_sync(Base.metadata.create_all)
                    columns=(await conn.execute(text('PRAGMA table_info(scan_snapshots)'))).all()
                    if 'tenant_id' not in {column[1] for column in columns}:
                        await conn.execute(text("ALTER TABLE scan_snapshots ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'owner'"))
                    await conn.execute(text('CREATE INDEX IF NOT EXISTS ix_scan_snapshots_tenant_id ON scan_snapshots (tenant_id)'))
                from sqlalchemy.engine import make_url
                from pathlib import Path
                filename=make_url(self.url).database
                if filename and filename!=':memory:' and Path(filename).exists():
                    os.chmod(filename,0o600)
            # Postgres tables must come from migrations, never create_all.
            self.initialized = True

    async def seed(self):
        await self.initialize()
        async with self.sessions.begin() as s:
            for name in AGENTS:
                if await s.scalar(select(Agent).where(Agent.name == name)) is None:
                    s.add(Agent(name=name, tool_backend='detector',version='1.0'))

    async def save(self, stored):
        await self.initialize()
        async with self._local_lock, self.sessions.begin() as session:
            await self._write(session, stored)

    async def _write(self, session, stored):
        from app.redaction import redact
        state = stored.state
        if 'per_file_outcomes' not in state:
            from app.interfaces import per_file_outcomes
            state['per_file_outcomes']=per_file_outcomes(state)
        rid = state['request_id']
        row = await session.scalar(select(ScanSnapshot).where(ScanSnapshot.request_id == rid).with_for_update())
        if row is not None and row.tenant_id != current_tenant.get():raise ValueError('scan belongs to another tenant')
        stamp = datetime.utcnow()
        if row is None:
            artifact = Artifact(artifact_type='batch' if len(state.get('files',[]))>1 else state.get('routing',[None])[0].artifact_type,
                content_hash=hashlib.sha256(json.dumps(state.get('files',[]),sort_keys=True).encode()).hexdigest())
            session.add(artifact); await session.flush()
            scan = Scan(artifact_id=artifact.id,started_at=stamp)
            session.add(scan); await session.flush()
            row = ScanSnapshot(request_id=rid,scan_id=scan.id,tenant_id=current_tenant.get(),payload={},updated_at=stamp)
            session.add(row)
        else:
            scan = await session.get(Scan,row.scan_id)
        scan.status = 'provisional' if state.get('pending_callbacks') else 'final'
        scan.completed_at = stamp if scan.status == 'final' else None
        row.payload = json.loads(serialize(stored)); row.updated_at = stamp
        await session.execute(delete(Finding).where(Finding.scan_id==scan.id))
        await session.execute(delete(AgentExecution).where(AgentExecution.scan_id==scan.id))
        for record in state.get('results',[]):
            agent = await session.scalar(select(Agent).where(Agent.name==record.agent))
            if agent is None:
                agent=Agent(name=record.agent,tool_backend='detector',version='1.0');session.add(agent);await session.flush()
            session.add(AgentExecution(scan_id=scan.id,agent_id=agent.id,file=record.file,status=record.status,payload=redact(record.model_dump(mode='json'))))
            for finding in record.result.findings if record.result else []:
                session.add(Finding(scan_id=scan.id,agent_id=agent.id,category=finding.category,
                    severity=finding.severity,confidence=finding.confidence,location=finding.location,raw_payload=redact(finding.model_dump(mode='json'))))
        score = await session.scalar(select(TrustScore).where(TrustScore.scan_id==scan.id))
        if score is None:
            score=TrustScore(scan_id=scan.id);session.add(score)
        score.overall_score = state['trust_result']['trust_score']
        score.agent_breakdown = state['trust_result'];score.computed_at = stamp

    async def load(self, request_id):
        await self.initialize()
        async with self.sessions() as s:
            row=await s.scalar(select(ScanSnapshot).where(ScanSnapshot.request_id==request_id,ScanSnapshot.tenant_id==current_tenant.get()))
            return deserialize(json.dumps(row.payload)) if row else None

    async def request_id_for_callback(self, callback_id):
        # Candidate scan query is limited to executions carrying callback IDs;
        # the exact lookup is done in Python to keep SQLite tests portable.
        await self.initialize()
        async with self.sessions() as s:
            row=(await s.execute(select(ScanSnapshot.request_id,ScanSnapshot.tenant_id).join(AgentExecution, AgentExecution.scan_id==ScanSnapshot.scan_id).where(AgentExecution.payload['callback_id'].as_string()==callback_id).limit(1))).first()
            # Internal callback path only, after callback-token authentication.
            if row:current_tenant.set(row.tenant_id)
            return row.request_id if row else None

    @asynccontextmanager
    async def locked(self, request_id):
        await self.initialize()
        async with self._local_lock, self.sessions() as s:
            try:
                if self.url.startswith('sqlite'): await s.execute(text('BEGIN IMMEDIATE'))
                row=await s.scalar(select(ScanSnapshot).where(ScanSnapshot.request_id==request_id,ScanSnapshot.tenant_id==current_tenant.get()).with_for_update())
                stored=deserialize(json.dumps(row.payload)) if row else None
                yield stored
                if stored is not None and json.loads(serialize(stored)) != row.payload:
                    await self._write(s,stored)
                await s.commit()
            except BaseException:
                await s.rollback();raise

    async def history(self, limit=20, offset=0):
        await self.initialize()
        async with self.sessions() as s:
            rows=(await s.scalars(select(ScanSnapshot).where(ScanSnapshot.tenant_id==current_tenant.get()).order_by(ScanSnapshot.updated_at.desc(),ScanSnapshot.request_id).offset(offset).limit(limit+1))).all()
            return {'items':[{'request_id':r.request_id,'updated_at':r.updated_at.isoformat(),
                'scan_status':'provisional' if r.payload.get('pending_callbacks') else 'final',
                **r.payload['trust_result']} for r in rows[:limit]],'limit':limit,'offset':offset,'has_more':len(rows)>limit}

    async def pending_ids(self):
        await self.initialize()
        async with self.sessions() as s:
            return list(await s.scalars(select(ScanSnapshot.request_id).join(Scan,Scan.id==ScanSnapshot.scan_id).where(Scan.status=='provisional')))

    async def pending_refs(self):
        await self.initialize()
        async with self.sessions() as s:
            return (await s.execute(select(ScanSnapshot.request_id,ScanSnapshot.tenant_id).join(Scan,Scan.id==ScanSnapshot.scan_id).where(Scan.status=='provisional'))).all()

    async def purge_expired(self,days=30,batch_size=500):
        if days<=0:return 0
        await self.initialize()
        cutoff=datetime.utcnow()-timedelta(days=days)
        async with self._local_lock,self.sessions.begin() as s:
            rows=(await s.execute(select(ScanSnapshot.scan_id,Scan.artifact_id).join(Scan,Scan.id==ScanSnapshot.scan_id)
                .where(Scan.status=='final',ScanSnapshot.updated_at<cutoff).limit(batch_size).with_for_update(skip_locked=True))).all()
            ids=[row.scan_id for row in rows]
            if not ids:return 0
            finding_ids=select(Finding.id).where(Finding.scan_id.in_(ids))
            for detail in (DependencyDetail,SecretDetail,DockerDetail):
                await s.execute(delete(detail).where(detail.finding_id.in_(finding_ids)))
            for model in (Finding,AgentExecution,TrustScore,ScanSnapshot):
                await s.execute(delete(model).where(model.scan_id.in_(ids)))
            await s.execute(delete(Scan).where(Scan.id.in_(ids)))
            artifacts=[row.artifact_id for row in rows]
            await s.execute(delete(Artifact).where(Artifact.id.in_(artifacts),~Artifact.id.in_(select(Scan.artifact_id))))
            return len(ids)

    async def ping(self):
        await self.initialize()
        async with self.sessions() as s: await s.execute(select(ScanSnapshot.tenant_id).limit(1))

    async def close(self): await self.engine.dispose()

_repository = None
def get_scan_store():
    global _repository
    if _repository is None:
        from app.private_state import private_state_file
        url=os.getenv('DATABASE_URL') or 'sqlite+aiosqlite:///'+private_state_file('scans.sqlite3')
        _repository=ScanStore(url)
    return _repository
