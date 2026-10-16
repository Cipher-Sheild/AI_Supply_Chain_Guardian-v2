"""Bounded SQLite job/outbox journal; callback tokens never persist.
A lease is claimed atomically across processes. Unacknowledged results retry
with exponential backoff; unfinished judge jobs replay after lease expiry.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

class Outbox:
    def __init__(self,path=None,max_entries=64):
        self.path=path or os.getenv('CALLBACK_OUTBOX_PATH','/tmp/guardian-callbacks.sqlite3')
        self.max_entries=max_entries
        Path(self.path).parent.mkdir(parents=True,exist_ok=True)
        with self.connect() as c:
            c.execute('CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, payload TEXT NOT NULL, due REAL NOT NULL, created REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)')
        os.chmod(self.path,0o600)
    @contextmanager
    def connect(self):
        descriptor=os.open(self.path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            metadata=os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.getuid():
                raise ValueError("unsafe callback journal ownership or file type")
            os.fchmod(descriptor,0o600)
            connection=sqlite3.connect(self.path,timeout=2)
        finally:os.close(descriptor)
        try:
            with connection: yield connection
        finally: connection.close()
    def enqueue(self,id,payload):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute('SELECT count(*) FROM outbox').fetchone()[0]>=self.max_entries: raise RuntimeError('callback journal capacity exhausted')
            c.execute('INSERT OR IGNORE INTO outbox(id,payload,due,created) VALUES(?,?,?,?)',(id,json.dumps(payload),time.time(),time.time()))
    def result(self,id,url,result):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            exists=c.execute('SELECT 1 FROM outbox WHERE id=?',(id,)).fetchone()
            if not exists and c.execute('SELECT count(*) FROM outbox').fetchone()[0]>=self.max_entries:
                raise RuntimeError('callback journal capacity exhausted')
            payload=json.dumps({'phase':'result','url':url,'result':result})
            c.execute('INSERT INTO outbox(id,payload,due,created) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload',(id,payload,time.time(),time.time()))
    def claim(self,id=None):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            c.execute('DELETE FROM outbox WHERE created < ?',(time.time()-86400,))
            row=c.execute('SELECT id,payload FROM outbox WHERE due<=?'+(' AND id=?' if id else '')+' ORDER BY created LIMIT 1', (time.time(),id) if id else (time.time(),)).fetchone()
            if not row: return None
            c.execute('UPDATE outbox SET due=? WHERE id=?',(time.time()+240,row[0]))
            return row[0],json.loads(row[1])
    def acknowledge(self,id):
        with self.connect() as c: c.execute('DELETE FROM outbox WHERE id=?',(id,))
    def retry(self,id):
        with self.connect() as c:
            row=c.execute('SELECT attempts FROM outbox WHERE id=?',(id,)).fetchone()
            if row: c.execute('UPDATE outbox SET attempts=attempts+1,due=? WHERE id=?',(time.time()+min(60,2**min(row[0]+1,6)),id))

_box=None
def get_outbox():
    global _box
    if _box is None: _box=Outbox()
    return _box
