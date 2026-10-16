"""Guardian Language Server: scan saved documents over the authenticated API.

JSON-RPC uses stdio; logs never enter stdout. Source is not executed. This
provides diagnostics in LSP-capable editors, not interception of AI accept UI.
"""
import concurrent.futures
import json
import os
import sys
import threading
from urllib.parse import unquote,urlsplit
from guardian_http import request_json,wait_final

MAX_MESSAGE=2*1024*1024


def read_message(stream):
    headers={};size=0
    while True:
        line=stream.readline(8193)
        if not line:return None
        size+=len(line)
        if size>8192:raise ValueError('LSP header too large')
        if line in (b'\r\n',b'\n'):break
        key,value=line.decode('ascii').split(':',1)
        key=key.lower().strip()
        if key in headers:raise ValueError('duplicate LSP header')
        headers[key]=value.strip()
    length=int(headers.get('content-length','-1'))
    if not 0<=length<=MAX_MESSAGE:raise ValueError('invalid LSP content length')
    chunks=[];remaining=length
    while remaining:
        chunk=stream.read(remaining)
        if not chunk:raise ValueError('truncated LSP message')
        chunks.append(chunk);remaining-=len(chunk)
    message=json.loads(b''.join(chunks))
    if not isinstance(message,dict) or message.get('jsonrpc')!='2.0':raise ValueError('invalid JSON-RPC message')
    return message


def diagnostics(result,text):
    lines=text.splitlines() or [''];output=[]
    for agent in result.get('detector_results',[]):
        for finding in agent.get('findings',[]):
            location=str(finding.get('location') or '')
            raw_line=location.rsplit(':',1)[-1]
            index=max(0,min(len(lines)-1,int(raw_line)-1 if raw_line.isdigit() else 0))
            output.append({'range':{'start':{'line':index,'character':0},'end':{'line':index,'character':len(lines[index].encode('utf-16-le'))//2}},
                'severity':1 if finding.get('severity') in {'critical','high'} else 2,
                'source':'Guardian/'+agent.get('agent_name','detector'),
                'message':str(finding.get('reason') or finding.get('category') or 'Security finding')})
    if result.get('scan_status')!='final' or (result.get('recommendation')!='accept' and not output):
        output.append({'range':{'start':{'line':0,'character':0},'end':{'line':0,'character':0}},'severity':2,
                       'source':'Guardian','message':str(result.get('explanation') or 'Scan incomplete; review required.')})
    return output


def main():
    output_lock=threading.Lock();document_lock=threading.Lock();documents={}
    slots=threading.BoundedSemaphore(4);pool=concurrent.futures.ThreadPoolExecutor(max_workers=2)
    base=os.getenv('GUARDIAN_URL','http://127.0.0.1:8000').rstrip('/')
    shutdown=False
    generation=0
    stopped=threading.Event()
    def send(message):
        raw=json.dumps({'jsonrpc':'2.0',**message},ensure_ascii=False).encode()
        with output_lock:
            sys.stdout.buffer.write(f'Content-Length: {len(raw)}\r\n\r\n'.encode()+raw);sys.stdout.buffer.flush()
    def publish(uri,version,issues,ticket):
        if stopped.is_set():return
        with document_lock:
            current=documents.get(uri)
            if current is None or current['version']!=version or current['generation']!=ticket:return
            send({'method':'textDocument/publishDiagnostics','params':{'uri':uri,'version':version,'diagnostics':issues}})
    def scan(uri,version,text,ticket):
        try:
            parsed=urlsplit(uri)
            filename=unquote(parsed.path) if parsed.scheme=='file' else uri
            if len(text.encode())>262144:raise ValueError('saved artifact exceeds 256 KiB')
            result=request_json(base+'/analyze',{'filename':filename,'content':text})
            result=wait_final(base,result,240,stop_event=stopped)
            publish(uri,version,diagnostics(result,text),ticket)
        except Exception:
            publish(uri,version,diagnostics({'explanation':'Guardian scan unavailable; review required.'},text),ticket)
        finally:slots.release()
    try:
        while True:
            message=read_message(sys.stdin.buffer)
            if message is None:break
            method=message.get('method');params=message.get('params') or {};rid=message.get('id')
            if not isinstance(params,dict):
                if rid is not None:send({'id':rid,'error':{'code':-32602,'message':'Expected object params'}})
                continue
            if method=='initialize':
                send({'id':rid,'result':{'capabilities':{'textDocumentSync':{'openClose':True,'change':1,'save':{'includeText':True}}},'serverInfo':{'name':'Guardian','version':'0.2.0'}}})
            elif method=='shutdown':shutdown=True;send({'id':rid,'result':None})
            elif method=='exit':break
            elif shutdown:
                if rid is not None:send({'id':rid,'error':{'code':-32600,'message':'Server shutting down'}})
            elif method in {'textDocument/didOpen','textDocument/didChange','textDocument/didSave','textDocument/didClose'}:
                document=params.get('textDocument') or {}
                if not isinstance(document,dict):continue
                uri=document.get('uri')
                if not isinstance(uri,str):continue
                generation+=1
                with document_lock:
                    if method=='textDocument/didClose':
                        documents.pop(uri,None)
                        send({'method':'textDocument/publishDiagnostics','params':{'uri':uri,'diagnostics':[]}});continue
                    if method=='textDocument/didOpen':
                        if isinstance(document.get('text',''),str) and (uri in documents or len(documents)<128):documents[uri]={'version':document.get('version',0),'text':document.get('text',''),'generation':generation}
                    elif method=='textDocument/didChange' and uri in documents:
                        changes=params.get('contentChanges') or []
                        if isinstance(changes,list) and changes and isinstance(changes[-1],dict) and isinstance(changes[-1].get('text'),str):documents[uri]={'version':document.get('version',0),'text':changes[-1].get('text',''),'generation':generation}
                    current=documents.get(uri)
                    if current and method=='textDocument/didSave':current['generation']=generation
                    snapshot=dict(current) if current else None
                    if snapshot and method=='textDocument/didSave' and isinstance(params.get('text'),str):
                        snapshot['text']=params['text'];documents[uri]=dict(snapshot)
                if method=='textDocument/didSave' and snapshot:
                    if slots.acquire(blocking=False):pool.submit(scan,uri,snapshot['version'],snapshot['text'],snapshot['generation'])
                    else:publish(uri,snapshot['version'],diagnostics({'explanation':'Guardian queue busy; save again to scan.'},snapshot['text']),snapshot['generation'])
            elif rid is not None:send({'id':rid,'error':{'code':-32601,'message':'Method not supported'}})
    finally:
        stopped.set()
        pool.shutdown(wait=False,cancel_futures=True)
    return 0


if __name__=='__main__':sys.exit(main())
