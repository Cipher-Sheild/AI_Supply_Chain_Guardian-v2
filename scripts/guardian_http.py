"""Shared stdlib client for CLI, benchmark and independently labeled corpora."""
import json
import time
import os
from urllib.request import Request, build_opener, HTTPRedirectHandler,HTTPSHandler
from urllib.parse import urlsplit
import ssl

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise ValueError('Guardian API redirects are refused')

def request_json(url,payload=None,timeout=10):
    target=urlsplit(url)
    if target.scheme not in {'http','https'} or not target.hostname or target.username is not None or target.password is not None:
        raise ValueError('Guardian URL must use HTTP or HTTPS without embedded credentials')
    data=None if payload is None else json.dumps(payload).encode('utf-8')
    headers={'Content-Type':'application/json'} if data is not None else {}
    key=os.getenv('GUARDIAN_API_KEY','')
    if key:
        target=urlsplit(url)
        if target.scheme!='https' and target.hostname not in {'localhost','127.0.0.1','::1'}:
            raise ValueError('authenticated remote Guardian connections require HTTPS')
        headers['Authorization']='Bearer '+key
    context=ssl.create_default_context()
    if os.getenv('GUARDIAN_CA_FILE'):context.load_verify_locations(os.environ['GUARDIAN_CA_FILE'])
    with build_opener(NoRedirect(),HTTPSHandler(context=context)).open(Request(url,data=data,headers=headers),timeout=timeout) as res:
        raw=res.read(16*1024*1024+1)
        if len(raw)>16*1024*1024:raise ValueError('Guardian response exceeds client data budget')
        return json.loads(raw)

def wait_final(base_url,result,deadline_seconds=240,poll_seconds=.5,stop_event=None):
    deadline=time.monotonic()+deadline_seconds
    while result.get('scan_status')=='provisional':
        if stop_event is not None and stop_event.is_set():raise TimeoutError('scan polling cancelled')
        if time.monotonic()>=deadline: raise TimeoutError('scan did not reach final state before polling deadline')
        delay=min(poll_seconds,max(0,deadline-time.monotonic()))
        if stop_event is not None:stop_event.wait(delay)
        else:time.sleep(delay)
        result=request_json(base_url.rstrip('/')+'/scans/'+result['request_id'],timeout=min(10,max(.1,deadline-time.monotonic())))
    if result.get('scan_status')!='final': raise ValueError('server did not return a final scan status')
    return result
