import io
import json
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guardian_lsp import read_message,diagnostics


def test_utf8_frame_and_eof():
    body=json.dumps({'jsonrpc':'2.0','method':'initialize','params':{'text':'λ'}}).encode()
    stream=io.BytesIO(f'Content-Length: {len(body)}\r\n\r\n'.encode()+body)
    assert read_message(stream)['method']=='initialize'
    assert read_message(stream) is None


@pytest.mark.parametrize('raw',[b'Content-Length: 99999999\r\n\r\n',b'Content-Length: 8\r\nContent-Length: 8\r\n\r\n',b'Content-Length: 10\r\n\r\n{}'])
def test_invalid_frames_refused(raw):
    with pytest.raises(ValueError):read_message(io.BytesIO(raw))


def test_diagnostics_use_utf16_columns_and_clamp_line():
    result={'scan_status':'final','recommendation':'reject','detector_results':[{'agent_name':'test','findings':[{'location':'app.py:999','severity':'high','reason':'unsafe'}]}]}
    issue=diagnostics(result,'🙂')[0]
    assert issue['range']['end']=={'line':0,'character':2} and issue['severity']==1


def test_unavailable_never_looks_clean():
    assert diagnostics({},'hello')[0]['severity']==2


def test_late_result_from_same_version_save_is_discarded(monkeypatch):
    import concurrent.futures
    import threading
    from types import SimpleNamespace
    import guardian_lsp as server
    started=threading.Event();release=threading.Event();futures=[]
    real_pool=concurrent.futures.ThreadPoolExecutor
    class Pool(real_pool):
        def submit(self,*args,**kwargs):
            future=super().submit(*args,**kwargs);futures.append(future);return future
    def request(url,payload):
        if payload['content']=='old':
            started.set();assert release.wait(5)
        return {'scan_status':'final','recommendation':'reject','detector_results':[
            {'agent_name':'test','findings':[{'severity':'high','reason':payload['content']}]}]}
    uri='file:///demo.py'
    def frames():
        yield {'method':'textDocument/didOpen','params':{'textDocument':{'uri':uri,'version':1,'text':'old'}}}
        yield {'method':'textDocument/didSave','params':{'textDocument':{'uri':uri},'text':'old'}}
        assert started.wait(5)
        yield {'method':'textDocument/didSave','params':{'textDocument':{'uri':uri},'text':'new'}}
        futures[1].result(timeout=5)
        release.set();futures[0].result(timeout=5)
        yield {'method':'exit'}
    iterator=iter(frames());output=io.BytesIO()
    monkeypatch.setattr(server,'read_message',lambda stream:next(iterator,None))
    monkeypatch.setattr(server,'request_json',request)
    monkeypatch.setattr(server,'wait_final',lambda base,result,*a,**k:result)
    monkeypatch.setattr(server.concurrent.futures,'ThreadPoolExecutor',Pool)
    monkeypatch.setattr(server.sys,'stdin',SimpleNamespace(buffer=io.BytesIO()))
    monkeypatch.setattr(server.sys,'stdout',SimpleNamespace(buffer=output))
    assert server.main()==0
    output.seek(0);messages=[]
    while (message:=read_message(output)) is not None:messages.append(message)
    assert [item['message'] for message in messages for item in message['params']['diagnostics']]==['new']
