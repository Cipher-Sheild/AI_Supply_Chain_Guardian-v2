"""Pre-write gating must never mutate a target, even when accepted."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guardian_pretool as gate


def event(tool='create_file', **args):
    return {'tool_name': tool, 'tool_input': args}


def final(decision='accept', score=95):
    return {'scan_status': 'final', 'recommendation': decision, 'trust_score': score, 'request_id': 'test'}


@pytest.mark.parametrize('decision', ['accept', 'review', 'reject'])
def test_create_inspected_before_existence(tmp_path, monkeypatch, decision):
    target = tmp_path / 'package.json'
    def scan(url, payload=None, **kw):
        assert url.endswith('/analyze/batch')
        assert not target.exists()
        assert payload['files'] == [{'filename': str(target), 'content': '{"name":"demo"}'}]
        return final(decision)
    monkeypatch.setattr(gate, 'request_json', scan)
    result, _ = gate.evaluate(event(filePath=str(target), content='{"name":"demo"}'), tmp_path, 'http://localhost')
    assert result == ('allow' if decision == 'accept' else 'deny')
    assert not target.exists()


def test_replacement_scans_whole_result_without_mutation(tmp_path, monkeypatch):
    target = tmp_path / 'app.py'
    target.write_text('def run(x):\n    return eval(x)\n')
    def scan(url, payload=None, **kw):
        assert 'return str(x)' in payload['files'][0]['content']
        assert 'eval' in target.read_text()
        return final()
    monkeypatch.setattr(gate, 'request_json', scan)
    assert gate.evaluate(event('replace_string_in_file', filePath=str(target), oldString='eval(x)', newString='str(x)'), tmp_path, 'http://localhost')[0] == 'allow'
    assert 'eval' in target.read_text()


def test_multi_edit_scans_final_composed_content(tmp_path, monkeypatch):
    target = tmp_path / 'app.py'; target.write_text('a = 1\nb = 2\n')
    monkeypatch.setattr(gate, 'request_json', lambda url, payload, **kw: final() if payload['files'][0]['content'] == 'a = 3\nb = 4\n' else final('reject'))
    edits = [{'filePath': str(target), 'oldString': old, 'newString': new} for old, new in [('a = 1', 'a = 3'), ('b = 2', 'b = 4')]]
    assert gate.evaluate(event('multi_replace_string_in_file', replacements=edits), tmp_path, 'http://localhost')[0] == 'allow'


@pytest.mark.parametrize('tool', ['run_in_terminal', 'Bash', 'apply_patch', 'insert_edit_into_file', 'runSubagent', 'unknown'])
def test_uninspectable_tools_blocked(tmp_path, tool):
    with pytest.raises(ValueError):
        gate.proposed_files(event(tool), tmp_path)


@pytest.mark.parametrize('path', ['../outside.py', '.github/hooks/guardian-preaccept.json', '.vscode/settings.json', '.git/config'])
def test_control_and_outside_paths_blocked(tmp_path, path):
    with pytest.raises(ValueError):
        gate.proposed_files(event(filePath=path, content='x'), tmp_path)


def test_symlink_blocked(tmp_path):
    (tmp_path / 'link.py').symlink_to(tmp_path / 'other.py')
    with pytest.raises(ValueError):
        gate.proposed_files(event(filePath='link.py', content='x'), tmp_path)


@pytest.mark.parametrize('response', [{}, final(score=float('nan')), final(score=True), {'scan_status': 'unknown'}, final('invalid')])
def test_invalid_results_do_not_allow(tmp_path, monkeypatch, response):
    monkeypatch.setattr(gate, 'request_json', lambda *a, **kw: response)
    assert gate.evaluate(event(filePath='a.py', content='x'), tmp_path, 'http://localhost')[0] == 'deny'


def test_provisional_polled_and_stale_result_denied(tmp_path, monkeypatch):
    target = tmp_path / 'app.py'; target.write_text('old')
    responses = iter([{'scan_status': 'provisional', 'request_id': 'test'}, final()])
    def scan(*a, **kw):
        response = next(responses)
        if response.get('scan_status') == 'final':target.write_text('changed')
        return response
    monkeypatch.setattr(gate, 'request_json', scan)
    assert gate.evaluate(event(filePath='app.py', content='new'), tmp_path, 'http://localhost')[0] == 'deny'


def test_backend_error_has_blocking_exit_and_redacted_output(tmp_path):
    result = subprocess.run([sys.executable, str(Path(gate.__file__)), '--workspace', str(tmp_path), '--url', 'http://127.0.0.1:1'], input=json.dumps(event(filePath='a.py', content='private-secret')), text=True, capture_output=True, timeout=10)
    assert result.returncode == 2
    assert json.loads(result.stdout)['hookSpecificOutput']['permissionDecision'] == 'deny'
    assert 'private-secret' not in result.stdout + result.stderr
    assert not (tmp_path / 'a.py').exists()


def test_real_http_and_camelcase_payload(tmp_path, monkeypatch):
    monkeypatch.setenv('GUARDIAN_API_KEY', 'test-client')
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.path == '/analyze/batch'
            assert self.headers['Authorization'] == 'Bearer test-client'
            payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            assert payload['files'][0]['content'] == 'print(1)'
            assert not (tmp_path / 'a.py').exists()
            self.send_response(200); self.end_headers(); self.wfile.write(json.dumps(final()).encode())
        def log_message(self, *args):pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        result = subprocess.run([sys.executable, str(Path(gate.__file__)), '--workspace', str(tmp_path), '--url', f'http://127.0.0.1:{server.server_port}'], input=json.dumps({'toolName':'create', 'toolArgs':json.dumps({'path':'a.py', 'file_text':'print(1)'})}), text=True, capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)['hookSpecificOutput']['permissionDecision'] == 'allow'
        assert not (tmp_path / 'a.py').exists()
    finally:
        server.shutdown();server.server_close();thread.join()


def test_installer_uses_external_hook_and_does_not_overwrite(tmp_path, capsys):
    gate.install(tmp_path, 'http://127.0.0.1:8000')
    config = json.loads((tmp_path / '.github/hooks/guardian-preaccept.json').read_text())
    hook = config['hooks']['PreToolUse'][0]
    assert hook['timeout'] > 25
    assert str(Path(gate.__file__).resolve()) in hook['command']
    assert 'GUARDIAN_API_KEY' not in hook['command']
    with pytest.raises(ValueError):gate.install(tmp_path, 'http://localhost')


@pytest.mark.parametrize('url', ['file:///tmp/server', 'http://key@localhost', 'http://localhost?key=private'])
def test_installer_refuses_unsafe_urls(tmp_path, url):
    with pytest.raises(ValueError):gate.install(tmp_path, url)
    assert not (tmp_path / '.github').exists()


def test_installer_refuses_linked_configuration(tmp_path):
    (tmp_path / '.github').symlink_to(tmp_path / 'elsewhere', target_is_directory=True)
    with pytest.raises(ValueError):gate.install(tmp_path, 'http://localhost')


def test_read_tool_does_not_contact_backend(tmp_path, monkeypatch):
    def unexpected(*a, **kw):raise AssertionError('Unexpected scan')
    monkeypatch.setattr(gate, 'request_json', unexpected)
    assert gate.evaluate(event('read_file', filePath='a.py'), tmp_path, 'http://localhost')[0] == 'allow'


def test_private_client_config_loaded_without_embedding_key(tmp_path, monkeypatch):
    config = tmp_path / 'private.env'; config.write_text('GUARDIAN_API_KEY=test-private-client\n'); config.chmod(0o600)
    monkeypatch.delenv('GUARDIAN_API_KEY', raising=False)
    gate.load_client_key(config)
    import os
    assert os.environ['GUARDIAN_API_KEY'] == 'test-private-client'
    workspace = tmp_path / 'workspace'; workspace.mkdir()
    gate.install(workspace, 'http://localhost', config)
    text = (workspace / '.github/hooks/guardian-preaccept.json').read_text()
    assert '--deployment-config' in text
    assert 'test-private-client' not in text


@pytest.mark.parametrize('mode', [0o644, 0o666])
def test_shared_client_config_refused(tmp_path, mode):
    config = tmp_path / 'private.env'; config.write_text('GUARDIAN_API_KEY=private\n');config.chmod(mode)
    with pytest.raises(ValueError):gate.load_client_key(config)


def test_linked_client_config_refused(tmp_path):
    config = tmp_path / 'private.env'; config.write_text('GUARDIAN_API_KEY=private\n');config.chmod(0o600)
    link = tmp_path / 'link.env'; link.symlink_to(config)
    with pytest.raises(ValueError):gate.load_client_key(link)


@pytest.mark.parametrize('name', ['demo.yml', 'demo.yaml'])
def test_workflow_proposals_can_be_scanned(tmp_path, name):
    path = '.github/workflows/' + name
    files = gate.proposed_files(event(filePath=path, content='name: test\n'), tmp_path)
    assert str(files[0][0]).endswith(path)
    assert not (tmp_path / path).exists()


@pytest.mark.parametrize('path', ['.github/workflows/unsafe.py', '.github/workflows/sub/test.yml', '.github/copilot-instructions.md', '.github/hooks/test.yml'])
def test_workflow_exception_does_not_unlock_control_files(tmp_path, path):
    with pytest.raises(ValueError):gate.proposed_files(event(filePath=path, content='x'), tmp_path)


def test_completion_without_backend(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, 'request_json', lambda *a, **k: pytest.fail('Completion must not scan'))
    assert gate.evaluate({'tool_name': 'task_complete'}, tmp_path, 'http://localhost')[0] == 'allow'


@pytest.mark.parametrize('wrapper', ['raw', 'input', 'patch', 'json'])
def test_patch_create_scans_before_write(tmp_path, monkeypatch, wrapper):
    patch = '*** Begin Patch\n*** Add File: safe.py\n+def add(a, b):\n+    return a + b\n*** End Patch'
    args = {'raw': patch, 'input': {'input': patch}, 'patch': {'patch': patch}, 'json': json.dumps({'input': patch})}[wrapper]
    def scan(url, payload, **kw):
        assert payload['files'][0]['content'] == 'def add(a, b):\n    return a + b\n'
        assert not (tmp_path / 'safe.py').exists()
        return final()
    monkeypatch.setattr(gate, 'request_json', scan)
    assert gate.evaluate({'tool_name':'apply_patch','tool_input':args}, tmp_path, 'http://localhost')[0] == 'allow'
    assert not (tmp_path / 'safe.py').exists()


def test_patch_update_scans_final_contents_and_preserves_disk(tmp_path, monkeypatch):
    path = tmp_path / 'app.py'; path.write_text('a = 1\nb = 2\n')
    patch = '*** Begin Patch\n*** Update File: app.py\n@@\n-a = 1\n+a = 3\n b = 2\n*** End Patch'
    monkeypatch.setattr(gate, 'request_json', lambda url, payload, **kw: final() if payload['files'][0]['content'] == 'a = 3\nb = 2\n' else final('reject'))
    assert gate.evaluate(event('apply_patch', input=patch), tmp_path, 'http://localhost')[0] == 'allow'
    assert path.read_text() == 'a = 1\nb = 2\n'


@pytest.mark.parametrize('operation', ['*** Delete File: app.py', '*** Update File: app.py\n*** Move to: other.py', '*** Add File: ../escape.py\n+x', '*** Add File: .vscode/settings.json\n+{}', '*** Add File: .github/hooks/new.json\n+{}', '*** Add File: app.py\nx'])
def test_patch_unsupported_and_protected_denied(tmp_path, operation):
    (tmp_path / 'app.py').write_text('x\n')
    with pytest.raises(ValueError):gate.proposed_files(event('apply_patch', input='*** Begin Patch\n'+operation+'\n*** End Patch'), tmp_path)


def test_patch_ambiguous_context_denied(tmp_path):
    (tmp_path / 'a.py').write_text('x\nx\n')
    with pytest.raises(ValueError):gate.proposed_files(event('apply_patch', input='*** Begin Patch\n*** Update File: a.py\n@@\n-x\n+y\n*** End Patch'), tmp_path)


@pytest.mark.parametrize('decision', ['review', 'reject'])
def test_patch_nonaccept_denied_without_writes(tmp_path, monkeypatch, decision):
    monkeypatch.setattr(gate, 'request_json', lambda *a, **k: final(decision))
    assert gate.evaluate(event('apply_patch', input='*** Begin Patch\n*** Add File: a.py\n+eval(x)\n*** End Patch'), tmp_path, 'http://localhost')[0] == 'deny'
    assert not (tmp_path / 'a.py').exists()


def test_patch_multi_file_is_one_batch(tmp_path, monkeypatch):
    patch='*** Begin Patch\n*** Add File: a.py\n+print(1)\n*** Add File: b.py\n+eval(x)\n*** End Patch'
    def scan(url, payload, **kw):
        assert len(payload['files']) == 2
        return final('review')
    monkeypatch.setattr(gate, 'request_json', scan)
    assert gate.evaluate(event('apply_patch', input=patch), tmp_path, 'http://localhost')[0] == 'deny'
    assert not list(tmp_path.iterdir())


def test_patch_stale_target_denied(tmp_path, monkeypatch):
    path=tmp_path/'a.py';path.write_text('x = 1\n')
    def scan(*a, **k):
        path.write_text('x = 9\n')
        return final()
    monkeypatch.setattr(gate,'request_json',scan)
    patch='*** Begin Patch\n*** Update File: a.py\n@@\n-x = 1\n+x = 2\n*** End Patch'
    assert gate.evaluate(event('apply_patch',input=patch),tmp_path,'http://localhost')[0]=='deny'
    assert path.read_text()=='x = 9\n'


def test_patch_symlink_and_size_denied(tmp_path):
    (tmp_path/'a.py').symlink_to(tmp_path/'other.py')
    for name,text in [('a.py','x'),('large.py','x'*(gate.LIMIT+1))]:
        with pytest.raises(ValueError):gate.proposed_files(event('apply_patch',input=f'*** Begin Patch\n*** Add File: {name}\n+{text}\n*** End Patch'),tmp_path)


def test_private_audit_records_shape_not_proposed_contents(tmp_path):
 log=tmp_path/'audit.jsonl'
 gate.append_audit(log,event('apply_patch',input='private-proposal-must-not-be-logged'),'deny','Guardian: test denial')
 text=log.read_text();record=json.loads(text)
 assert 'private-proposal-must-not-be-logged' not in text
 assert record['tool']=='apply_patch' and record['args_keys']==['input']
 assert log.stat().st_mode & 0o777 == 0o600


def test_private_audit_refuses_symlinks(tmp_path):
 target=tmp_path/'target';target.write_text('unchanged')
 link=tmp_path/'link';link.symlink_to(target)
 with pytest.raises(OSError):gate.append_audit(link,event(),'allow','test')
 assert target.read_text()=='unchanged'


@pytest.mark.parametrize('encoded',[False,True])
def test_vscode_sdk_Edit_freeform_patch_inspected(tmp_path,monkeypatch,encoded):
    patch='*** Begin Patch\n*** Add File: a.py\n+print(1)\n*** End Patch\n'
    def scan(url,payload,**kw):
        assert payload['files'][0]['content']=='print(1)\n'
        assert not (tmp_path/'a.py').exists()
        return final()
    monkeypatch.setattr(gate,'request_json',scan)
    assert gate.evaluate({'tool_name':'Edit','tool_input':json.dumps(patch) if encoded else patch},tmp_path,'http://localhost')[0]=='allow'
    assert not (tmp_path/'a.py').exists()

def test_vscode_Edit_structured_replacement_remains_supported(tmp_path):
    (tmp_path/'a.py').write_text('x = 1\n')
    files=gate.proposed_files(event('Edit',path='a.py',old_str='x = 1',new_str='x = 2'),tmp_path)
    assert files[0][1]=='x = 2\n'
