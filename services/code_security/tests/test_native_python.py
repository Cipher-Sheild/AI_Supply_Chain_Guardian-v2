import pytest
from app.native_python import scan_python


def test_aliases_and_local_assignment_propagation():
    content='''import os as operating
from pickle import loads as decode
def bad(user):
    command = "echo " + user
    operating.system(command)
    decode(user)
'''
    findings=scan_python(content,'sample.py')
    assert {finding.category for finding in findings}=={'command_injection','insecure_deserialization'}


def test_constant_assignment_and_bound_sql_are_clean():
    content='''def safe(user):
    query = "SELECT * FROM t WHERE id = ?"
    cursor.execute(query, (user,))
    command = "echo constant"
    os.system(command)
    yaml.load(user, Loader=yaml.SafeLoader)
'''
    assert not scan_python(content,'safe.py')


def test_comments_are_not_executed_rules():
    assert not scan_python('# eval(input())\nmessage="pickle.loads(data)"\n','example.py')


def test_invalid_python_is_not_clean():
    with pytest.raises(SyntaxError):scan_python('def broken(:','invalid.py')


def test_native_does_not_invoke_scanner(monkeypatch):
    from app import main
    monkeypatch.delenv('GUARDIAN_EXTERNAL_SCANNERS',raising=False)
    monkeypatch.setattr(main,'_external_scan',lambda *a:pytest.fail('external scanner called'))
    assert main.run_semgrep('eval(input())','native.py')

def test_unknown_query_and_conditional_assignments_do_not_become_clean():
    assert any(f.category=='sql_injection' for f in scan_python('cursor.execute(external_query)','x.py'))
    content='def x(user,flag):\n if flag:\n  query="SELECT "+user\n else:\n  query="SELECT constant"\n cursor.execute(query)\n'
    assert any(f.category=='sql_injection' for f in scan_python(content,'x.py'))


def test_zero_iteration_loop_does_not_clear_external_command():
    source='import os\ndef run(user_input):\n    command=user_input\n    for item in []:\n        command="echo safe"\n    os.system(command)\n'
    result=scan_python(source,'loop.py')
    assert any(f.category=='command_injection' for f in result)


def test_function_local_import_and_callable_alias_are_scanned():
    source='def run(user_input):\n    import os as local_os\n    command=local_os.system\n    command(user_input)\n'
    result=scan_python(source,'alias.py')
    assert any(f.category=='command_injection' for f in result)


def test_subscript_assignment_does_not_sanitize_its_index():
    source='import os\ndef run(user_input, values):\n    values[user_input]="safe"\n    os.system(user_input)\n'
    result=scan_python(source,'subscript.py')
    assert any(f.category=='command_injection' for f in result)


def test_bound_values_do_not_hide_injection_in_python_query_text():
    source='def lookup(user,tenant):\n query="SELECT * FROM users WHERE name="+user+" AND tenant=?"\n cursor.execute(query,(tenant,))\n'
    assert any(f.category=='sql_injection' for f in scan_python(source,'query.py'))
    assert not scan_python('cursor.execute("SELECT * FROM users WHERE name=?",(user,))','safe.py')


def test_static_query_fragments_are_constant_but_default_arguments_are_not():
    assert not scan_python('suffix="main"\nquery="SELECT * FROM users_"+suffix+" WHERE id=?"\ncursor.execute(query,(user,))','static.py')
    source='def lookup(cursor,user,suffix="main"):\n query="SELECT * FROM users_"+suffix+" WHERE id=?"\n cursor.execute(query,(user,))\n'
    assert any(f.category=='sql_injection' for f in scan_python(source,'dynamic.py'))


@pytest.mark.parametrize('source',[
 'runner=eval\nrunner(input())',
 'import builtins as b\nrunner=b.eval\nrunner(input())',
 'def f(value=eval(input())):\n return value',
 'class C(eval(input())):\n pass',
])
def test_callable_aliases_and_definition_expressions_are_analyzed(source):
    assert any(f.category=='unsafe_eval' for f in scan_python(source,'definitions.py'))


def test_loop_assignment_from_external_iterable_replaces_previous_constant():
    source='import os\nitem="safe"\nfor item in external_items:\n os.system(item)\n'
    assert any(f.category=='command_injection' for f in scan_python(source,'loop.py'))


def test_branch_aliases_preserve_every_reachable_sensitive_callable():
    source='import os,yaml\nif flag:\n runner=os.system\nelse:\n runner=yaml.safe_load\nforward=runner\nforward(input())\n'
    assert any(f.category=='command_injection' for f in scan_python(source,'aliases.py'))
    source='import yaml\nif flag:\n runner=eval\nelse:\n runner=yaml.safe_load\nrunner(input())\n'
    assert any(f.category=='unsafe_eval' for f in scan_python(source,'aliases.py'))
