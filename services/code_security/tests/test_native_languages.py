import pytest
from app.native_ast import scan


@pytest.mark.parametrize('filename,content,category',[
 ('a.js','const q="SELECT "+user; conn.query(q);','sql_injection'),
 ('a.ts','const q: string = "SELECT "+user; conn.query(q);','sql_injection'),
 ('a.php','<?php $q="SELECT ".$user; mysqli_query($db,$q);','sql_injection'),
 ('A.java','class A { void x(String user){String q="SELECT "+user; db.executeQuery(q);} }','sql_injection'),
 ('a.go','package main\nfunc x(user string){q := "SELECT " + user; db.Query(q)}','sql_injection'),
 ('a.go','package main\nfunc x(user string){exec.Command("sh", "-c", user)}','command_injection'),
 ('a.go','package main\nvar cfg = tls.Config{InsecureSkipVerify: true}','insecure_tls'),
])
def test_native_sinks_without_processes(monkeypatch,filename,content,category):
    monkeypatch.setattr('subprocess.Popen',lambda *a,**k:pytest.fail('scanner subprocess used'))
    assert any(f.category==category for f in scan(content,filename))


def test_html_sanitizer_does_not_sanitize_sql():
    findings=scan('<?php $q="SELECT ".htmlspecialchars($_GET["id"]); mysqli_query($db,$q);','a.php')
    assert any(f.category=='sql_injection' for f in findings)


def test_comment_and_literal_not_executable_rules():
    assert not scan('// eval(input)\nconst doc="eval(user)";','a.js')


def test_safe_go_bound_parameters_and_argument_array():
    source='package main\nfunc x(user string){db.Query("SELECT * FROM t WHERE id=?",user);exec.Command("echo",user)}'
    assert not scan(source,'a.go')


def test_native_parse_errors_reduce_coverage():
    result=scan('eval(user); function broken(','a.js')
    assert result.partial and any(f.category=='unsafe_eval' for f in result)

def test_branch_assignment_cannot_erase_risky_path():
    result=scan('let q="constant"; if(flag){q="SELECT "+user;}else{q="constant";} db.query(q);','a.js')
    assert any(f.category=='sql_injection' for f in result)

def test_php_fragments_without_open_tag_are_analyzed():
    assert any(f.category=='unsafe_eval' for f in scan('eval($input);','fragment.php'))

@pytest.mark.parametrize('filename,source',[
 ('a.js','const q="SELECT * FROM users WHERE name="+req.query.name+" AND tenant=?";db.query(q,[tenant]);'),
 ('a.go','package main\nfunc x(user string,tenant string){q:="SELECT * FROM users WHERE name="+user+" AND tenant=?";db.Query(q,tenant)}'),
 ('a.php','<?php $q="SELECT * FROM users WHERE name=".$_GET["name"]; $db->execute($q,[$tenant]);'),
])
def test_bound_values_do_not_hide_injection_in_query_text(filename,source):
    assert any(f.category=='sql_injection' for f in scan(source,filename))


def test_raw_request_sql_is_not_a_constant_template():
    assert any(f.category=='sql_injection' for f in scan('db.query(req.query.sql);','request.js'))
