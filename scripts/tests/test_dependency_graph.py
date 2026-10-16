import importlib.util
import json
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location('dependency_graph',Path(__file__).resolve().parents[2]/'runtime/dependency_graph.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def graph(packages):
    return module.npm_graph(json.dumps({'lockfileVersion':3,'packages':packages}))


def test_nested_versions_and_hoisted_edges():
    result=graph({'':{'dependencies':{'a':'^1'}},
        'node_modules/a':{'version':'1.0.0','dependencies':{'b':'^2','c':'^1'}},
        'node_modules/b':{'version':'1.0.0'},
        'node_modules/a/node_modules/b':{'version':'2.0.0'},
        'node_modules/c':{'version':'1.0.0','dependencies':{'a':'^1'}}})
    assert result['complete'] and len(result['nodes'])==4
    assert next(e['to'] for e in result['edges'] if e['from']=='node_modules/a' and e['name']=='b')=='node_modules/a/node_modules/b'
    assert next(e['to'] for e in result['edges'] if e['from']=='node_modules/a' and e['name']=='c')=='node_modules/c'
    assert sum(node['direct'] for node in result['nodes'])==1


def test_missing_edges_and_workspace_links_are_visible():
    result=graph({'':{'dependencies':{'missing':'1','workspace':'file:local'}},
                  'node_modules/workspace':{'link':True,'resolved':'local'}})
    assert not result['complete'] and len(result['unresolved'])==3


def test_scoped_name_and_optional_absence():
    result=graph({'':{'dependencies':{'@scope/pkg':'1'},'optionalDependencies':{'native':'1'}},
                  'node_modules/@scope/pkg':{'version':'1.0.0'}})
    assert result['complete'] and result['nodes'][0]['name']=='@scope/pkg'


@pytest.mark.parametrize('content',['{}','[]','{"lockfileVersion":1}', '{"lockfileVersion":3,"packages":{"":{},"../escape":{}}}'])
def test_invalid_lockfiles_refused(content):
    with pytest.raises(ValueError):module.npm_graph(content)


def test_real_project_graph():
    content=(Path(__file__).resolve().parents[2]/'frontend/package-lock.json').read_text()
    result=module.npm_graph(content)
    assert result['node_count']>50 and result['edge_count']>50
