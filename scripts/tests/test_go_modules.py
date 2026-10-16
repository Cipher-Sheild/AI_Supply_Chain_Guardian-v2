import asyncio
import httpx
import pytest
from runtime.go_modules import resolve,parse_mod,version_key

def run(root,files,**kwargs):
    seen=[]
    def handle(request):
        seen.append(request.url.path)
        key=request.url.path
        return httpx.Response(200 if key in files else 404,text=files.get(key,''))
    async def execute():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:return await resolve(client,root,**kwargs)
    return asyncio.run(execute()),seen

def test_mvs_selects_highest_required_not_registry_latest():
    root='module example.com/root\ngo 1.16\nrequire example.com/a v1.0.0\nrequire example.com/b v1.0.0\n'
    files={'/example.com/a/@v/v1.0.0.mod':'module example.com/a\ngo 1.16\nrequire example.com/c v1.1.0',
           '/example.com/b/@v/v1.0.0.mod':'module example.com/b\ngo 1.16\nrequire example.com/c v1.2.0',
           '/example.com/c/@v/v1.1.0.mod':'module example.com/c\ngo 1.16',
           '/example.com/c/@v/v1.2.0.mod':'module example.com/c\ngo 1.16'}
    graph,seen=run(root,files)
    assert graph['complete']
    assert next(node for node in graph['nodes'] if node['name']=='example.com/c')['version']=='v1.2.0'
    assert all('v1.3' not in request for request in seen)

def test_modern_graph_prunes_transitive_edges_but_legacy_paths_are_loaded():
    root='module example.com/root\ngo 1.17\nrequire example.com/a v1.0.0'
    files={'/example.com/a/@v/v1.0.0.mod':'module example.com/a\ngo 1.17\nrequire example.com/b v1.0.0',
           '/example.com/b/@v/v1.0.0.mod':'module example.com/b\ngo 1.17\nrequire example.com/c v1.0.0',
           '/example.com/c/@v/v1.0.0.mod':'module example.com/c\ngo 1.17'}
    graph,seen=run(root,files)
    assert graph['complete'] and graph['pruning']
    assert {node['name'] for node in graph['nodes']}=={'example.com/a','example.com/b'}
    assert '/example.com/b/@v/v1.0.0.mod' not in seen
    files['/example.com/a/@v/v1.0.0.mod']=files['/example.com/a/@v/v1.0.0.mod'].replace('1.17','1.16')
    graph,seen=run(root,files)
    assert graph['complete'] and 'example.com/c' in {node['name'] for node in graph['nodes']}

def test_root_replacements_and_missing_metadata_never_claim_complete():
    root='module example.com/root\nrequire example.com/a v1.0.0'
    graph,seen=run(root+'\nreplace example.com/a => ../private',{})
    assert not graph['complete'] and not seen
    graph,seen=run(root,{})
    assert not graph['complete'] and graph['unresolved']
    graph,seen=run(root,{},max_modules=0)
    assert not graph['complete'] and not seen

def test_semver_prerelease_and_malformed_module_directives():
    assert version_key('v1.0.0-9')<version_key('v1.0.0-10')<version_key('v1.0.0-alpha')<version_key('v1.0.0')
    with pytest.raises(ValueError):parse_mod('require ../local v1.0.0')
    with pytest.raises(ValueError):parse_mod('require (\nexample.com/a v1.0.0')


def test_missing_module_and_noncanonical_versions_do_not_get_clean_graph():
    with pytest.raises(ValueError,match='module directive missing'):run('go 1.20\nrequire example.com/a v1.0.0',{})
    with pytest.raises(ValueError,match='leading zero'):version_key('v01.2.3')
