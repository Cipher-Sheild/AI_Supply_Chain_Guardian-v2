import importlib.util
from pathlib import Path
import pytest
spec=importlib.util.spec_from_file_location('dependency_manifests',Path(__file__).resolve().parents[2]/'runtime/dependency_manifests.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def test_pyproject_dependencies_and_build_requirements():
    graph=module.parse('pyproject.toml','[project]\ndependencies=["requests==2.32.5"]\n[build-system]\nrequires=["setuptools>=80"]\n')
    assert {node['name'] for node in graph['nodes']}=={'requests','setuptools'}


def test_cargo_lock_resolves_duplicate_versions_by_explicit_reference():
    content='''version=3
[[package]]
name="demo"
version="0.1.0"
dependencies=["serde 1.0.0"]
[[package]]
name="serde"
version="1.0.0"
source="registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name="serde"
version="2.0.0"
source="registry+https://github.com/rust-lang/crates.io-index"
'''
    graph=module.parse('Cargo.lock',content)
    assert graph['complete'] and graph['edges'][0]['to']=='rust:serde@1.0.0'
    assert next(node['direct'] for node in graph['nodes'] if node['id']=='rust:serde@1.0.0')


def test_go_inventory_does_not_claim_resolved_graph():
    graph=module.parse('go.mod','module example.com/demo\nrequire (\n golang.org/x/net v0.40.0\n)\n')
    assert graph['nodes'][0]['ecosystem']=='go' and not graph['complete']


def test_local_and_dynamic_dependencies_remain_unresolved():
    assert not module.parse('pyproject.toml','[project]\ndynamic=["dependencies"]')['complete']
    assert not module.parse('Cargo.toml','[dependencies]\nlocal={path="../local"}')['complete']


@pytest.mark.parametrize('filename,content',[('pyproject.toml','project="wrong"'),('Cargo.lock','package=[1]'),('go.mod','require invalid')])
def test_malformed_structures_rejected(filename,content):
    with pytest.raises(ValueError):module.parse(filename,content)
