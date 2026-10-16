import importlib.util
from pathlib import Path
import pytest
spec=importlib.util.spec_from_file_location('bounded_yaml',Path(__file__).resolve().parents[2]/'runtime/bounded_yaml.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def test_regular_aliases_work():
    result=module.load('common: &common [echo hello]\njob:\n  script: *common\n')
    assert result['job']['script']==['echo hello']


def test_cycles_rejected():
    with pytest.raises(ValueError):module.load('cycle: &cycle [*cycle]')


def test_small_input_with_large_expansion_rejected():
    text='a: &a ['+','.join(['hello']*10)+']\n'
    for i in range(1,7):
        previous='a' if i==1 else 'a'+str(i-1)
        text+='a'+str(i)+': &a'+str(i)+' ['+','.join(['*'+previous]*10)+']\n'
    with pytest.raises(ValueError):module.load(text)


def test_excessive_nesting_rejected():
    with pytest.raises(ValueError):module.load('['*70+'hello'+']'*70)
