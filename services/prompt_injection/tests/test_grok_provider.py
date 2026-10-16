from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from app import llm_client


@pytest.mark.asyncio
@pytest.mark.parametrize('provider,prefix,endpoint',[
    ('grok','XAI','https://api.x.ai/v1'),
    ('groq','GROQ','https://api.groq.com/openai/v1')])
async def test_providers_use_separate_endpoints_and_credentials(monkeypatch,provider,prefix,endpoint):
    import openai
    captured={}
    completion=AsyncMock(return_value=SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='{"risk":false}'))]))
    class Client:
        def __init__(self,**settings):
            captured.update(settings)
            self.chat=SimpleNamespace(completions=SimpleNamespace(create=completion))
        async def __aenter__(self):return self
        async def __aexit__(self,*args):pass
    monkeypatch.setattr(openai,'AsyncOpenAI',Client)
    monkeypatch.setenv('LLM_PROVIDER',provider)
    monkeypatch.setenv(prefix+'_API_KEY','fake-provider-unit-key')
    monkeypatch.setenv('OPENAI_API_KEY','different-unit-key')
    monkeypatch.setenv(prefix+'_MODEL','available-provider-model')
    assert await llm_client.call_llm('untrusted text','judge instructions')=='{"risk":false}'
    assert captured['base_url']==endpoint
    assert captured['api_key']=='fake-provider-unit-key' and captured['max_retries']==0
    assert completion.call_args.kwargs['model']=='available-provider-model'
    if provider=='groq':
        assert completion.call_args.kwargs['extra_body']=={'reasoning_format':'hidden'}
        assert 'reasoning_format' not in completion.call_args.kwargs


@pytest.mark.asyncio
@pytest.mark.parametrize('provider,prefix',[('grok','XAI'),('groq','GROQ')])
@pytest.mark.parametrize('missing',['API_KEY','MODEL'])
async def test_missing_configuration_is_not_clean(monkeypatch,missing,provider,prefix):
    monkeypatch.setenv('LLM_PROVIDER',provider)
    monkeypatch.setenv(prefix+'_API_KEY','fake-unit-key')
    monkeypatch.setenv(prefix+'_MODEL','unit-model')
    monkeypatch.delenv(prefix+'_'+missing)
    with pytest.raises(ValueError,match='configured'):await llm_client.call_llm('test')
