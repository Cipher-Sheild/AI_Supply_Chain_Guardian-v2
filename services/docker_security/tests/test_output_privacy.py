import pytest
from app import main
from app.engines.result import EngineResult
from app.redaction import redact

def test_hardening_output_masks_credentials_without_dropping_fields():
    artifact={'hardened_artifact':{'content':'ENV DATABASE_URL=postgresql://admin:FabricatedPasswordOnly@db/app'},'findings':[{'details':{'token':'FabricatedPasswordOnly'}}],'risk_score':100}
    masked=redact(artifact)
    assert 'FabricatedPasswordOnly' not in str(masked)
    assert masked.keys()==artifact.keys() and masked['risk_score']==100

@pytest.mark.asyncio
async def test_detector_applies_redaction_to_optional_hardening(monkeypatch):
    from app.contract import ArtifactRequest
    from types import SimpleNamespace
    monkeypatch.setattr(main.hadolint_engine,'analyze',lambda *args:EngineResult(True))
    monkeypatch.setattr(main.trivy_config_engine,'analyze',lambda *args:EngineResult(True))
    monkeypatch.setattr(main.base_image_checker,'check_image_exists',lambda *args:EngineResult(True))
    monkeypatch.setattr(main.dockerfile_hardener,'harden',lambda *args:SimpleNamespace(model_dump=lambda:{'suggested':'ENV DATABASE_URL=postgresql://admin:FabricatedPasswordOnly@db/app'}))
    result=await main.analyze(ArtifactRequest(content='FROM alpine:3.20\nUSER 10001\n',filename='Dockerfile',type='dockerfile'))
    assert 'FabricatedPasswordOnly' not in str(result.model_dump())
    assert result.evidence['hardened_artifact']['suggested']
