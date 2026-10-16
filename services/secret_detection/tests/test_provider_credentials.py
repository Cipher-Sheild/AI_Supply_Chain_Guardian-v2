import pytest
from app.detectors.vendor_signatures import VendorSignatureDetector

@pytest.mark.parametrize('prefix,rule',[('gsk_','groq_key'),('xai-','xai_key'),('hf_','huggingface_token')])
def test_provider_credentials_in_plain_prose_are_detected(prefix,rule):
    credential=prefix+'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0'
    findings=list(VendorSignatureDetector().scan('Use credential '+credential+' for authentication.','README.md'))
    assert any(item['detector_id']=='vendor_signature:'+rule for item in findings)

@pytest.mark.asyncio
async def test_provider_credential_response_does_not_echo_secret():
    import json
    from app.main import analyze
    credential='gsk_'+'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0'
    result=await analyze({'filename':'README.md','content':'Credential for this service: '+credential})
    assert result.status=='fail' and result.findings
    assert credential not in json.dumps(result.model_dump())

@pytest.mark.parametrize('kind',['ENCRYPTED PRIVATE KEY','PGP PRIVATE KEY BLOCK'])
def test_additional_private_key_markers_are_detected(kind):
    text='-----BEGIN '+kind+'-----\ncontrolled-fixture-body\n-----END '+kind+'-----'
    assert any(item['detector_id']=='vendor_signature:rsa_private_key' for item in VendorSignatureDetector().scan(text,'keys.txt'))
