from pathlib import Path
import importlib.util
spec=importlib.util.spec_from_file_location('redaction',Path(__file__).resolve().parents[2]/'runtime/redaction.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
def test_credential_values_masked_without_dropping_evidence():
    original={'findings':[{'details':{'url':'postgresql://admin:FabricatedPasswordOnly@db/app','password':'FabricatedPasswordOnly'},'reason':'ENV password=FabricatedPasswordOnly'}],'score':65,'callback_id':'cb-123'}
    masked=module.redact(original)
    assert 'FabricatedPasswordOnly' not in str(masked)
    assert masked['score']==65 and masked['callback_id']=='cb-123'
    assert set(masked['findings'][0])==set(original['findings'][0])
    assert original['findings'][0]['details']['password']=='FabricatedPasswordOnly'


def test_provider_credentials_are_redacted_without_assignment_context():
    from runtime.redaction import redact_text
    for prefix in ('gsk_','xai-','hf_','npm_','github_pat_'):
        credential=prefix+'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0'
        assert credential not in redact_text('Credential embedded in prose: '+credential)


def test_environment_names_headers_and_private_blocks_are_masked():
    from runtime.redaction import redact,redact_text
    credential='OpaqueCredentialValue1234567890'
    for key in ('GUARDIAN_API_KEY','AWS_SECRET_ACCESS_KEY','DB_PASSWORD','serviceAuthToken'):
        assert credential not in redact_text(key+'="'+credential+'"')
        assert credential not in redact_text('"'+key+'": "'+credential+'"')
        assert credential not in str(redact({key:credential}))
    assert credential not in redact_text('Authorization: Bearer '+credential)
    assert credential not in redact_text('-----BEGIN RSA PRIVATE KEY-----\n'+credential+'\n-----END RSA PRIVATE KEY-----')


def test_header_maps_do_not_expose_credentials():
    from runtime.redaction import redact
    credential='OpaqueCredentialValue1234567890'
    assert credential not in str(redact({'headers':{'Authorization':'Bearer '+credential,'Cookie':'session='+credential}}))
