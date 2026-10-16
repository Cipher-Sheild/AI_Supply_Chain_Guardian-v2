import pytest
from app.scorer import SecretScorer
from app.contract import AgentResult
from app.schemas import AgentResult as LocalResult

@pytest.mark.parametrize("content",['DB_PASSWORD=abc','password: abc','export API_TOKEN=abcTestExample9Q','password = "abc"','api_key="sk-abcdefghijklmnopqrstexampleABCDEFGHIJKLMNOP"'])
def test_context_confirmed_secrets_survive_suppression(content):
    findings=SecretScorer().score_findings(content,".env")
    assert findings
    parsed=AgentResult(**LocalResult(agent_name="secret_detection",status="fail",findings=findings).model_dump())
    assert all(0<=f.confidence<=1 and f.category and f.location.startswith(".env:") for f in parsed.findings)
    assert all(f.remediation and f.reason and f.details["detector_id"] for f in parsed.findings)

@pytest.mark.parametrize("content",['password=${DB_PASSWORD}','password: YOUR_PASSWORD','token="xxxxxxxxxxxxxxxx"'])
def test_clear_placeholders_remain_suppressed(content):
    assert not SecretScorer().score_findings(content,".env")

def test_weak_password_literal_is_not_placeholder():
    assert SecretScorer().score_findings('password="password"',"settings.py")

def test_quoted_environment_reference_is_not_credential():
    assert not SecretScorer().score_findings('password="${DB_PASSWORD}"',"settings.py")
