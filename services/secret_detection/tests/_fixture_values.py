"""Generate deliberately synthetic provider-shaped values for offline scanner tests.

No provider calls are made. Fixture templates avoid publishing complete
credential-shaped literals; rendering restores realistic scanner input.
"""

STRIPE_KEY = "sk_" + "live_" + "GuardianFixtureOnly123456789ABC"
SLACK_TOKEN = "xoxb" + "-" + "12345678901" + "-" + "1234567890123" + "-" + "AbCdEfGhIjKlMnOpQrStUvWx"


def render_fixture(content: str) -> str:
    return content.replace("{{SYNTHETIC_STRIPE_KEY}}", STRIPE_KEY).replace(
        "{{SYNTHETIC_SLACK_TOKEN}}", SLACK_TOKEN
    )
