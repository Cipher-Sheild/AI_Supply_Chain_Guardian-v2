# Scanner fixture template; tests render synthetic provider values before scanning.
"""
Realistic code sample for Secret Detection Agent testing.
Secrets below are synthetic, format-valid, non-canonical fakes (see generation notes).
Embedded in realistic code contexts: functions, classes, configs, f-strings.
"""

import os
import json
import boto3
import requests
from dataclasses import dataclass


# --- 1. Class attribute style (common in AI-generated boilerplate) ---
class AWSConfig:
    ACCESS_KEY = "AKIAXAJI0Y6DPBHSAHXT"
    SECRET_KEY = "oLZaZSvj9vfg2MZUI+yJ1N3KTcosfogrOxxnr7PM"
    REGION = "us-east-1"

    def get_client(self):
        return boto3.client(
            "s3",
            aws_access_key_id=self.ACCESS_KEY,
            aws_secret_access_key=self.SECRET_KEY,
            region_name=self.REGION,
        )


# --- 2. Function default arguments (secrets baked into signatures) ---
def push_to_github(
    repo: str,
    branch: str = "main",
    token: str = "ghp_kTkx9NIQ0Wobtqn62tOy4CqpIqK3yn9FfcgM",
):
    headers = {"Authorization": f"token {token}"}
    resp = requests.get(f"https://api.github.com/repos/{repo}", headers=headers)
    return resp.json()


def deploy_with_fine_grained_pat():
    pat = "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"
    headers = {"Authorization": f"Bearer {pat}"}
    return headers


# --- 3. Payment integration (common in AI-generated e-commerce code) ---
def charge_customer(amount_cents: int, customer_id: str):
    import stripe
    stripe.api_key = "{{SYNTHETIC_STRIPE_KEY}}"
    return stripe.Charge.create(
        amount=amount_cents,
        currency="usd",
        customer=customer_id,
    )


# --- 4. LLM client wrapper (very common in this project's own domain) ---
class OpenAIClient:
    def __init__(self):
        self.api_key = "sk-proj-d9Z850kEnydx9qWCA79ISjs8JHUdKF0j7elKPoh3pKMzKG5m"
        self.base_url = "https://api.openai.com/v1"

    def chat(self, prompt: str):
        headers = {"Authorization": f"Bearer {self.api_key}"}
        return requests.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json={"model": "gpt-4", "messages": [{"role": "user", "content": prompt}]},
        )


# --- 5. Database config as nested dict (common config pattern) ---
DB_CONFIG = {
    "host": "10.0.4.22",
    "port": 5432,
    "database": "prod_orders",
    "user": "appuser",
    "password": "Xk9#mQ2!vL7$pR4&nW8@",
}


def get_connection_string() -> str:
    return (
        f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}"
        f"@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
    )


@dataclass
class DatabaseSettings:
    url: str = "postgresql://appuser:Xk9#mQ2!vL7$pR4&nW8@@10.0.4.22:5432/prod_orders"
    pool_size: int = 10


# --- 6. Slack notification helper ---
def notify_slack(message: str):
    slack_token = "{{SYNTHETIC_SLACK_TOKEN}}"
    requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {slack_token}"},
        json={"channel": "#alerts", "text": message},
    )


# --- 7. SSH/deploy key loaded inline (multiline string, indented in function) ---
def get_deploy_key() -> str:
    private_key = """-----BEGIN RSA PRIVATE KEY-----
TO6pGvDgIkMd4xu+jSdFSJo1t1c0r6LaQ4F9QOfo2A0XomzURgsAVcUho/pDKb1x
jbRtjwIcE/HisOcmiwnVXpWNJW4gCk5d5u7L+NwK5ls1rj+qGlrHj+LfaPmevyfs
7jzdKfnMzy3haQYtvOxVyO5pzavdvM8/RCjJsxth3wnbeDgz0et1WU7Sy986OQao
MWZUR90R98VHWaSCZq3714lU8Acd4PhCLZT2+0MJG5hvWLrJUG+b+4IdYuaTMEEL
tW8AhezOia+48L28qzJdbhHyqutUn1Cp2R+45kyBT6poU2eyS40gMWuq8GGtv+cs
nZFNZ4zVAE1JNW7JlJunUndxcaw2gnnL5vXLvCuoFUiDqaKeVRfR88A8rE85zjIl
Bgs++3mc2cQSdGrioZMxt7JifmY+JaewAeTA3MXiG8dsOC3N9bKEdgyOP+rZH3Qi
zXaqh/yPmFHzweRxnNC45IFt1OiMcuUovtx5c0LAP9ejRsTHhXygPUZwE7ZJPEVV
UeSKFCMmO2KxJ7Q2EGpoVIp3ag801Wtj58WV8rIF2+HDk2F6AfFaTMBj2uT01WuJ
v7yLzJrlOHw4RW98B2NWq63MZ7kq13frIPufiAboZJeQqQYVpG0i3XYuDEJhUzZ0
U1bC4WFHwPPUa0DVFHgEv4oN//NZOaYRx/WmCsEH8z8z1gWfJz0geasdkPI3d7NB
xF4qm5v2v7cdx9Ep9k8blAbtT5Ot6PVgZfG3MhOXsNSgPhqyxU3Zr5nOHsv7kMgK
WIhtqV4RgaVXA9lr0n0bbvVcouTUdbUn
-----END RSA PRIVATE KEY-----"""
    return private_key


# --- 8. Should NOT be detected (decoys, kept from original fixture) ---
NORMAL_VAR = "database_connection_helper"
TEST_KEY = "test-placeholder-not-real"


def helper_function(connection_helper: str = NORMAL_VAR):
    """A normal utility function with a normal default arg — not a secret."""
    return connection_helper.upper()


if __name__ == "__main__":
    print(get_connection_string())
