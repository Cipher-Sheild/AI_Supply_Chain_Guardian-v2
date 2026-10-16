#!/usr/bin/env python3
"""Create private deployment credentials without printing or overwriting them."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'.data/deployment/config.env')
    parser.add_argument('--tenant',action='append',default=[])
    parser.add_argument('--api-port',type=int,default=8000)
    parser.add_argument('--dashboard-port',type=int,default=3000)
    parser.add_argument('--tls-port',type=int,default=3443)
    args=parser.parse_args()
    if any(not 1024<=port<=65535 for port in [args.api_port,args.dashboard_port,args.tls_port]):
        parser.error('Ports must be between 1024 and 65535')
    if len({args.api_port,args.dashboard_port,args.tls_port})!=3:parser.error('Ports must be distinct')
    if any(not re.fullmatch(r'[A-Za-z0-9._-]{1,64}',tenant) or tenant=='owner' for tenant in args.tenant):
        parser.error('Tenant identifiers must be 1–64 letters, digits, dots, underscores, or hyphens; owner is reserved')
    path=args.output.absolute()
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.parent.is_relative_to(ROOT/'.data'):path.parent.chmod(0o700)
    values={'GUARDIAN_ENV':'production','GUARDIAN_API_KEY':secrets.token_hex(32),
        'CALLBACK_TOKEN':secrets.token_hex(32),'POSTGRES_PASSWORD':secrets.token_hex(32),
        'GUARDIAN_TENANT_KEYS':json.dumps({tenant:secrets.token_hex(32) for tenant in args.tenant},separators=(',',':')),
        'TRUST_ENGINE_PORT':str(args.api_port),'DASHBOARD_PORT':str(args.dashboard_port),
        'GUARDIAN_TLS_PORT':str(args.tls_port),'GUARDIAN_TLS_DIR':str(path.parent/'tls'),'TRUST_SCORER':'weighted','LLM_PROVIDER':'ollama',
        'SCAN_RETENTION_DAYS':'30'}
    try:descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError:parser.error('Configuration already exists; refusing to replace credentials')
    with os.fdopen(descriptor,'w') as stream:
        stream.write(''.join(f'{name}={value}\n' for name,value in values.items()))
    print('Private deployment configuration created:',path)
    print('Use this file with docker compose --env-file and guardian --deployment-config.')
    print('Prepare localhost TLS with scripts/setup_demo_tls.py --directory',path.parent/'tls')


if __name__=='__main__':main()
