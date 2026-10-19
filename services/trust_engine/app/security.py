"""Deployment access control with scoped tenant credentials.

Local mode accepts only loopback clients without a configured key. Production
mode requires a strong key at startup. TLS belongs at the deployment ingress.
"""
import hmac
import os
import json
import re
from contextvars import ContextVar
from urllib.parse import urlsplit
from starlette.responses import JSONResponse
current_tenant=ContextVar('guardian_tenant',default='owner')

def deployment_keys():
    keys=json.loads(os.getenv('GUARDIAN_TENANT_KEYS') or '{}')
    if not isinstance(keys,dict):raise ValueError('tenant keys must be an object')
    if os.getenv('GUARDIAN_API_KEY'):keys.setdefault('owner',os.environ['GUARDIAN_API_KEY'])
    if any(not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}',name) or not isinstance(key,str) or len(key.encode())<32 for name,key in keys.items()):
        raise ValueError('tenant keys require valid tenant identifiers and keys of at least 32 bytes')
    if len(set(keys.values()))!=len(keys):raise ValueError('tenant keys must be distinct')
    return keys


def validate_configuration():
    if os.getenv('GUARDIAN_ENV','local') == 'production':
        if not deployment_keys():
            raise RuntimeError('production requires GUARDIAN_API_KEY of at least 32 bytes')
        callback=os.getenv('CALLBACK_TOKEN','')
        if len(callback.encode())<32:
            raise RuntimeError('production requires CALLBACK_TOKEN of at least 32 bytes')
        if callback in deployment_keys().values():
            raise RuntimeError('callback and API credentials must be distinct')


def local_browser_request(scope, headers):
    """Reject DNS rebinding and foreign browser origins in keyless local mode."""
    allowed = {'localhost', '127.0.0.1', '::1'}
    if (scope.get('client') or ('', 0))[0] == 'testclient':
        allowed.add('testserver')
    try:
        host = urlsplit('http://' + headers.get(b'host', b'').decode('ascii'))
        if host.hostname not in allowed or host.username or host.password:
            return False
        # Accessing port validates malformed port syntax as well.
        host.port
        origin = headers.get(b'origin')
        if origin:
            parsed = urlsplit(origin.decode('ascii'))
            if parsed.scheme not in {'http', 'https'} or parsed.hostname not in allowed or parsed.username or parsed.password:
                return False
            parsed.port
        return headers.get(b'sec-fetch-site', b'') != b'cross-site'
    except (ValueError, UnicodeError):
        return False


class AccessMiddleware:
    def __init__(self,app):self.app=app

    async def __call__(self,scope,receive,send):
        if scope['type'] != 'http':
            return await self.app(scope,receive,send)
        path=scope.get('path','')
        # Callbacks have their own scoped token validation in the endpoint.
        if path == '/health' or (path.startswith('/callback/') and scope.get('method') == 'POST'):
            token=current_tenant.set('owner')
            try:return await self.app(scope,receive,send)
            finally:current_tenant.reset(token)
        headers={k.lower():v for k,v in scope.get('headers',[])}
        try:configured=deployment_keys()
        except (ValueError,TypeError):
            return await JSONResponse({'detail':'Deployment authentication configuration invalid'},status_code=503)(scope,receive,send)
        authorization=headers.get(b'authorization',b'')
        tenant=next((name for name,key in configured.items() if hmac.compare_digest(authorization,b'Bearer '+key.encode())),None)
        valid=tenant is not None
        host=(scope.get('client') or ('',0))[0]
        local=host in {'127.0.0.1','::1','testclient'}
        if not valid and (configured or not local or os.getenv('GUARDIAN_ENV','local') == 'production'):
            response=JSONResponse({'detail':'Guardian authentication required'},status_code=401,
                                  headers={'WWW-Authenticate':'Bearer'})
            return await response(scope,receive,send)
        if not valid and not local_browser_request(scope, headers):
            return await JSONResponse({'detail':'Local host and origin required'},status_code=403)(scope,receive,send)
        token=current_tenant.set(tenant or 'owner')
        try:await self.app(scope,receive,send)
        finally:current_tenant.reset(token)
