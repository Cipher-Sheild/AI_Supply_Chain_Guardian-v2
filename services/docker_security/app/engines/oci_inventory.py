"""Guardian-owned OCI layer inventory reader for public Docker Hub images.

Layers are streamed and verified, never extracted to disk or executed. Only
package-manager databases and OS identity files are retained across layers.
"""
import hashlib
import io
import json
import tarfile
import asyncio
from urllib.parse import urlsplit
import httpx
from app.registry.image_reference import ImageReference
from app.ttl_cache import TTLCache
_inventory_cache=TTLCache(max_entries=64,ttl=3600)

TARGETS={'lib/apk/db/installed','var/lib/dpkg/status','etc/os-release','usr/lib/os-release'}
ACCEPT='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'


async def retry_transient(operation):
    """At most three attempts; never turn missing/auth/bad-content into clean."""
    for attempt in range(3):
        try:
            result = await operation()
            if isinstance(result, httpx.Response): result.raise_for_status()
            return result
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise
        except httpx.TransportError:
            if attempt == 2: raise
        await asyncio.sleep(0.25 * (2 ** attempt))


def apply_layer(raw,files):
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:*') as archive:
        count=0;expanded=0;updates={}
        for member in archive:
            count+=1
            if count>100000:raise ValueError('OCI layer entry budget exceeded')
            expanded+=member.size
            if member.size>256*1024*1024 or expanded>512*1024*1024:raise ValueError('OCI expanded layer budget exceeded')
            name=member.name.removeprefix('./').lstrip('/')
            if '..' in name.split('/'):raise ValueError('OCI layer traversal path')
            parent,_,base=name.rpartition('/')
            if base=='.wh..wh..opq':
                for target in list(files):
                    if not parent or target.startswith(parent+'/'):files.pop(target,None)
            elif base.startswith('.wh.'):
                removed=(parent+'/' if parent else '')+base[4:]
                for target in list(files):
                    if target==removed or target.startswith(removed+'/'):files.pop(target,None)
            elif name in TARGETS:
                if not member.isfile():updates[name]=None;continue
                if member.size>8*1024*1024:raise ValueError('package database exceeds inventory budget')
                stream=archive.extractfile(member)
                updates[name]=stream.read(8*1024*1024+1)
        # Whiteouts affect the lower layer, regardless of archive entry order.
        for name,content in updates.items():
            if content is None:files.pop(name,None)
            else:files[name]=content


def packages_from_files(files):
    identity=files.get('etc/os-release',files.get('usr/lib/os-release',b'')).decode('utf-8',errors='replace')
    release={}
    for line in identity.splitlines():
        if '=' in line:
            key,value=line.split('=',1);release[key]=value.strip('"\'')
    packages=[];os_name=release.get('ID');version=release.get('VERSION_ID','')
    if os_name=='alpine' and 'lib/apk/db/installed' in files:
        ecosystem='Alpine:v'+'.'.join(version.split('.')[:2])
        for block in files['lib/apk/db/installed'].decode(errors='replace').split('\n\n'):
            values=dict(line.split(':',1) for line in block.splitlines() if ':' in line)
            name=values.get('o') or values.get('P');installed=values.get('V')
            if name and installed:packages.append({'ecosystem':ecosystem,'name':name,'version':installed})
    elif os_name=='debian' and 'var/lib/dpkg/status' in files:
        ecosystem='Debian:'+version.split('.')[0]
        for block in files['var/lib/dpkg/status'].decode(errors='replace').split('\n\n'):
            values=dict(line.split(': ',1) for line in block.splitlines() if ': ' in line and not line.startswith(' '))
            if values.get('Status')!='install ok installed':continue
            package=values.get('Package');installed=values.get('Version')
            if package and installed:
                source=values.get('Source','').split()
                if source:
                    package=source[0]
                    if len(source)>1:installed=source[1].strip('()')
                packages.append({'ecosystem':ecosystem,'name':package,'version':installed})
    else:raise ValueError('OS/package database format not supported for image advisory attribution')
    unique={(item['ecosystem'],item['name'],item['version']):item for item in packages}
    if not unique:raise ValueError('no installed package inventory was established')
    return list(unique.values()),release


async def inventory(reference):
    ref=ImageReference.parse(reference)
    if ref.registry not in {'docker.io','index.docker.io','registry-1.docker.io'}:
        raise ValueError('OCI adapter currently accepts public Docker Hub references')
    repository=ref.repository
    if repository.startswith(ref.registry+'/'):repository=repository[len(ref.registry)+1:]
    if '/' not in repository:repository='library/'+repository
    base='https://registry-1.docker.io/v2/'+repository
    async with httpx.AsyncClient(timeout=15,follow_redirects=False) as client:
        response=await retry_transient(lambda: client.get('https://auth.docker.io/token',params={'service':'registry.docker.io','scope':'repository:'+repository+':pull'}))
        response.raise_for_status();token=response.json()['token']
        headers={'Authorization':'Bearer '+token,'Accept':ACCEPT}
        async def fetch_once(url,maximum,digest=None):
            authorization=headers if url.startswith(base+'/') else {'Accept':ACCEPT}
            for _ in range(5):
                async with client.stream('GET',url,headers=authorization) as response:
                    if response.is_redirect:
                        target=response.headers.get('location','');parsed=urlsplit(target)
                        host=parsed.hostname or ''
                        if parsed.scheme!='https' or not any(host==suffix or host.endswith('.'+suffix) for suffix in ('docker.com','docker.io','cloudflarestorage.com','amazonaws.com')):
                            raise ValueError('OCI redirect outside approved HTTPS storage hosts')
                        url=target;authorization={'Accept':ACCEPT};continue
                    response.raise_for_status();raw=bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw)>maximum:raise ValueError('OCI download exceeds inventory budget')
                    if digest and 'sha256:'+hashlib.sha256(raw).hexdigest()!=digest:
                        raise ValueError('OCI content digest mismatch')
                    return bytes(raw)
            raise ValueError('OCI redirect budget exceeded')
        async def fetch(url, maximum, digest=None):
            return await retry_transient(lambda: fetch_once(url, maximum, digest))
        raw=await fetch(base+'/manifests/'+(ref.digest or ref.tag),2*1024*1024,ref.digest or None)
        root_digest='sha256:'+hashlib.sha256(raw).hexdigest();manifest=json.loads(raw)
        if 'manifests' in manifest:
            selected=next((item for item in manifest['manifests'] if item.get('platform',{}).get('os')=='linux' and item.get('platform',{}).get('architecture')=='amd64'),None)
            if selected is None:raise ValueError('requested linux/amd64 image manifest unavailable')
            raw=await fetch(base+'/manifests/'+selected['digest'],2*1024*1024,selected['digest']);manifest=json.loads(raw)
        content_digest='sha256:'+hashlib.sha256(raw).hexdigest()
        cached=_inventory_cache.get(content_digest)
        if cached is not None:
            return {**cached,'image_ref':reference,'manifest_digest':root_digest}
        config_descriptor=manifest.get('config') or {}
        config_digest=config_descriptor.get('digest')
        if not config_digest:raise ValueError('OCI image config digest unavailable')
        config=json.loads(await fetch(base+'/blobs/'+config_digest,2*1024*1024,config_digest))
        if config.get('os')!='linux' or config.get('architecture')!='amd64':
            raise ValueError('OCI image config does not match supported linux/amd64 platform')
        files={};downloaded=0
        for layer in manifest.get('layers',[]):
            if layer.get('size',0)>64*1024*1024:raise ValueError('OCI layer exceeds download budget')
            raw=await fetch(base+'/blobs/'+layer['digest'],64*1024*1024,layer['digest'])
            downloaded+=len(raw)
            if downloaded>256*1024*1024:raise ValueError('OCI image exceeds download budget')
            await asyncio.to_thread(apply_layer,raw,files)
        packages,release=packages_from_files(files)
        result={'image_ref':reference,'manifest_digest':root_digest,'platform':'linux/amd64',
                'content_manifest_digest':content_digest,'packages':packages,'os_release':release,'layers_verified':len(manifest.get('layers',[])),
                'package_inventory_scope':'OS packages; language packages require their supplied lockfiles'}
        _inventory_cache.set(content_digest,result)
        return result
