import io
import tarfile
import pytest
from app.engines.oci_inventory import apply_layer,packages_from_files


def layer(files):
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
        for name,content in files.items():
            raw=content.encode();info=tarfile.TarInfo(name);info.size=len(raw);archive.addfile(info,io.BytesIO(raw))
    return buffer.getvalue()


def test_alpine_inventory_and_whiteout_order():
    files={}
    apply_layer(layer({'etc/os-release':'ID=alpine\nVERSION_ID=3.20.8\n','lib/apk/db/installed':'P:openssl-lib\nV:3.3.2-r0\no:openssl\n\n'}),files)
    packages,release=packages_from_files(files)
    assert packages==[{'ecosystem':'Alpine:v3.20','name':'openssl','version':'3.3.2-r0'}]
    apply_layer(layer({'lib/apk/db/.wh.installed':''}),files)
    assert 'lib/apk/db/installed' not in files


def test_tar_traversal_rejected_without_extraction():
    with pytest.raises(ValueError):apply_layer(layer({'../../etc/passwd':'unsafe'}),{})


def test_debian_source_package_version_used():
    files={'etc/os-release':b'ID=debian\nVERSION_ID="12"\n','var/lib/dpkg/status':b'Package: libssl3\nStatus: install ok installed\nSource: openssl (3.0.11-1)\nVersion: 3.0.11-1+b1\n\n'}
    packages,_=packages_from_files(files)
    assert packages[0]['name']=='openssl' and packages[0]['version']=='3.0.11-1'


def test_unsupported_inventory_never_claims_clean():
    with pytest.raises(ValueError):packages_from_files({'etc/os-release':b'ID=unknown'})


@pytest.mark.parametrize("whiteout", ["lib/apk/db/.wh.installed", "lib/apk/db/.wh..wh..opq"])
def test_whiteout_does_not_delete_same_layer_replacement(whiteout):
    files={'lib/apk/db/installed':b'old'}
    apply_layer(layer({'lib/apk/db/installed':'new',whiteout:''}),files)
    assert files['lib/apk/db/installed']==b'new'


def test_root_opaque_whiteout_removes_lower_files():
    files={'etc/os-release':b'old','var/lib/dpkg/status':b'old'}
    apply_layer(layer({'etc/os-release':'new','.wh..wh..opq':''}),files)
    assert files=={'etc/os-release':b'new'}


@pytest.mark.asyncio
async def test_mutable_tags_are_rechecked_but_verified_inventory_is_reused(monkeypatch):
    import hashlib,json,httpx
    from app.engines import oci_inventory as module
    module._inventory_cache.clear()
    config=json.dumps({'os':'linux','architecture':'amd64'}).encode()
    raw_layer=layer({'etc/os-release':'ID=alpine\nVERSION_ID=3.20.8\n','lib/apk/db/installed':'P:sample\nV:1.0-r0\n\n'})
    digest=lambda raw:'sha256:'+hashlib.sha256(raw).hexdigest()
    manifest=json.dumps({'config':{'digest':digest(config)},'layers':[{'digest':digest(raw_layer),'size':len(raw_layer)}]}).encode()
    calls=[]
    def response(request):
        calls.append(request.url.path)
        if request.url.host=='auth.docker.io':return httpx.Response(200,json={'token':'fake-unit-token'})
        if '/manifests/' in request.url.path:return httpx.Response(200,content=manifest)
        if request.url.path.endswith(digest(config)):return httpx.Response(200,content=config)
        if request.url.path.endswith(digest(raw_layer)):return httpx.Response(200,content=raw_layer)
        return httpx.Response(404)
    real_client=httpx.AsyncClient
    monkeypatch.setattr(module.httpx,'AsyncClient',lambda **kwargs:real_client(transport=httpx.MockTransport(response),**kwargs))
    first=await module.inventory('alpine:3.20');second=await module.inventory('alpine:latest')
    assert first['packages']==second['packages'] and second['image_ref']=='alpine:latest'
    assert sum('/manifests/' in path for path in calls)==2
    assert sum('/blobs/' in path for path in calls)==2
    module._inventory_cache.clear()
