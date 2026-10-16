"""Refresh owned exact-text license data from a pinned official SPDX archive.

Only bounded regular text members are read; archive paths are never extracted.
"""
import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path

REVISION='31ba1a50e5397e00a304dbadc76531740e89ee48'
ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive',type=Path)
    args=parser.parse_args()
    target=ROOT/'services/license_compliance/app/data/spdx'
    prefix=f'license-list-data-{REVISION}/'
    with tarfile.open(args.archive,'r|gz') as archive:
        for member in archive:
            if member.name==prefix+'json/licenses.json':
                if not member.isfile() or member.size>2000000:raise ValueError('Invalid SPDX index')
                index=json.load(archive.extractfile(member));break
        else:raise ValueError('SPDX index missing')
    expected={entry['licenseId'] for entry in index['licenses'] if not entry['isDeprecatedLicenseId']}
    if any(not re.fullmatch(r'[A-Za-z0-9.+-]+',key) for key in expected):raise ValueError('Invalid license identifier')
    files={};payloads={}
    # Sequential streaming avoids repeated decompression of the large archive.
    with tarfile.open(args.archive,'r|gz') as archive:
        for member in archive:
            if not member.name.startswith(prefix+'text/'):continue
            identifier=member.name[len(prefix+'text/'):-4] if member.name.endswith('.txt') else ''
            if identifier not in expected:continue
            if not member.isfile() or member.size>1000000:raise ValueError('Invalid license member')
            raw=archive.extractfile(member).read();raw.decode('utf-8')
            files[identifier]={'url':f'https://raw.githubusercontent.com/spdx/license-list-data/{REVISION}/text/{identifier}.txt','sha256':hashlib.sha256(raw).hexdigest()}
            payloads[identifier]=raw
    if set(payloads)!=expected:raise ValueError('SPDX templates missing')
    manifest={'source':'https://github.com/spdx/license-list-data','revision':REVISION,
              'license_list_version':index['licenseListVersion'],
              'archive_sha256':hashlib.sha256(args.archive.read_bytes()).hexdigest(),
              'matching':'Conservative exact normalized text; ambiguous matches require review.',
              'files':dict(sorted(files.items()))}
    for identifier,raw in payloads.items():(target/(identifier+'.txt')).write_bytes(raw)
    for existing in target.glob('*.txt'):
        if existing.stem not in payloads:existing.unlink()
    (target/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'licenses':len(files),'revision':REVISION}))

if __name__=='__main__':main()
