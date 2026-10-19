"""Ship common operational code into independent build contexts; check drift."""
import argparse
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    changed=[]
    for app in (ROOT/'services').glob('*/app'):
        for source,target in [('private_state.py','private_state.py'),('operational.py','runtime.py'),('readiness.py','readiness.py'),('ttl_cache.py','ttl_cache.py'),('redaction.py','redaction.py'),('dependency_graph.py','dependency_graph.py'),('go_modules.py','go_modules.py'),('bounded_yaml.py','bounded_yaml.py'),('dependency_manifests.py','dependency_manifests.py'),('registry_metadata.py','registry_metadata.py'),('advisories.py','advisories.py')]:
            if target=='private_state.py' and app.parent.name not in {'trust_engine','docker_security','prompt_injection'}:continue
            if target=='advisories.py' and app.parent.name not in {'cipherguard','docker_security'}:continue
            if target in {'dependency_manifests.py','registry_metadata.py','go_modules.py'} and app.parent.name not in {'cipherguard','license_compliance'}:continue
            if target=='bounded_yaml.py' and app.parent.name not in {'docker_security','workflow_cicd'}:continue
            if target=='dependency_graph.py' and app.parent.name not in {'cipherguard','license_compliance'}:continue
            if target=='redaction.py' and app.parent.name not in {'trust_engine','docker_security','prompt_injection'}:continue
            if target=='readiness.py' and app.parent.name in {'code_security','trust_engine'}:continue
            if target=='ttl_cache.py' and app.parent.name not in {'cipherguard','license_compliance','docker_security','prompt_injection'}:continue
            content=(ROOT/'runtime'/source).read_bytes();path=app/target
            if not path.exists() or path.read_bytes()!=content:
                changed.append(str(path.relative_to(ROOT)))
                if not args.check:path.write_bytes(content)
    if args.check and changed: print('\n'.join(changed));return 1
    print('Operational runtime copies match.' if args.check else f'Updated {len(changed)} runtime copies.')
    return 0
if __name__=='__main__':raise SystemExit(main())
