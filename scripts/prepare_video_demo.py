#!/usr/bin/env python3
"""Prepare a separate trusted VS Code demo workspace without creating demo source files."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--url', default='http://127.0.0.1:8000')
    parser.add_argument('--deployment-config', type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.expanduser().resolve()
    if workspace == ROOT or ROOT in workspace.parents:
        parser.error('Use a separate workspace outside the Guardian checkout')
    # Health does not transmit the private client key.
    with urlopen(args.url.rstrip('/') + '/health', timeout=15) as response:
        health = json.load(response)
    if health.get('status') != 'ok' or not all(health.get('checks', {}).values()):
        raise RuntimeError('Backend is not ready; inspect its health checks before filming')
    workspace.mkdir(parents=True, exist_ok=True)
    hook = workspace / '.github/hooks/guardian-preaccept.json'
    settings = workspace / '.vscode/settings.json'
    if hook.exists() or settings.exists():
        parser.error('Workspace already has hook/settings files; use a fresh directory to preserve them')
    subprocess.run([sys.executable, str(ROOT / 'scripts/guardian_pretool.py'), '--install',
                    '--workspace', str(workspace), '--url', args.url,
                    '--deployment-config', str(args.deployment_config.expanduser().resolve())], check=True)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({'chat.useHooks': True, 'guardian.serverUrl': args.url,
                                    'guardian.scanOnSave': False}, indent=2) + '\n')
    # Record only the audit path, never the key, in the hook command.
    data = json.loads(hook.read_text())
    audit = args.deployment_config.expanduser().resolve().parent / 'video-pretool-audit.jsonl'
    data['hooks']['PreToolUse'][0]['command'] += ' --audit-log ' + shlex.quote(str(audit))
    hook.write_text(json.dumps(data, indent=2) + '\n')
    print('Ready:', workspace)
    print('No video_safe.py, video_unsafe.py or package.json was created by setup.')
    print('Open this folder in VS Code, trust it, verify Chat: Configure Hooks, then use Copilot Local Agent.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
