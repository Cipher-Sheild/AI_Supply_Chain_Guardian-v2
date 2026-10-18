#!/usr/bin/env python3
"""PreToolUse gate: inspect proposed file contents without writing them.

Supports VS Code Local snake_case and Copilot camelCase hook payloads.
Unknown tools are denied; this is deliberately a restricted agent workflow.
"""
import argparse
import json
import os
import re
from pathlib import Path
import shlex
import signal
import stat
import sys
import time
from urllib.parse import quote, urlsplit

from guardian_http import request_json
from guardian_cli import exit_code

LIMIT = 262144
READ_TOOLS = frozenset({
    'read_file', 'list_dir', 'file_search', 'grep_search', 'semantic_search',
    'get_errors', 'list_code_usages', 'manage_todo_list', 'ask_questions',
    'Read', 'Grep', 'Glob', 'TodoWrite', 'AskUserQuestion', 'view', 'grep', 'rg', 'glob',
    'task_complete',
})
CREATE_TOOLS = frozenset({'create_file', 'create', 'Write'})
EDIT_TOOLS = frozenset({'replace_string_in_file', 'edit', 'Edit'})


def target_path(root, value):
    if not isinstance(value, str) or not value:
        raise ValueError('Missing file path')
    path = Path(value)
    path = path if path.is_absolute() else root / path
    # Do not follow a link to read a different artifact from the tool target.
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        raise ValueError('Symlink targets are not supported')
    path = path.resolve()
    if not path.is_relative_to(root):
        raise ValueError('Target is outside the protected workspace')
    relative = path.relative_to(root)
    workflow = (len(relative.parts) == 3 and relative.parts[:2] == ('.github', 'workflows')
                and relative.suffix.lower() in {'.yml', '.yaml'})
    if any(p in {'.git', '.vscode', '.guardian'} for p in relative.parts) or ('.github' in relative.parts and not workflow):
        raise ValueError('Agent changes to control/configuration directories require manual review')
    if path.exists() and (not path.is_file() or path.stat().st_size > LIMIT):
        raise ValueError('Target must be a regular file under 256 KiB')
    return path


def patch_edits(patch, root):
    """Reconstruct a conservative Add/Update patch subset entirely in memory.

    Reject deletes, renames, ambiguous context and unsupported syntax. This is
    intentionally stricter than a patch executor: uncertain proposals are denied.
    """
    if not isinstance(patch, str) or len(patch.encode('utf-8')) > 1048576:
        raise ValueError('Invalid patch budget')
    lines = patch.splitlines()
    if not lines or lines[0] != '*** Begin Patch' or lines[-1] != '*** End Patch':
        raise ValueError('Expected complete patch envelope')
    pending = []
    seen = set()
    i = 1
    while i < len(lines) - 1:
        header = lines[i]
        adding = header.startswith('*** Add File: ')
        updating = header.startswith('*** Update File: ')
        if not adding and not updating:
            raise ValueError('Only Add File and Update File patches are supported')
        path = target_path(root, header.split(': ', 1)[1])
        if path in seen:
            raise ValueError('Repeated patch target')
        seen.add(path)
        i += 1
        original = path.read_bytes() if path.exists() else None
        if adding:
            if original is not None:
                raise ValueError('Add target already exists')
            out = []
            while i < len(lines) - 1 and not lines[i].startswith('*** '):
                if not lines[i].startswith('+'):
                    raise ValueError('Invalid added line')
                out.append(lines[i][1:]); i += 1
            content = ''.join(line + '\n' for line in out)
        else:
            if original is None:
                raise ValueError('Update target does not exist')
            content = original.decode('utf-8')
            if '\r' in content or (content and not content.endswith('\n')):
                raise ValueError('Only LF-terminated update targets supported')
            cursor = 0
            hunks = 0
            while i < len(lines) - 1 and not lines[i].startswith('*** '):
                if lines[i] != '@@':
                    raise ValueError('Only explicit unlabelled context hunks supported')
                i += 1; old = []; new = []
                while i < len(lines) - 1 and lines[i] != '@@' and not lines[i].startswith('*** '):
                    line = lines[i]
                    if not line or line[0] not in ' +-':
                        raise ValueError('Invalid patch hunk')
                    if line[0] in ' -': old.append(line[1:] + '\n')
                    if line[0] in ' +': new.append(line[1:] + '\n')
                    i += 1
                before, after = ''.join(old), ''.join(new)
                if not before or content.count(before) != 1:
                    raise ValueError('Patch context must match exactly once')
                index = content.find(before)
                if index < cursor:
                    raise ValueError('Out-of-order patch hunks')
                content = content[:index] + after + content[index + len(before):]
                cursor = index + len(after); hunks += 1
            if not hunks:
                raise ValueError('Empty update patch')
        if len(content.encode('utf-8')) > LIMIT:
            raise ValueError('Patched file exceeds budget')
        pending.append((path, content, original))
        if len(pending) > 50 or sum(len(c.encode('utf-8')) for _, c, _ in pending) > 1048576:
            raise ValueError('Patch exceeds scan budget')
    if not pending:
        raise ValueError('Empty patch')
    return pending


def proposed_files(event, root):
    tool = event.get('tool_name', event.get('toolName'))
    args = event.get('tool_input', event.get('toolArgs'))
    # VS Code's SDK bridge canonicalizes its freeform apply_patch as Edit.
    # Recognize only an actual patch envelope; structured Edit stays below.
    if tool == 'Edit' and isinstance(args, str):
        try: decoded_patch = json.loads(args)
        except json.JSONDecodeError: decoded_patch = args
        if isinstance(decoded_patch, str) and decoded_patch.startswith('*** Begin Patch'):
            return patch_edits(decoded_patch, root)
    if tool == 'apply_patch':
        if isinstance(args, dict):
            args = args.get('input', args.get('patch'))
        elif isinstance(args, str) and not args.startswith('*** Begin Patch'):
            decoded = json.loads(args)
            args = decoded.get('input', decoded.get('patch')) if isinstance(decoded, dict) else decoded
        return patch_edits(args, root)
    if tool == 'task_complete' and args is None:
        args = {}
    if isinstance(args, str):
        args = json.loads(args)
    if not isinstance(tool, str) or not isinstance(args, dict):
        raise ValueError('Invalid tool payload')
    if tool in READ_TOOLS:
        return []
    if tool == 'multi_replace_string_in_file':
        edits = args.get('replacements')
        if not isinstance(edits, list) or not 1 <= len(edits) <= 50:
            raise ValueError('Invalid replacements')
    elif tool in CREATE_TOOLS | EDIT_TOOLS:
        edits = [args]
    else:
        raise ValueError('Unsupported tool blocked: use create_file or replace_string_in_file; terminal and delegated tools require manual review; apply_patch accepts only the restricted Add/Update format')
    pending = {}
    originals = {}
    for edit in edits:
        if not isinstance(edit, dict):
            raise ValueError('Invalid edit')
        path = target_path(root, edit.get('filePath', edit.get('file_path', edit.get('path'))))
        if path not in originals:
            originals[path] = path.read_bytes() if path.exists() else None
        if tool in CREATE_TOOLS:
            content = edit.get('content', edit.get('file_text'))
        else:
            current = pending.get(path)
            if current is None:
                if originals[path] is None:
                    raise ValueError('Replacement target does not exist')
                current = originals[path].decode('utf-8')
            old = edit.get('oldString', edit.get('old_str', edit.get('old_string')))
            new = edit.get('newString', edit.get('new_str', edit.get('new_string')))
            if not isinstance(old, str) or not old or not isinstance(new, str) or current.count(old) != 1:
                raise ValueError('Replacement must match exactly one existing string')
            content = current.replace(old, new, 1)
        if not isinstance(content, str) or len(content.encode('utf-8')) > LIMIT:
            raise ValueError('Proposed content must be UTF-8 text under 256 KiB')
        pending[path] = content
    if len(pending) > 50 or sum(len(v.encode('utf-8')) for v in pending.values()) > 1048576:
        raise ValueError('Proposed change exceeds the scan budget')
    return [(path, content, originals[path]) for path, content in pending.items()]


def evaluate(event, root, url, wait_seconds=20):
    files = proposed_files(event, root)
    if not files:
        return 'allow', 'Guardian: recognized read-only/planning/completion tool.'
    deadline = time.monotonic() + wait_seconds
    result = request_json(url.rstrip('/') + '/analyze/batch', {
        'files': [{'filename': str(path), 'content': content} for path, content, _ in files]
    }, timeout=min(10, wait_seconds))
    while isinstance(result, dict) and result.get('scan_status') == 'provisional':
        remaining = deadline - time.monotonic()
        if remaining <= .1:
            raise TimeoutError('Final decision did not arrive; no edit allowed')
        request_id = result.get('request_id')
        if not isinstance(request_id, str) or not request_id:
            raise ValueError('Missing scan identifier')
        time.sleep(min(.25, remaining))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Final decision did not arrive')
        result = request_json(url.rstrip('/') + '/scans/' + quote(request_id, safe=''), timeout=min(5, remaining))
    if not isinstance(result, dict) or time.monotonic() > deadline or exit_code(result, 0) != 0:
        scan_id = result.get('request_id') if isinstance(result, dict) else None
        reference = ('; scan ' + scan_id) if isinstance(scan_id, str) and re.fullmatch(r'[a-f0-9]{32}', scan_id) else ''
        return 'deny', 'Guardian: proposed edit blocked (review, reject, incomplete or invalid response)' + reference + '. See Guardian scan history for findings.'
    for path, _, original in files:
        target_path(root, str(path))
        if (path.read_bytes() if path.exists() else None) != original:
            return 'deny', 'Guardian: target changed during inspection; regenerate and scan again.'
    return 'allow', f'Guardian: proposed content accepted; scan {result.get("request_id", "unknown")}, score {result["trust_score"]}/100.'


def load_client_key(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65536 or (os.name != "nt" and metadata.st_mode & 0o077):
        raise ValueError("Client configuration must be a private regular file under 64 KiB")
    keys = [line.split("=", 1)[1].strip() for line in path.read_text().splitlines() if line.startswith("GUARDIAN_API_KEY=")]
    if len(keys) != 1 or not keys[0] or any(c.isspace() or c in chr(34) + chr(39) for c in keys[0]):
        raise ValueError("A single unquoted Guardian client key is required")
    os.environ["GUARDIAN_API_KEY"] = keys[0]


def install(workspace, url, deployment_config=None):
    root = workspace.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Select a workspace directory')
    endpoint = urlsplit(url)
    if endpoint.scheme not in {'http', 'https'} or not endpoint.hostname or endpoint.username is not None or endpoint.password is not None or endpoint.query or endpoint.fragment:
        raise ValueError('Use an HTTP(S) server URL without credentials, query or fragment')
    if any((root / p).is_symlink() for p in ('.github', '.github/hooks')):
        raise ValueError('Hook configuration directories must not be symlinks')
    destination = root / '.github' / 'hooks' / 'guardian-preaccept.json'
    if destination.exists() or destination.is_symlink():
        raise ValueError('Guardian hook already exists; review it manually before replacing')
    command_args = [sys.executable, str(Path(__file__).resolve()), '--workspace', str(root), '--url', url]
    if deployment_config is not None:
        load_client_key(deployment_config)
        command_args += ['--deployment-config', str(deployment_config.resolve())]
    command = shlex.join(command_args)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps({'hooks': {'PreToolUse': [
        {'type': 'command', 'command': command, 'timeout': 30}
    ]}}, indent=2) + '\n')
    print(f'Installed {destination}. Enable chat.useHooks and verify discovery with Chat: Configure Hooks in a trusted VS Code Local session.')


def append_audit(path, event, decision, reason):
    """Operator-selected private log: shape/outcome only, never proposed text."""
    import hashlib
    from datetime import datetime, timezone
    args = event.get('tool_input', event.get('toolArgs')) if isinstance(event, dict) else None
    tool = event.get('tool_name', event.get('toolName')) if isinstance(event, dict) else None
    record = {'timestamp': datetime.now(timezone.utc).isoformat(),
        'tool': tool if isinstance(tool, str) and len(tool) < 100 else None,
        'event_keys': sorted(event) if isinstance(event, dict) else [],
        'args_type': type(args).__name__,
        'args_keys': sorted(args) if isinstance(args, dict) else [],
        'input_type': type(args.get('input')).__name__ if isinstance(args, dict) else None,
        'permissionDecision': decision, 'reason': reason,
        'adapter_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_size > 8 * 1048576:
            raise ValueError('Invalid private audit file')
        os.fchmod(fd, 0o600)
        os.write(fd, (json.dumps(record) + '\n').encode())
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--url', default=os.getenv('GUARDIAN_URL', 'http://127.0.0.1:8000'))
    parser.add_argument('--deployment-config', type=Path, help='Private client configuration outside the agent workspace.')
    parser.add_argument('--audit-log', type=Path, help='Optional private operator audit log outside the agent workspace; never records proposed text.')
    parser.add_argument('--install', action='store_true', help='Install a VS Code Local hook in the selected workspace (Linux/macOS).')
    args = parser.parse_args()
    if args.install:
        install(args.workspace, args.url, args.deployment_config)
        return 0
    event = None
    decision, reason = 'deny', 'Guardian: inspection failed; no edit allowed.'
    try:
        # Finish before the editor's 30-second hook timeout, which is not a security boundary.
        if hasattr(signal, 'SIGALRM'):
            def expired(*_):
                raise TimeoutError('Guardian hook deadline exceeded')
            signal.signal(signal.SIGALRM, expired)
            signal.alarm(25)
        if args.deployment_config is not None:
            load_client_key(args.deployment_config)
        raw = sys.stdin.buffer.read(2 * 1048576 + 1)
        if len(raw) > 2 * 1048576:
            raise ValueError('Hook input exceeds data budget')
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError('Hook event must be an object')
        decision, reason = evaluate(event, args.workspace.resolve(strict=True), args.url)
    except Exception as exc:
        # Do not echo tool content, secrets, server messages or paths back into the agent context.
        reason = f'Guardian: inspection unavailable or unsupported ({type(exc).__name__}); edit blocked.'
    finally:
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)
    if args.audit_log is not None:
        try:
            if args.audit_log.resolve().is_relative_to(args.workspace.resolve()):
                raise ValueError('Audit log must be outside workspace')
            append_audit(args.audit_log, event, decision, reason)
        except Exception:
            decision, reason = 'deny', 'Guardian: private audit unavailable; edit blocked.'
    print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse',
        'permissionDecision': decision, 'permissionDecisionReason': reason},
        'permissionDecision': decision, 'permissionDecisionReason': reason}))
    if decision == 'deny':
        print(reason, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
