# Inspect agent changes before they are written

The editor's scan-on-save feature is post-save inspection. The separate Guardian
PreToolUse adapter is a pre-write gate for supported VS Code **Local** agent tools.
It does not intercept inline Tab completions, manual edits, or every assistant.

## Set up a separate test workspace (Linux/macOS)

1. Start the Guardian backend using your existing launcher. Keep its actual URL
   handy: normally `http://127.0.0.1:8000` for Compose or port `18108` for the native
   launcher. Run a normal authenticated scan first to confirm the server is ready.
2. Create a test folder and install the hook from the Guardian repository:

   ```bash
   mkdir -p "$HOME/guardian-preaccept-demo"
   python3 scripts/guardian_pretool.py --install \
     --workspace "$HOME/guardian-preaccept-demo" \
     --url http://127.0.0.1:8000
   ```

   This creates `.github/hooks/guardian-preaccept.json` in the test folder. It
   references the adapter in the Guardian checkout using absolute paths; keep
   that checkout and Python installation available. It does not overwrite a hook.
3. For a private configuration file, add `--deployment-config /absolute/path/client.env`
   to the installer command. It must be a regular file under 64 KiB with mode
   `600`, containing one `GUARDIAN_API_KEY=...` line. The hook JSON stores only
   its path, not its contents. Keep it outside the agent workspace.

   Alternatively, the hook uses `GUARDIAN_API_KEY` from its process environment. In a dedicated
   terminal, enter the client key without placing it in shell history:

   ```bash
   read -rsp 'Guardian client API key: ' GUARDIAN_API_KEY
   export GUARDIAN_API_KEY
   echo
   code "$HOME/guardian-preaccept-demo"
   ```

   Fully exit VS Code first if an existing process would otherwise be reused:
   that process may not inherit the new environment. The existing extension's
   SecretStorage key is **not** automatically shared with the external hook.
   Never place a key in hook JSON, a prompt, or a committed file. Authenticated
   remote server URLs must use HTTPS; localhost HTTP is supported.
4. Use a VS Code version supporting agent hooks. Trust the test workspace, enable
   `chat.useHooks`, and run **Chat: Configure Hooks** to confirm the Guardian hook
   is discovered. Select the **Local** agent harness; other harnesses require
   separate compatibility verification. A visible hook configuration alone does
   not prove it is executing.
5. Start a new agent chat and prompt:

   > Create a small Node.js application with package.json and index.js. Use
   > create/create_file or restricted apply_patch additions for new files, and
   > structured replacements or restricted exact-context patch updates for changes. Guardian
   > must inspect each proposed change before the file tool runs. Do not use
   > terminal commands or subagents.

## Verify enforcement before relying on it

Use a disposable directory. Check **Output → GitHub Copilot Chat Hooks** and the
agent debug logs, plus Guardian's website scan history for the report. The
scan-on-save extension's Problems entries are a separate reporting mechanism.

- Ask for a small supported safe source file. The hook must return a final
  `accept` before the tool executes; the detector can still require review for
  incomplete coverage.
- Ask it to create `unsafe.py` containing `def run(x): return eval(x)`. Confirm a
  reject/review denies the tool and that the file does not appear on disk.
- Stop the backend and repeat. Confirm the hook returns a blocking decision and
  no file is written. Restart the backend afterward.
- Try a terminal write or unsupported edit tool. It must be denied, not silently
  bypass inspection.

The adapter reconstructs `create_file`/`create`/`Write`, exact single-string
replacement (`replace_string_in_file`/`edit`/`Edit`), and
`multi_replace_string_in_file` inputs in memory. It scans the **full resulting
contents**, not merely added strings, via `/analyze/batch`. Multiple replacements
of one file are composed before inspection. Review, reject, invalid responses,
service failure, and non-final scans deny the call. A changed target invalidates
approval. No proposed artifact is written by the adapter itself; the editor
executes an approved tool call afterward.

Unknown tools, terminal execution, unsupported patch forms, delegation, writes outside the
workspace, symlinks, and changes to `.github`, `.vscode`, `.guardian`, or `.git`
are denied, except direct `.yml`/`.yaml` files under `.github/workflows/`,
which may be proposed and scanned before writing. These restrictions prevent obvious alternative write paths but mean
this mode cannot autonomously run the generated app or install dependencies.
Perform those operations yourself after review. New tool names/schemas require
an adapter and tests before allowing them.

The adapter has a 20-second scan budget and a 25-second process deadline, below
the configured 30-second hook timeout. Long provisional scans are blocked and
can be retried after investigation. Hook timeout, hook disablement, process
termination, a different harness, other extensions, and concurrent changes
between approval and execution are editor/platform limits: this is not an OS
sandbox or a universal guarantee that all workspace writes are inspected. Keep
normal tool approvals enabled. The live editor tests above are required on your
installed VS Code/Copilot version; automated adapter tests do not establish live
editor enforcement.

To disable the gate, manually remove only
`.github/hooks/guardian-preaccept.json` from the test workspace.

References: [VS Code hook configuration](https://code.visualstudio.com/docs/agent-customization/hooks)
and [Local hook input/output contract](https://code.visualstudio.com/docs/agents/reference/hooks-reference).


## Copilot patch compatibility (18 October 2026)

The hook recognizes create/create_file and structured replacements, plus
apply_patch with a raw patch string or an input/patch field. Patch support
is conservative: Add File and Update File with bare @@ exact, unique-context
hunks only. Full files are reconstructed in memory and scanned together.
Deletes, moves, labelled hunks, ambiguous context and non-LF-terminated update
targets are denied. Existing path, symlink, configuration, size, final-result
and stale-target checks apply. task_complete is a completion notification
allowed without a backend scan. Terminal/delegated writes remain blocked.
This is a tool gate, not a sandbox.
