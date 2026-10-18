# Guardian editor integration

Install the packaged VSIX in VS Code. Set `guardian.serverUrl` to the local Trust
Engine (8000 for Compose; 18108 for the native launcher). Run **Guardian: Scan
Active Artifact** to submit the current unsaved buffer, display findings and poll
provisional scans. Cancel, service errors and finalization timeout retain review
warnings. Edits during a scan invalidate its result.

Enable `guardian.scanOnSave` to inspect files after saving (off by default).
Both commands send artifact contents to the configured backend. They report
findings and do not block edits or saving.

For inspection **before** supported agent file tools write code, install the
separate [PreToolUse gate](PREACCEPTANCE.md). It requires a compatible VS Code
Local agent session and explicit hook setup for the workspace. It is not enabled
by installing the VSIX and does not intercept Copilot inline Tab acceptance.
