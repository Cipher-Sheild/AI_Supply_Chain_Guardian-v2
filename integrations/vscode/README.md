# Guardian editor command
Install the packaged VSIX in VS Code. Set `guardian.serverUrl` to the local Trust Engine (8000 for Compose; 18108 for the native launcher). Run **Guardian: Scan Active Artifact** to submit the current unsaved buffer, display findings and poll provisional scans. Cancel, service errors and finalization timeout retain review warnings. Edits during a scan invalidate its result.

This is explicit developer-triggered review. It does not intercept every AI assistant's Accept button, does not install an AI provider hook and does not silently scan/save/upload every file. Build/package verification does not prove editor interaction; manual VS Code testing remains required. Artifact content is sent to the configured server only when the command is invoked.
