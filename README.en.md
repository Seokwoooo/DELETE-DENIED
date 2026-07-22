[한국어](README.md) | [English](README.en.md) | [日本語](README.ja.md)

# DELETE-DENIED

> AI file deletion, denied.

DELETE-DENIED is a simple safety check for Codex that helps stop an attempt to remove an
important local parent folder. Claude Code is not currently supported.

## Install

Run one line in macOS Terminal:

```sh
curl -fsSL https://raw.githubusercontent.com/Seokwoooo/DELETE-DENIED/main/bootstrap/install.sh | sh
```

On Windows, run this in a regular PowerShell:

```powershell
irm https://raw.githubusercontent.com/Seokwoooo/DELETE-DENIED/main/bootstrap/install.ps1 | iex
```

The installer downloads the latest release, checks SHA-256, and runs a trusted install or update.
It uses Codex app-server to trust only the exact DELETE-DENIED hook, then runs DELETE-DENIED's
own `doctor`. If app-server is unavailable, it fails quickly without writing trust state. Run the
same command again to update.

Both installers write only below the current user's `.codex` directory.

## Zero CPU and RAM while idle

No DELETE-DENIED process remains between calls. Codex starts one short-lived check each
time it invokes a terminal tool matching `^Bash$`; safe commands finish before the policy
file is read.

## How the Codex hook works

A hook is an official Codex feature that inserts a defined check immediately before or
after a tool runs. DELETE-DENIED connects to the pre-execution `PreToolUse` event.

1. Codex prepares a terminal command for the `Bash` tool.
2. The `PreToolUse` hook starts one small checker immediately before execution.
3. Safe commands pass without reading the policy file.
4. For deletion candidates, the checker resolves the target path and compares it with protected paths.
5. The checker is designed to return a deny response for an important-parent deletion, while normal project work is allowed.
6. The checker process exits when the check is complete.

The `^Bash$` tool-name matcher means every matching Bash call gets one short check, not
only deletion commands. It does not continuously inspect folders or watch file changes.

## What is and is not protected?

The intended product surface is terminal deletion calls delivered through Codex's
`PreToolUse` `Bash` hook. The checker is designed to
reject risky deletions aimed at important local parent paths. This is not an OS-wide
deletion blocker. Other Codex file-changing methods, direct screen or file-manager
actions, browser downloads, remote, cloud, or database work, other programs, and other
AI tools are outside the scope. See [What is and is not protected (Korean)](docs/threat-model.md)
for the full boundaries.

## Detailed documentation

- [Installation guide (Korean)](docs/install.md) — Installation, updates, and removal
- [Suspend/resume guide (Korean)](docs/suspend-resume.md) — Change protection state safely
- [How it works (Korean)](docs/architecture.md) — How the hook and command flow work
- [What is and is not protected (Korean)](docs/threat-model.md) — Protected and unprotected work
- [Research (Korean)](docs/research.md) — Evidence and references

## License and security reporting

DELETE-DENIED is released under the MIT License. For security issues, follow the
[security reporting instructions (Korean)](SECURITY.md).
