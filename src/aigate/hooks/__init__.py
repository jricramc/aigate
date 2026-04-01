"""Claude Code hook integration for AiGate."""

from __future__ import annotations

import json
import shutil
from importlib import resources
from pathlib import Path

HOOKS_DIR = Path.home() / ".claude" / "hooks"
SETTINGS_FILE = Path.home() / ".claude" / "settings.json"

HOOK_FILES = {
    "scan_prompt.sh": "aigate-scan-prompt.sh",
    "scan_tool.sh": "aigate-scan-tool.sh",
}

HOOK_CONFIG = {
    "UserPromptSubmit": [
        {
            "matcher": "",
            "hooks": [
                {
                    "type": "command",
                    "command": str(HOOKS_DIR / "aigate-scan-prompt.sh"),
                    "timeout": 5,
                }
            ],
        }
    ],
    "PreToolUse": [
        {
            "matcher": "",
            "hooks": [
                {
                    "type": "command",
                    "command": str(HOOKS_DIR / "aigate-scan-tool.sh"),
                    "timeout": 5,
                }
            ],
        }
    ],
}


def install_hooks() -> list[str]:
    """Install AiGate hooks into Claude Code. Returns list of actions taken."""
    actions: list[str] = []

    # 1. Copy hook scripts to ~/.claude/hooks/
    HOOKS_DIR.mkdir(parents=True, exist_ok=True)

    hooks_package = resources.files("aigate.hooks")
    for src_name, dst_name in HOOK_FILES.items():
        src = hooks_package / src_name
        dst = HOOKS_DIR / dst_name
        dst.write_bytes(src.read_bytes())
        dst.chmod(0o755)
        actions.append(f"Installed {dst}")

    # 2. Update ~/.claude/settings.json
    if SETTINGS_FILE.exists():
        with open(SETTINGS_FILE) as f:
            settings = json.load(f)
    else:
        SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        settings = {}

    hooks = settings.setdefault("hooks", {})

    for event_name, event_hooks in HOOK_CONFIG.items():
        existing = hooks.get(event_name, [])
        # Check if already installed (by command path)
        aigate_cmds = {
            h["command"]
            for entry in event_hooks
            for h in entry.get("hooks", [])
        }
        already_installed = any(
            h.get("command") in aigate_cmds
            for entry in existing
            for h in entry.get("hooks", [])
        )
        if not already_installed:
            existing.extend(event_hooks)
            hooks[event_name] = existing
            actions.append(f"Added {event_name} hook to settings.json")
        else:
            actions.append(f"{event_name} hook already configured")

    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")

    return actions


def uninstall_hooks() -> list[str]:
    """Remove AiGate hooks from Claude Code. Returns list of actions taken."""
    actions: list[str] = []

    # 1. Remove hook scripts
    for dst_name in HOOK_FILES.values():
        dst = HOOKS_DIR / dst_name
        if dst.exists():
            dst.unlink()
            actions.append(f"Removed {dst}")

    # 2. Clean settings.json
    if SETTINGS_FILE.exists():
        with open(SETTINGS_FILE) as f:
            settings = json.load(f)

        hooks = settings.get("hooks", {})
        for event_name in HOOK_CONFIG:
            if event_name not in hooks:
                continue
            # Filter out aigate entries
            hooks[event_name] = [
                entry for entry in hooks[event_name]
                if not any(
                    "aigate" in h.get("command", "")
                    for h in entry.get("hooks", [])
                )
            ]
            if not hooks[event_name]:
                del hooks[event_name]
            actions.append(f"Removed {event_name} hook from settings.json")

        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=2)
            f.write("\n")

    return actions
