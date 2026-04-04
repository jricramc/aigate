"""Claude Code hook integration for aigate."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

HOOKS_DIR = Path.home() / ".claude" / "hooks"
SETTINGS_FILE = Path.home() / ".claude" / "settings.json"

HOOK_FILES = {
    "scan_prompt.sh": "aigate-scan-prompt.sh",
    "scan_tool.sh": "aigate-scan-tool.sh",
    "scan_output.sh": "aigate-scan-output.sh",
}

HOOK_CONFIG = {
    "UserPromptSubmit": [{"matcher": "", "hooks": [{"type": "command", "command": str(HOOKS_DIR / "aigate-scan-prompt.sh"), "timeout": 5}]}],
    "PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": str(HOOKS_DIR / "aigate-scan-tool.sh"), "timeout": 5}]}],
    "PostToolUse": [{"matcher": "Write|Edit", "hooks": [{"type": "command", "command": str(HOOKS_DIR / "aigate-scan-output.sh"), "timeout": 5}]}],
}


def _read_settings() -> dict:
    if SETTINGS_FILE.exists():
        with open(SETTINGS_FILE) as f:
            return json.load(f)
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    return {}


def _write_settings(settings: dict) -> None:
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")


def _aigate_commands(event_hooks: list[dict]) -> set[str]:
    return {h["command"] for entry in event_hooks for h in entry.get("hooks", [])}


def _has_aigate_hook(entries: list[dict], cmds: set[str]) -> bool:
    return any(h.get("command") in cmds for entry in entries for h in entry.get("hooks", []))


def install_hooks(only_events: set[str] | None = None) -> list[str]:
    """Install hooks. If only_events is set, only install those hook events."""
    actions: list[str] = []

    HOOKS_DIR.mkdir(parents=True, exist_ok=True)
    pkg = resources.files("aigate.hooks")

    # Determine which events to install
    events_to_install = only_events or set(HOOK_CONFIG.keys())

    # Map events back to which script files they need
    needed_scripts: set[str] = set()
    event_to_script = {
        "UserPromptSubmit": "scan_prompt.sh",
        "PreToolUse": "scan_tool.sh",
        "PostToolUse": "scan_output.sh",
    }
    for event in events_to_install:
        script = event_to_script.get(event)
        if script:
            needed_scripts.add(script)

    for src_name, dst_name in HOOK_FILES.items():
        if src_name not in needed_scripts:
            continue
        dst = HOOKS_DIR / dst_name
        dst.write_bytes((pkg / src_name).read_bytes())
        dst.chmod(0o755)
        actions.append(f"Installed {dst}")

    settings = _read_settings()
    hooks = settings.setdefault("hooks", {})

    for event, event_hooks in HOOK_CONFIG.items():
        if event not in events_to_install:
            continue
        existing = hooks.get(event, [])
        if _has_aigate_hook(existing, _aigate_commands(event_hooks)):
            actions.append(f"{event} hook already configured")
        else:
            existing.extend(event_hooks)
            hooks[event] = existing
            actions.append(f"Added {event} hook to settings.json")

    _write_settings(settings)
    return actions


def uninstall_hooks() -> list[str]:
    actions: list[str] = []

    for dst_name in HOOK_FILES.values():
        dst = HOOKS_DIR / dst_name
        if dst.exists():
            dst.unlink()
            actions.append(f"Removed {dst}")

    if SETTINGS_FILE.exists():
        settings = _read_settings()
        hooks = settings.get("hooks", {})
        for event in HOOK_CONFIG:
            if event not in hooks:
                continue
            hooks[event] = [
                e for e in hooks[event]
                if not any("aigate" in h.get("command", "") for h in e.get("hooks", []))
            ]
            if not hooks[event]:
                del hooks[event]
            actions.append(f"Removed {event} hook from settings.json")
        _write_settings(settings)

    return actions
