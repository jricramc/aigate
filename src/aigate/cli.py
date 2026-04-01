"""AiGate CLI — AI Prompt Secret Scanner."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click

from aigate import __version__
from aigate.config import Config, default_config_yaml, DEFAULT_CONFIG_NAME
from aigate.scanner import scan_text


@click.group()
@click.version_option(version=__version__, prog_name="aigate")
def main():
    """AiGate — scan and block secrets before they reach AI APIs."""


@main.command()
@click.option("--port", "-p", type=int, default=None, help="Proxy port (default: 8080)")
@click.option("--mode", "-m", type=click.Choice(["block", "redact", "warn", "audit"]), default=None)
@click.option("--config", "-c", "config_path", type=click.Path(), default=None)
def start(port: int | None, mode: str | None, config_path: str | None):
    """Start the AiGate proxy."""
    config = Config.load(config_path)
    if port is not None:
        config.port = port
    if mode is not None:
        config.mode = mode

    Path(config.log.file).expanduser().parent.mkdir(parents=True, exist_ok=True)

    click.echo(f"🛡️  AiGate v{__version__}")
    click.echo(f"   Mode:      {config.mode}")
    click.echo(f"   Proxy:     http://127.0.0.1:{config.port}")
    click.echo(f"   Providers: {', '.join(config.providers)}")
    click.echo(f"   Log:       {config.log.file}")
    click.echo()
    click.echo("Configure your AI tool to use this proxy:")
    click.echo(f"   export HTTP_PROXY=http://127.0.0.1:{config.port}")
    click.echo(f"   export HTTPS_PROXY=http://127.0.0.1:{config.port}")
    click.echo()

    from aigate.proxy import run_proxy
    asyncio.run(run_proxy(config))


@main.command()
@click.argument("target", default="-")
@click.option("--config", "-c", "config_path", type=click.Path(), default=None)
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def scan(target: str, config_path: str | None, json_output: bool):
    """Scan a file or stdin for secrets."""
    config = Config.load(config_path)

    if target == "-":
        text = sys.stdin.read()
        source = "<stdin>"
    else:
        path = Path(target)
        if not path.exists():
            click.echo(f"Error: file not found: {target}", err=True)
            sys.exit(1)
        text = path.read_text()
        source = str(path)

    findings = scan_text(text, enabled_rules=config.rules, allowlist=config.allowlist)

    if not findings:
        if json_output:
            click.echo(json.dumps({"source": source, "findings": [], "clean": True}))
        else:
            click.echo(f"✅ No secrets found in {source}")
        sys.exit(0)

    if json_output:
        click.echo(json.dumps({
            "source": source,
            "clean": False,
            "findings": [{"rule": f.rule, "match_redacted": f.redacted, "offset": f.offset} for f in findings],
        }, indent=2))
    else:
        click.echo(f"🚨 {len(findings)} secret(s) found in {source}:\n")
        for f in findings:
            click.echo(f"  [{f.rule}] {f.redacted} (offset {f.offset})")
        click.echo()

    sys.exit(1)


@main.command()
@click.option("--path", "-p", "output_path", default=DEFAULT_CONFIG_NAME)
def init(output_path: str):
    """Create a default .aigate.yml config file."""
    path = Path(output_path)
    if path.exists():
        click.echo(f"Config already exists: {path}")
        sys.exit(1)
    path.write_text(f"# AiGate configuration\n{default_config_yaml()}")
    click.echo(f"✅ Created {path}")


@main.command("install-hook")
def install_hook():
    """Install AiGate as a Claude Code hook (recommended)."""
    from aigate.hooks import install_hooks

    actions = install_hooks()
    click.echo("🛡️  AiGate Claude Code integration installed:\n")
    for action in actions:
        click.echo(f"   {action}")
    click.echo("\nDone. All prompts and tool inputs are now scanned automatically.")
    click.echo("To uninstall: aigate uninstall-hook")


@main.command("uninstall-hook")
def uninstall_hook():
    """Remove AiGate Claude Code hooks."""
    from aigate.hooks import uninstall_hooks

    actions = uninstall_hooks()
    if actions:
        click.echo("Removed AiGate from Claude Code:\n")
        for action in actions:
            click.echo(f"   {action}")
    else:
        click.echo("AiGate hooks were not installed.")


@main.command()
@click.option("--tail", "-n", "num_lines", type=int, default=20, help="Number of entries to show")
@click.option("--follow", "-f", is_flag=True, help="Follow log output in real time")
def logs(num_lines: int, follow: bool):
    """View AiGate scan logs."""
    log_file = Path.home() / ".aigate" / "scan.log"
    if not log_file.exists():
        click.echo("No logs yet.")
        return

    if follow:
        import subprocess
        subprocess.run(["tail", "-f", str(log_file)])
        return

    lines = log_file.read_text().strip().split("\n")
    for line in lines[-num_lines:]:
        try:
            e = json.loads(line)
            ts = e.get("timestamp", "?")
            action = e.get("action", "?")
            event = e.get("event", e.get("provider", "proxy"))
            tool = e.get("tool", "")
            rules = ", ".join(f.get("rule", "?") for f in e.get("findings", []))
            redacted = ", ".join(f.get("match_redacted", "?") for f in e.get("findings", []))
            label = f"{event}/{tool}" if tool else event
            click.echo(f"  {ts}  [{action.upper()}]  {label}  {rules}  {redacted}")
        except json.JSONDecodeError:
            click.echo(f"  {line}")


@main.group()
def allowlist():
    """Manage the allowlist for false positive suppression."""


@allowlist.command("add")
@click.argument("pattern")
@click.option("--config", "-c", "config_path", type=click.Path(), default=None)
def allowlist_add(pattern: str, config_path: str | None):
    """Add a pattern to the allowlist."""
    import yaml

    config_file = Path(config_path) if config_path else Path(DEFAULT_CONFIG_NAME)
    if not config_file.exists():
        click.echo(f"No config found at {config_file}. Run 'aigate init' first.", err=True)
        sys.exit(1)

    with open(config_file) as f:
        data = yaml.safe_load(f) or {}

    al = data.setdefault("allowlist", [])
    if pattern in al:
        click.echo(f"Pattern already in allowlist: {pattern}")
        return

    al.append(pattern)
    with open(config_file, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    click.echo(f"✅ Added to allowlist: {pattern}")
