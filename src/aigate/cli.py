"""aigate CLI — AI Prompt Secret Scanner."""

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
    """aigate — scan and block secrets before they reach AI APIs."""


@main.command()
def setup():
    """One-time setup: install the CA cert so the proxy can inspect HTTPS traffic.

    Requires sudo. After this, just set HTTPS_PROXY and everything works.
    """
    from aigate.cert import install_cert, is_cert_installed

    if is_cert_installed():
        click.echo("CA cert already exists. Reinstalling into trust store...")
    else:
        click.echo("Generating and installing mitmproxy CA certificate...")

    try:
        actions = install_cert()
        click.echo()
        for action in actions:
            click.echo(f"   {action}")
        click.echo("\n✅ Done. The proxy can now inspect HTTPS traffic.")

        # Print export commands so `eval $(aigate setup)` works
        from aigate.cert import MITMPROXY_CA, LINUX_CA_BUNDLE
        import platform
        click.echo("")
        exports = [f'export NODE_EXTRA_CA_CERTS="{MITMPROXY_CA}"']
        if platform.system() == "Linux" and Path(LINUX_CA_BUNDLE).exists():
            exports.append(f'export REQUESTS_CA_BUNDLE="{LINUX_CA_BUNDLE}"')
            exports.append(f'export SSL_CERT_FILE="{LINUX_CA_BUNDLE}"')
        else:
            exports.append(f'export SSL_CERT_FILE="{MITMPROXY_CA}"')

        click.echo("   Apply env vars now (copy-paste this, or use eval):")
        click.echo("")
        for exp in exports:
            click.echo(f"   {exp}")
        click.echo("")
    except Exception as e:
        click.echo(f"\nError: {e}", err=True)
        click.echo("You may need to run: sudo aigate setup", err=True)
        sys.exit(1)


@main.command()
@click.option("--port", "-p", type=int, default=None, help="Proxy port (default: 8080)")
@click.option("--mode", "-m", type=click.Choice(["block", "redact", "warn", "audit"]), default=None)
@click.option("--config", "-c", "config_path", type=click.Path(), default=None)
def start(port: int | None, mode: str | None, config_path: str | None):
    """Start the aigate proxy."""
    from aigate.cert import is_cert_installed

    config = Config.load(config_path)
    if port is not None:
        config.port = port
    if mode is not None:
        config.mode = mode

    Path(config.log.file).expanduser().parent.mkdir(parents=True, exist_ok=True)

    if not is_cert_installed():
        click.echo("CA cert not found. Installing for HTTPS interception...")
        click.echo("(This requires sudo — one-time only)\n")
        from aigate.cert import install_cert
        try:
            for action in install_cert():
                click.echo(f"   {action}")
            click.echo()
        except Exception as e:
            click.echo(f"   Failed: {e}", err=True)
            click.echo("   Run 'sudo aigate setup' manually.\n", err=True)

    # Check if cert env vars are loaded in the current shell
    import os
    if is_cert_installed() and not os.environ.get("NODE_EXTRA_CA_CERTS"):
        click.echo("⚠️  NODE_EXTRA_CA_CERTS is not set in this shell.")
        click.echo("   Claude Code / Node.js won't trust the proxy yet.")
        click.echo("")
        click.echo("   Run this in the terminal where you use Claude Code:")
        click.echo("     source ~/.bashrc")
        click.echo("")

    click.echo(f"🛡️  aigate v{__version__}")
    click.echo(f"   Mode:      {config.mode}")
    click.echo(f"   Proxy:     http://127.0.0.1:{config.port}")
    click.echo(f"   Providers: {', '.join(config.providers)}")
    click.echo(f"   Log:       {config.log.file}")
    click.echo()
    click.echo("Point your AI tool at aigate:")
    click.echo(f"   export HTTPS_PROXY=http://127.0.0.1:{config.port}")
    click.echo(f"   export HTTP_PROXY=http://127.0.0.1:{config.port}")
    click.echo()

    from aigate.proxy import run_proxy
    asyncio.run(run_proxy(config))


@main.command()
@click.argument("target", default="-")
@click.option("--config", "-c", "config_path", type=click.Path(), default=None)
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
@click.option("--redact", "-r", is_flag=True, help="Redact secrets and save to .env")
def scan(target: str, config_path: str | None, json_output: bool, redact: bool):
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
        try:
            text = path.read_text()
        except (UnicodeDecodeError, ValueError):
            click.echo(f"Error: cannot scan binary file: {target}", err=True)
            sys.exit(1)
        source = str(path)

    findings = scan_text(text, enabled_rules=config.rules, allowlist=config.allowlist)

    if not findings:
        if json_output:
            click.echo(json.dumps({"source": source, "findings": [], "clean": True,
                                    **({"redacted_text": text} if redact else {})}))
        else:
            click.echo(f"✅ No secrets found in {source}")
        sys.exit(0)

    if redact:
        from aigate.redactor import redact_text, save_to_dotenv

        result = redact_text(text, findings)
        env_actions = save_to_dotenv(result.redactions)

        if json_output:
            click.echo(json.dumps({
                "source": source,
                "clean": False,
                "redacted_text": result.redacted_text,
                "redactions": [
                    {"rule": r.finding.rule, "env_var": r.env_var_name,
                     "placeholder": r.placeholder, "match_redacted": r.finding.redacted}
                    for r in result.redactions
                ],
            }))
        else:
            click.echo(f"🛡️  Redacted {len(result.redactions)} secret(s) in {source}:\n")
            for r in result.redactions:
                click.echo(f"  {r.finding.redacted} → {r.placeholder}")
            click.echo()
            for a in env_actions:
                click.echo(f"  {a}")
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
    path.write_text(f"# aigate configuration\n{default_config_yaml()}")
    click.echo(f"✅ Created {path}")


@main.command("install-hook")
def install_hook():
    """Install aigate as a Claude Code hook (recommended)."""
    from aigate.hooks import install_hooks

    actions = install_hooks()
    click.echo("🛡️  aigate Claude Code integration installed:\n")
    for action in actions:
        click.echo(f"   {action}")
    click.echo("\nDone. All prompts and tool inputs are now scanned automatically.")
    click.echo("To uninstall: aigate uninstall-hook")


@main.command("uninstall-hook")
def uninstall_hook():
    """Remove aigate Claude Code hooks."""
    from aigate.hooks import uninstall_hooks

    actions = uninstall_hooks()
    if actions:
        click.echo("Removed aigate from Claude Code:\n")
        for action in actions:
            click.echo(f"   {action}")
    else:
        click.echo("aigate hooks were not installed.")


@main.command()
@click.option("--tail", "-n", "num_lines", type=int, default=20, help="Number of entries to show")
@click.option("--follow", "-f", is_flag=True, help="Follow log output in real time")
def logs(num_lines: int, follow: bool):
    """View aigate scan logs."""
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
