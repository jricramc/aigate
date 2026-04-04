"""AiGate MCP Server — exposes secret scanning as tools for any MCP-compatible agent."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from mcp.server.fastmcp import FastMCP

from aigate.config import Config
from aigate.scanner import Finding, scan_text
from aigate.redactor import Redaction, _env_var_name_for, save_to_dotenv

_INSTRUCTIONS = """\
You have access to aigate, a secret hygiene tool. Follow these rules:

1. BEFORE writing any code that contains credentials, API keys, tokens, passwords, \
or connection strings, call aigate_scan_code to check for hardcoded secrets.
2. If aigate_scan_code returns findings, rewrite the code to use environment variables \
as suggested, and call aigate_store_secret to save the real values to .env.
3. When a user provides a secret value (API key, token, password) in their message, \
use aigate_store_secret to save it to .env immediately — never write it into source code.
4. When asked to review or audit existing files for secrets, use aigate_scan_file.
5. Never hardcode credentials in source code. Always use environment variables."""

mcp = FastMCP("aigate", instructions=_INSTRUCTIONS, json_response=True)

_config: Config | None = None


def _get_config() -> Config:
    global _config
    if _config is None:
        _config = Config.load()
    return _config


def _line_number(text: str, offset: int) -> int:
    """Convert a character offset to a 1-based line number."""
    return text[:offset].count("\n") + 1


def _suggest_env_reference(env_var: str, file_path: str | None = None) -> str:
    """Suggest the code to reference an env var based on file extension."""
    ext = Path(file_path).suffix if file_path else ""
    if ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
        return f"process.env.{env_var}"
    if ext in (".rb",):
        return f"ENV['{env_var}']"
    if ext in (".go",):
        return f'os.Getenv("{env_var}")'
    if ext in (".rs",):
        return f'std::env::var("{env_var}")'
    # Default to Python
    return f"os.environ['{env_var}']"


def _findings_to_response(
    findings: list[Finding], text: str, file_path: str | None = None
) -> dict:
    """Convert scanner findings into the MCP tool response format."""
    if not findings:
        return {"clean": True, "findings": []}

    rule_counters: dict[str, int] = {}
    result_findings = []
    for f in findings:
        idx = rule_counters.get(f.rule, 0)
        rule_counters[f.rule] = idx + 1
        env_var = _env_var_name_for(f, idx)
        result_findings.append({
            "rule": f.rule,
            "line": _line_number(text, f.offset),
            "match_redacted": f.redacted,
            "suggestion": _suggest_env_reference(env_var, file_path),
            "env_var": env_var,
        })

    return {"clean": False, "findings": result_findings}


@mcp.tool()
def aigate_scan_code(
    code: Annotated[str, "The code to scan for hardcoded secrets"],
    file_path: Annotated[str | None, "Optional file path for language-aware suggestions"] = None,
) -> dict:
    """Scan code for hardcoded secrets before writing it to disk.

    Returns findings with suggested env variable replacements. The agent
    should use the suggestions to rewrite its code to use environment
    variables instead of hardcoded credentials.
    """
    cfg = _get_config()
    findings = scan_text(code, enabled_rules=cfg.rules, allowlist=cfg.allowlist)
    return _findings_to_response(findings, code, file_path)


@mcp.tool()
def aigate_store_secret(
    key: Annotated[str, "The environment variable name (e.g. OPENAI_API_KEY)"],
    value: Annotated[str, "The secret value to store"],
    file_path: Annotated[str, "Path to the env file"] = ".env",
) -> dict:
    """Store a credential in a .env file instead of hardcoding it.

    Returns the env variable reference to use in code. This makes it easy
    for agents to do the right thing — store secrets properly instead of
    hardcoding them.
    """
    env_path = Path(file_path)

    # Build a synthetic Redaction to reuse save_to_dotenv
    dummy_finding = Finding(rule="manual", match=value, offset=0)
    redaction = Redaction(
        finding=dummy_finding,
        placeholder=f"[REDACTED_{key}]",
        env_var_name=key,
        original_value=value,
    )

    actions = save_to_dotenv([redaction], env_path=env_path)
    stored = any("Added" in a for a in actions)

    return {
        "stored": stored,
        "env_reference": _suggest_env_reference(key),
        "file": str(env_path),
        "message": actions[0] if actions else f"Stored {key}",
    }


@mcp.tool()
def aigate_scan_file(
    file_path: Annotated[str, "Path to the file to scan for hardcoded secrets"],
) -> dict:
    """Scan an existing file for hardcoded secrets.

    Use this to retroactively find credentials in existing code and get
    suggestions for replacing them with environment variable references.
    """
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    try:
        text = path.read_text()
    except UnicodeDecodeError:
        return {"error": f"Cannot read binary file: {file_path}"}

    cfg = _get_config()
    findings = scan_text(text, enabled_rules=cfg.rules, allowlist=cfg.allowlist)
    response = _findings_to_response(findings, text, file_path)
    response["file"] = file_path
    return response


def run_mcp_server(config_path: str | None = None):
    """Entry point for running the MCP server."""
    global _config
    _config = Config.load(config_path)
    mcp.run()


if __name__ == "__main__":
    run_mcp_server()
