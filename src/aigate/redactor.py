"""Secret redaction — replace secrets with env var placeholders."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from aigate.scanner import Finding

RULE_TO_ENV: dict[str, str] = {
    "aws_keys": "AWS_ACCESS_KEY_ID",
    "database_urls": "DATABASE_URL",
    "private_keys": "PRIVATE_KEY",
    "api_tokens": "API_KEY",
    "env_files": "",
    "gcp_service_accounts": "GOOGLE_APPLICATION_CREDENTIALS",
    "tailscale_keys": "TAILSCALE_AUTH_KEY",
    "entropy_secrets": "SECRET",
}

# Map token prefixes to their conventional env var names
TOKEN_PREFIX_TO_ENV: list[tuple[str, str]] = [
    ("sk-ant-", "ANTHROPIC_API_KEY"),
    ("sk-proj-", "OPENAI_API_KEY"),
    ("sk-", "OPENAI_API_KEY"),
    ("ghp_", "GITHUB_TOKEN"),
    ("gho_", "GITHUB_TOKEN"),
    ("ghu_", "GITHUB_TOKEN"),
    ("ghs_", "GITHUB_TOKEN"),
    ("github_pat_", "GITHUB_TOKEN"),
    ("glpat-", "GITLAB_TOKEN"),
    ("xoxb-", "SLACK_BOT_TOKEN"),
    ("xoxp-", "SLACK_USER_TOKEN"),
    ("xapp-", "SLACK_APP_TOKEN"),
    ("SG.", "SENDGRID_API_KEY"),
    ("sq0atp-", "SQUARE_ACCESS_TOKEN"),
]

_ENV_VAR_RE = re.compile(r"^([A-Z_]+)=")


@dataclass
class Redaction:
    finding: Finding
    placeholder: str
    env_var_name: str
    original_value: str


@dataclass
class RedactResult:
    redacted_text: str
    redactions: list[Redaction] = field(default_factory=list)

    @property
    def system_instruction(self) -> str:
        if not self.redactions:
            return ""
        env_list = ", ".join(r.env_var_name for r in self.redactions)
        lines = [
            "CRITICAL CONTEXT: aigate (a local security proxy running on the user's machine) "
            "intercepted this request and replaced real credentials with placeholders. "
            "You NEVER received the actual secret values. This happened transparently — "
            "the user typed real credentials, but aigate swapped them out before the request "
            "reached you.",
            "",
            "YOU MUST begin your response with a section like this:",
            "",
            "---",
            "**aigate protected your credentials:**",
            f"- Detected {len(self.redactions)} secret(s) in your message",
        ]
        for r in self.redactions:
            lines.append(f"- `{r.finding.redacted}` -> replaced with `{r.placeholder}`")
        lines += [
            f"- Saved to `.env` as: {env_list}",
            "- I never saw your actual credentials — only the placeholders above",
            "- I'll write code using `os.environ[]` to load them from `.env`",
            "---",
            "",
            "After that section, proceed with the user's request normally.",
            "",
            "The following env var mappings apply:",
        ]
        for r in self.redactions:
            lines.append(
                f"  - {r.placeholder} -> os.environ['{r.env_var_name}'] "
                f"(or process.env.{r.env_var_name} in Node.js)"
            )
        lines += [
            "",
            "When writing code, ALWAYS load .env first:",
            "  - Python: from dotenv import load_dotenv; load_dotenv()",
            "  - Node.js: require('dotenv').config()",
            "  - Shell: set -a; source .env; set +a",
            "",
            "Never output the original secret values. Always use the "
            "environment variable references above.",
        ]
        return "\n".join(lines)


def _env_var_name_for(finding: Finding, index: int) -> str:
    if finding.rule == "env_files":
        m = _ENV_VAR_RE.match(finding.match)
        if m:
            return m.group(1)

    # For API tokens, match prefix to conventional env var name
    if finding.rule == "api_tokens":
        for prefix, env_name in TOKEN_PREFIX_TO_ENV:
            if finding.match.startswith(prefix):
                return env_name

    prefix = RULE_TO_ENV.get(finding.rule, "SECRET")
    return f"{prefix}_{index + 1}" if index > 0 else prefix


def _secret_value_for(finding: Finding) -> str:
    if finding.rule == "env_files" and "=" in finding.match:
        return finding.match.split("=", 1)[1].strip("\"'")
    return finding.match


def redact_text(text: str, findings: list[Finding]) -> RedactResult:
    if not findings:
        return RedactResult(redacted_text=text)

    # Deduplicate by match value
    seen: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        if f.match not in seen:
            seen.add(f.match)
            unique.append(f)

    # Build redactions
    rule_counters: dict[str, int] = {}
    redactions: list[Redaction] = []
    for f in unique:
        idx = rule_counters.get(f.rule, 0)
        rule_counters[f.rule] = idx + 1
        env_name = _env_var_name_for(f, idx)
        redactions.append(Redaction(
            finding=f,
            placeholder=f"[REDACTED_{env_name}]",
            env_var_name=env_name,
            original_value=_secret_value_for(f),
        ))

    # Apply replacements
    redacted = text
    for r in redactions:
        if r.finding.rule == "env_files":
            redacted = redacted.replace(r.finding.match, f"{r.env_var_name}={r.placeholder}")
        else:
            redacted = redacted.replace(r.finding.match, r.placeholder)

    return RedactResult(redacted_text=redacted, redactions=redactions)


def save_to_dotenv(redactions: list[Redaction], env_path: str | Path = ".env") -> list[str]:
    path = Path(env_path)
    actions: list[str] = []

    existing_keys: set[str] = set()
    existing_content = ""
    if path.exists():
        existing_content = path.read_text()
        for line in existing_content.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                existing_keys.add(stripped.split("=", 1)[0].strip())

    new_lines: list[str] = []
    for r in redactions:
        if r.env_var_name in existing_keys:
            actions.append(f"{r.env_var_name} already in .env, skipped")
        else:
            new_lines.append(f"{r.env_var_name}={r.original_value}")
            actions.append(f"Added {r.env_var_name} to .env")

    if new_lines:
        with open(path, "a") as f:
            if existing_content and not existing_content.endswith("\n"):
                f.write("\n")
            if not existing_content:
                f.write("# Secrets extracted by aigate\n")
            f.write("\n".join(new_lines) + "\n")

    return actions
