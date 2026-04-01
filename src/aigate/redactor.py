"""Secret redaction — replace secrets with placeholders and manage .env."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from aigate.scanner import Finding


# Map scanner rule names to friendly env var name prefixes
RULE_TO_ENV_PREFIX: dict[str, str] = {
    "aws_keys": "AWS_ACCESS_KEY_ID",
    "database_urls": "DATABASE_URL",
    "private_keys": "PRIVATE_KEY",
    "api_tokens": "API_KEY",
    "env_files": "",  # already has a name, we'll extract it
    "gcp_service_accounts": "GCP_SERVICE_ACCOUNT",
    "tailscale_keys": "TAILSCALE_KEY",
    "entropy_secrets": "SECRET",
}

# Pattern to extract the variable name from env_files findings like "DATABASE_URL=value"
ENV_VAR_PATTERN = re.compile(r"^([A-Z_]+)=")


@dataclass
class Redaction:
    """A single secret that was redacted."""
    finding: Finding
    placeholder: str
    env_var_name: str
    original_value: str


@dataclass
class RedactResult:
    """Result of redacting secrets from text."""
    redacted_text: str
    redactions: list[Redaction] = field(default_factory=list)

    @property
    def system_instruction(self) -> str:
        if not self.redactions:
            return ""
        lines = [
            "IMPORTANT: The user's message contained sensitive credentials that have been "
            "redacted for security. When writing code, use environment variables instead "
            "of hardcoded values. The following substitutions were made:"
        ]
        for r in self.redactions:
            lines.append(f"  - {r.placeholder} → use os.environ['{r.env_var_name}'] "
                         f"(or process.env.{r.env_var_name} in Node.js)")
        lines.append("")
        lines.append("Never output the original secret values. Always use the "
                      "environment variable references above.")
        return "\n".join(lines)


def _env_var_name_for(finding: Finding, index: int) -> str:
    """Generate an appropriate env var name for a finding."""
    if finding.rule == "env_files":
        m = ENV_VAR_PATTERN.match(finding.match)
        if m:
            return m.group(1)

    prefix = RULE_TO_ENV_PREFIX.get(finding.rule, "SECRET")
    if index > 0:
        return f"{prefix}_{index + 1}"
    return prefix


def _secret_value_for(finding: Finding) -> str:
    """Extract the raw secret value from a finding."""
    if finding.rule == "env_files":
        # Finding match is "KEY=value", extract just the value
        eq_pos = finding.match.find("=")
        if eq_pos != -1:
            val = finding.match[eq_pos + 1:]
            return val.strip("\"'")
    return finding.match


def redact_text(text: str, findings: list[Finding]) -> RedactResult:
    """Replace all findings in text with placeholders.

    Processes findings in reverse offset order to preserve positions.
    """
    if not findings:
        return RedactResult(redacted_text=text)

    # Deduplicate findings by match value, keep first occurrence
    seen: dict[str, Finding] = {}
    unique_findings: list[Finding] = []
    for f in findings:
        if f.match not in seen:
            seen[f.match] = f
            unique_findings.append(f)

    # Assign env var names
    rule_counters: dict[str, int] = {}
    redactions: list[Redaction] = []

    for f in unique_findings:
        count = rule_counters.get(f.rule, 0)
        rule_counters[f.rule] = count + 1
        env_name = _env_var_name_for(f, count)
        placeholder = f"[REDACTED_{env_name}]"
        secret_value = _secret_value_for(f)

        redactions.append(Redaction(
            finding=f,
            placeholder=placeholder,
            env_var_name=env_name,
            original_value=secret_value,
        ))

    # Replace all occurrences of each secret in the text
    redacted = text
    for r in redactions:
        # For env_files, replace the whole KEY=value
        if r.finding.rule == "env_files":
            redacted = redacted.replace(r.finding.match, f"{r.env_var_name}={r.placeholder}")
        else:
            redacted = redacted.replace(r.finding.match, r.placeholder)

    return RedactResult(redacted_text=redacted, redactions=redactions)


def save_to_dotenv(redactions: list[Redaction], env_path: str | Path = ".env") -> list[str]:
    """Append redacted secrets to a .env file. Returns list of actions taken."""
    path = Path(env_path)
    actions: list[str] = []

    existing_content = ""
    existing_keys: set[str] = set()
    if path.exists():
        existing_content = path.read_text()
        for line in existing_content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key = line.split("=", 1)[0].strip()
                existing_keys.add(key)

    new_lines: list[str] = []
    for r in redactions:
        if r.env_var_name in existing_keys:
            actions.append(f"{r.env_var_name} already in .env, skipped")
            continue
        new_lines.append(f"{r.env_var_name}={r.original_value}")
        actions.append(f"Added {r.env_var_name} to .env")

    if new_lines:
        with open(path, "a") as f:
            if existing_content and not existing_content.endswith("\n"):
                f.write("\n")
            if not existing_content:
                f.write("# Secrets extracted by AiGate\n")
            f.write("\n".join(new_lines) + "\n")

    return actions
