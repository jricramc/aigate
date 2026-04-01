"""Secret scanner — pattern matching + entropy analysis."""

from __future__ import annotations

import fnmatch
import math
import re
from dataclasses import dataclass


@dataclass
class Finding:
    rule: str
    match: str
    offset: int
    location: str = ""

    @property
    def redacted(self) -> str:
        if len(self.match) <= 8:
            return "****"
        return self.match[:4] + "****...****" + self.match[-4:]


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

PATTERNS: dict[str, re.Pattern] = {
    "aws_keys": re.compile(
        r"(?<![A-Za-z0-9/])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])"
    ),
    "database_urls": re.compile(
        r"((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)"
        r"://[^\s\"'`<>]+:[^\s\"'`<>]+@[^\s\"'`<>]+)"
    ),
    "private_keys": re.compile(
        r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        r"[\s\S]{20,}?"
        r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)"
    ),
    "api_tokens": re.compile(
        r"(?<![A-Za-z0-9_\-])"
        r"("
        r"sk-proj-[A-Za-z0-9_\-]{20,}"  # OpenAI project keys
        r"|sk-[A-Za-z0-9]{20,}"  # OpenAI / generic sk- keys
        r"|ghp_[A-Za-z0-9]{36,}"  # GitHub PAT
        r"|gho_[A-Za-z0-9]{36,}"  # GitHub OAuth
        r"|ghu_[A-Za-z0-9]{36,}"  # GitHub user-to-server
        r"|ghs_[A-Za-z0-9]{36,}"  # GitHub server-to-server
        r"|github_pat_[A-Za-z0-9_]{22,}"  # GitHub fine-grained PAT
        r"|glpat-[A-Za-z0-9\-_]{20,}"  # GitLab PAT
        r"|xoxb-[A-Za-z0-9\-]+"  # Slack bot token
        r"|xoxp-[A-Za-z0-9\-]+"  # Slack user token
        r"|xapp-[A-Za-z0-9\-]+"  # Slack app token
        r"|sk-ant-[A-Za-z0-9\-_]{20,}"  # Anthropic API key
        r"|SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}"  # SendGrid
        r"|sq0atp-[A-Za-z0-9\-_]{22,}"  # Square access token
        r")"
        r"(?![A-Za-z0-9_\-])"
    ),
    "env_files": re.compile(
        r"(?:^|\n)"
        r"((?:DATABASE_URL|DB_PASSWORD|SECRET_KEY|API_KEY|API_SECRET"
        r"|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|PRIVATE_KEY"
        r"|STRIPE_SECRET_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY"
        r"|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN"
        r"|GITHUB_TOKEN|GITLAB_TOKEN|SLACK_TOKEN"
        r"|PASSWORD|PASSWD|CREDENTIALS)"
        r"=[\"']?(?![<{])[^\s\"']{8,}[\"']?)"
    ),
    "gcp_service_accounts": re.compile(
        r'("type"\s*:\s*"service_account"[\s\S]{0,500}"private_key"\s*:\s*"[^"]+)'
    ),
    "tailscale_keys": re.compile(
        r"(?<![A-Za-z0-9_\-])(tskey-(?:auth|api)-[A-Za-z0-9\-_]{16,})(?![A-Za-z0-9_\-])"
    ),
}

# Keywords that signal a nearby string might be a secret
ENTROPY_KEYWORDS = re.compile(
    r"(?:password|passwd|secret[_\-]?key|secret|auth_token|access_token|refresh_token"
    r"|token|api_key|apikey|auth|credential|private[_\-]?key)"
    r"\s*[=:]\s*[\"']?([^\s\"']{12,})[\"']?",
    re.IGNORECASE,
)

ENTROPY_THRESHOLD = 3.5


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def scan_text(
    text: str,
    *,
    enabled_rules: dict[str, bool] | None = None,
    allowlist: list[str] | None = None,
) -> list[Finding]:
    """Scan text for secrets. Returns list of findings."""
    findings: list[Finding] = []
    enabled = enabled_rules or {rule: True for rule in PATTERNS}
    allowed = allowlist or []

    def is_allowed(value: str) -> bool:
        return any(fnmatch.fnmatch(value, pattern) for pattern in allowed)

    # Run regex patterns
    for rule_name, pattern in PATTERNS.items():
        if not enabled.get(rule_name, True):
            continue
        for m in pattern.finditer(text):
            value = m.group(1) if m.lastindex else m.group(0)
            if is_allowed(value):
                continue
            findings.append(Finding(
                rule=rule_name,
                match=value,
                offset=m.start(),
            ))

    # Entropy-based detection
    if enabled.get("entropy_secrets", True):
        for m in ENTROPY_KEYWORDS.finditer(text):
            value = m.group(1)
            if is_allowed(value) or shannon_entropy(value) < ENTROPY_THRESHOLD:
                continue
            # Don't double-report if already caught by another rule
            if any(value in f.match or f.match in value for f in findings):
                continue
            findings.append(Finding(
                rule="entropy_secrets",
                match=value,
                offset=m.start(1),
            ))

    return findings
