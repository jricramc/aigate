"""Secret scanner — pattern matching + entropy analysis."""

from __future__ import annotations

import fnmatch
import math
import re
from dataclasses import dataclass

_ALNUM = r"A-Za-z0-9"


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
        return f"{self.match[:4]}****...****{self.match[-4:]}"


PATTERNS: dict[str, re.Pattern] = {
    "aws_keys": re.compile(
        rf"(?<![{_ALNUM}/])(AKIA[0-9A-Z]{{16}})(?![{_ALNUM}/+=])"
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
        rf"(?<![{_ALNUM}_\-])("
        r"sk-proj-[A-Za-z0-9_\-]{20,}"
        r"|sk-[A-Za-z0-9]{20,}"
        r"|gh[pous]_[A-Za-z0-9]{36,}"
        r"|github_pat_[A-Za-z0-9_]{22,}"
        r"|glpat-[A-Za-z0-9\-_]{20,}"
        r"|xox[bp]-[A-Za-z0-9\-]+"
        r"|xapp-[A-Za-z0-9\-]+"
        r"|sk-ant-[A-Za-z0-9\-_]{20,}"
        r"|SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}"
        r"|sq0atp-[A-Za-z0-9\-_]{22,}"
        rf")(?![{_ALNUM}_\-])"
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
        rf"(?<![{_ALNUM}_\-])(tskey-(?:auth|api)-[{_ALNUM}\-_]{{16,}})(?![{_ALNUM}_\-])"
    ),
}

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
    length = len(s)
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((n / length) * math.log2(n / length) for n in freq.values())


def scan_text(
    text: str,
    *,
    enabled_rules: dict[str, bool] | None = None,
    allowlist: list[str] | None = None,
) -> list[Finding]:
    """Scan text for secrets. Returns list of findings."""
    enabled = enabled_rules or {r: True for r in PATTERNS}
    allowed = allowlist or []

    def is_allowed(value: str) -> bool:
        return any(fnmatch.fnmatch(value, p) for p in allowed)

    findings: list[Finding] = []

    for rule, pattern in PATTERNS.items():
        if not enabled.get(rule, True):
            continue
        for m in pattern.finditer(text):
            value = m.group(1) if m.lastindex else m.group(0)
            if not is_allowed(value):
                findings.append(Finding(rule=rule, match=value, offset=m.start()))

    if enabled.get("entropy_secrets", True):
        for m in ENTROPY_KEYWORDS.finditer(text):
            value = m.group(1)
            if is_allowed(value) or shannon_entropy(value) < ENTROPY_THRESHOLD:
                continue
            if any(value in f.match or f.match in value for f in findings):
                continue
            findings.append(Finding(rule="entropy_secrets", match=value, offset=m.start(1)))

    return findings
