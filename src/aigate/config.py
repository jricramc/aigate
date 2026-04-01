"""Configuration loading and defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


DEFAULT_CONFIG_NAME = ".aigate.yml"
DEFAULT_LOG_DIR = Path.home() / ".aigate"

DEFAULT_PROVIDERS = [
    "api.anthropic.com",
    "api.openai.com",
    "api.mistral.ai",
]

DEFAULT_RULES = {
    "aws_keys": True,
    "database_urls": True,
    "private_keys": True,
    "api_tokens": True,
    "env_files": True,
    "gcp_service_accounts": True,
    "tailscale_keys": True,
    "entropy_secrets": True,
}


@dataclass
class LogConfig:
    file: str = str(DEFAULT_LOG_DIR / "scan.log")
    format: str = "json"


@dataclass
class Config:
    mode: str = "block"  # block | warn | audit
    port: int = 8080
    providers: list[str] = field(default_factory=lambda: list(DEFAULT_PROVIDERS))
    rules: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_RULES))
    allowlist: list[str] = field(default_factory=list)
    log: LogConfig = field(default_factory=LogConfig)

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        """Load config from YAML file, falling back to defaults."""
        if path is None:
            # Search up from cwd
            cwd = Path.cwd()
            for parent in [cwd, *cwd.parents]:
                candidate = parent / DEFAULT_CONFIG_NAME
                if candidate.exists():
                    path = candidate
                    break

        if path is None or not Path(path).exists():
            return cls()

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        log_data = data.get("log", {})
        log_config = LogConfig(
            file=log_data.get("file", str(DEFAULT_LOG_DIR / "scan.log")),
            format=log_data.get("format", "json"),
        )

        return cls(
            mode=data.get("mode", "block"),
            port=data.get("port", 8080),
            providers=data.get("providers", list(DEFAULT_PROVIDERS)),
            rules={**DEFAULT_RULES, **data.get("rules", {})},
            allowlist=data.get("allowlist", []),
            log=log_config,
        )

    def to_yaml(self) -> str:
        data = {
            "mode": self.mode,
            "port": self.port,
            "providers": self.providers,
            "rules": self.rules,
            "allowlist": self.allowlist,
            "log": {"file": self.log.file, "format": self.log.format},
        }
        return yaml.dump(data, default_flow_style=False, sort_keys=False)


def default_config_yaml() -> str:
    return Config().to_yaml()
