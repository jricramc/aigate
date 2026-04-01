"""JSON logger for scan detections."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from aigate.scanner import Finding


def log_detection(
    log_file: str,
    *,
    provider: str,
    findings: list[Finding],
    action: str,
    request_url: str = "",
) -> None:
    """Append a JSON-lines log entry for a detection event."""
    path = Path(log_file).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": provider,
        "request_url": request_url,
        "action": action,
        "findings": [
            {
                "rule": f.rule,
                "match_redacted": f.redacted,
                "offset": f.offset,
                "location": f.location,
            }
            for f in findings
        ],
    }

    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
