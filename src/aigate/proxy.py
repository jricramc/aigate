"""HTTP(S) proxy that intercepts AI API calls and scans for secrets."""

from __future__ import annotations

import json

from mitmproxy import http, ctx
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from aigate.config import Config
from aigate.logger import log_detection
from aigate.scanner import Finding, scan_text


def _extract_prompt_text(body: dict) -> list[tuple[str, str]]:
    """Extract text content from AI API request bodies.

    Returns list of (location, text) tuples.
    """
    texts: list[tuple[str, str]] = []

    # Anthropic Messages API
    messages = body.get("messages", [])
    for i, msg in enumerate(messages):
        content = msg.get("content")
        if isinstance(content, str):
            texts.append((f"messages[{i}].content", content))
        elif isinstance(content, list):
            for j, block in enumerate(content):
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        texts.append((f"messages[{i}].content[{j}].text", block.get("text", "")))
                    elif block.get("type") == "tool_result":
                        inner = block.get("content", "")
                        if isinstance(inner, str):
                            texts.append((f"messages[{i}].content[{j}].content", inner))
                        elif isinstance(inner, list):
                            for k, sub in enumerate(inner):
                                if isinstance(sub, dict) and sub.get("type") == "text":
                                    texts.append((f"messages[{i}].content[{j}].content[{k}].text", sub.get("text", "")))

    # System prompt
    system = body.get("system")
    if isinstance(system, str):
        texts.append(("system", system))
    elif isinstance(system, list):
        for i, block in enumerate(system):
            if isinstance(block, dict) and block.get("type") == "text":
                texts.append((f"system[{i}].text", block.get("text", "")))

    # OpenAI-style: messages with role/content
    if not texts and messages:
        for i, msg in enumerate(messages):
            content = msg.get("content")
            if isinstance(content, str):
                texts.append((f"messages[{i}].content", content))

    # OpenAI: prompt field (completions)
    prompt = body.get("prompt")
    if isinstance(prompt, str):
        texts.append(("prompt", prompt))
    elif isinstance(prompt, list):
        for i, p in enumerate(prompt):
            if isinstance(p, str):
                texts.append((f"prompt[{i}]", p))

    # Tools / tool definitions may contain secrets in descriptions
    tools = body.get("tools", [])
    for i, tool in enumerate(tools):
        desc = None
        if isinstance(tool, dict):
            desc = tool.get("description", "")
            # Anthropic tool format
            input_schema = tool.get("input_schema", {})
            if isinstance(input_schema, dict):
                desc = (desc or "") + " " + json.dumps(input_schema)
            # OpenAI function format
            func = tool.get("function", {})
            if isinstance(func, dict):
                desc = (desc or "") + " " + func.get("description", "")
        if desc:
            texts.append((f"tools[{i}]", desc))

    return texts


def _build_blocked_response(findings: list[Finding]) -> str:
    """Build the JSON error response for blocked requests."""
    primary = findings[0]
    details = [
        {
            "rule": f.rule,
            "match": f.redacted,
            "location": f"{f.location}, offset {f.offset}" if f.location else f"offset {f.offset}",
        }
        for f in findings
    ]
    rule_names = {f.rule.replace("_", " ") for f in findings}
    detected = ", ".join(sorted(rule_names))
    return json.dumps({
        "error": {
            "type": "blocked_by_aigate",
            "message": f"AiGate blocked this request: {detected} detected in prompt content",
            "details": details,
            "action": "Remove the credential from your prompt and retry.",
        }
    })


class AiGateAddon:
    """mitmproxy addon that scans AI API requests for secrets."""

    def __init__(self, config: Config):
        self.config = config
        self.provider_hosts = set(config.providers)

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if host not in self.provider_hosts:
            return

        # Only scan POST requests with JSON bodies
        if flow.request.method != "POST":
            return

        content_type = flow.request.headers.get("content-type", "")
        if "json" not in content_type:
            return

        try:
            body = json.loads(flow.request.get_text())
        except (json.JSONDecodeError, ValueError):
            return

        texts = _extract_prompt_text(body)
        all_findings: list[Finding] = []

        for location, text in texts:
            findings = scan_text(
                text,
                enabled_rules=self.config.rules,
                allowlist=self.config.allowlist,
            )
            for f in findings:
                f.location = location
            all_findings.extend(findings)

        if not all_findings:
            return

        # Log the detection
        log_detection(
            self.config.log.file,
            provider=host,
            findings=all_findings,
            action=self.config.mode,
            request_url=flow.request.pretty_url,
        )

        count = len(all_findings)
        rules = {f.rule for f in all_findings}
        ctx.log.warn(
            f"[AiGate] {count} secret(s) detected ({', '.join(rules)}) "
            f"→ action: {self.config.mode}"
        )

        if self.config.mode == "block":
            flow.response = http.Response.make(
                400,
                _build_blocked_response(all_findings),
                {"Content-Type": "application/json"},
            )
        elif self.config.mode == "warn":
            # Forward but print warning
            for f in all_findings:
                ctx.log.warn(f"  ⚠ {f.rule}: {f.redacted} at {f.location}")
        # audit mode: just log, no terminal output beyond the initial line


async def run_proxy(config: Config) -> None:
    """Start the mitmproxy-based proxy."""
    opts = Options(
        listen_host="127.0.0.1",
        listen_port=config.port,
        mode=[f"regular"],
    )
    master = DumpMaster(opts)
    master.addons.add(AiGateAddon(config))

    try:
        await master.run()
    except KeyboardInterrupt:
        master.shutdown()
