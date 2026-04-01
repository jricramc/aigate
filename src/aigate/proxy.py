"""HTTP(S) proxy that intercepts AI API calls and scans for secrets."""

from __future__ import annotations

import json

from mitmproxy import http, ctx
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from aigate.config import Config
from aigate.logger import log_detection
from aigate.redactor import redact_text, save_to_dotenv
from aigate.scanner import Finding, scan_text


def _extract_prompt_text(body: dict) -> list[tuple[str, str]]:
    """Extract text content from AI API request bodies."""
    texts: list[tuple[str, str]] = []
    messages = body.get("messages", [])

    for i, msg in enumerate(messages):
        content = msg.get("content")
        if isinstance(content, str):
            texts.append((f"messages[{i}].content", content))
        elif isinstance(content, list):
            for j, block in enumerate(content):
                if not isinstance(block, dict):
                    continue
                btype = block.get("type")
                if btype == "text":
                    texts.append((f"messages[{i}].content[{j}].text", block.get("text", "")))
                elif btype == "tool_result":
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

    # OpenAI fallback: if no texts extracted yet, try simple messages
    if not texts and messages:
        for i, msg in enumerate(messages):
            content = msg.get("content")
            if isinstance(content, str):
                texts.append((f"messages[{i}].content", content))

    # OpenAI completions: prompt field
    prompt = body.get("prompt")
    if isinstance(prompt, str):
        texts.append(("prompt", prompt))
    elif isinstance(prompt, list):
        for i, p in enumerate(prompt):
            if isinstance(p, str):
                texts.append((f"prompt[{i}]", p))

    # Tool definitions
    for i, tool in enumerate(body.get("tools", [])):
        if not isinstance(tool, dict):
            continue
        desc = tool.get("description", "")
        schema = tool.get("input_schema", {})
        if isinstance(schema, dict):
            desc = f"{desc} {json.dumps(schema)}"
        func = tool.get("function", {})
        if isinstance(func, dict):
            desc = f"{desc} {func.get('description', '')}"
        if desc.strip():
            texts.append((f"tools[{i}]", desc))

    return texts


def _build_blocked_response(findings: list[Finding]) -> str:
    rules = sorted({f.rule.replace("_", " ") for f in findings})
    return json.dumps({
        "error": {
            "type": "blocked_by_aigate",
            "message": f"AiGate blocked this request: {', '.join(rules)} detected in prompt content",
            "details": [
                {
                    "rule": f.rule,
                    "match": f.redacted,
                    "location": f"{f.location}, offset {f.offset}" if f.location else f"offset {f.offset}",
                }
                for f in findings
            ],
            "action": "Remove the credential from your prompt and retry.",
        }
    })


class AiGateAddon:
    """mitmproxy addon that scans AI API requests for secrets."""

    def __init__(self, config: Config):
        self.config = config
        self.provider_hosts = set(config.providers)

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.pretty_host not in self.provider_hosts:
            return
        if flow.request.method != "POST":
            return
        if "json" not in flow.request.headers.get("content-type", ""):
            return

        try:
            body = json.loads(flow.request.get_text())
        except (json.JSONDecodeError, ValueError):
            return

        all_findings: list[Finding] = []
        for location, text in _extract_prompt_text(body):
            for f in scan_text(text, enabled_rules=self.config.rules, allowlist=self.config.allowlist):
                f.location = location
                all_findings.append(f)

        if not all_findings:
            return

        log_detection(
            self.config.log.file,
            provider=flow.request.pretty_host,
            findings=all_findings,
            action=self.config.mode,
            request_url=flow.request.pretty_url,
        )

        rules = {f.rule for f in all_findings}
        ctx.log.warn(
            f"[AiGate] {len(all_findings)} secret(s) detected ({', '.join(rules)}) "
            f"-> action: {self.config.mode}"
        )

        if self.config.mode == "redact":
            self._handle_redact(flow, all_findings)
        elif self.config.mode == "block":
            flow.response = http.Response.make(
                400, _build_blocked_response(all_findings), {"Content-Type": "application/json"},
            )
        elif self.config.mode == "warn":
            for f in all_findings:
                ctx.log.warn(f"  ! {f.rule}: {f.redacted} at {f.location}")

    def _handle_redact(self, flow: http.HTTPFlow, findings: list[Finding]) -> None:
        result = redact_text(flow.request.get_text(), findings)
        flow.request.set_text(result.redacted_text)

        for r in result.redactions:
            ctx.log.warn(f"  ~ {r.finding.rule}: redacted -> {r.placeholder} (use {r.env_var_name})")

        for action in save_to_dotenv(result.redactions):
            ctx.log.info(f"  > {action}")

        # Inject system instruction
        try:
            redacted_body = json.loads(flow.request.get_text())
        except (json.JSONDecodeError, ValueError):
            return

        instruction = result.system_instruction
        if not instruction:
            return

        existing = redacted_body.get("system")
        if isinstance(existing, str):
            redacted_body["system"] = f"{existing}\n\n{instruction}"
        elif isinstance(existing, list):
            redacted_body["system"].append({"type": "text", "text": instruction})
        else:
            redacted_body["system"] = instruction

        flow.request.set_text(json.dumps(redacted_body))


async def run_proxy(config: Config) -> None:
    opts = Options(listen_host="127.0.0.1", listen_port=config.port, mode=["regular"])
    master = DumpMaster(opts)
    master.addons.add(AiGateAddon(config))
    try:
        await master.run()
    except KeyboardInterrupt:
        master.shutdown()
