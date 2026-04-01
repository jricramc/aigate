"""Tests for the proxy request parsing and response building."""

import json
import pytest
from aigate.proxy import _extract_prompt_text, _build_blocked_response
from aigate.scanner import Finding


class TestExtractPromptText:
    def test_anthropic_messages_string_content(self):
        body = {
            "messages": [
                {"role": "user", "content": "Hello world"}
            ]
        }
        texts = _extract_prompt_text(body)
        assert any("Hello world" in t for _, t in texts)

    def test_anthropic_messages_block_content(self):
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Check this code"}
                    ]
                }
            ]
        }
        texts = _extract_prompt_text(body)
        assert any("Check this code" in t for _, t in texts)

    def test_system_prompt_string(self):
        body = {
            "system": "You are a helpful assistant",
            "messages": []
        }
        texts = _extract_prompt_text(body)
        assert any("helpful assistant" in t for _, t in texts)

    def test_openai_prompt_field(self):
        body = {"prompt": "Complete this: def hello"}
        texts = _extract_prompt_text(body)
        assert any("Complete this" in t for _, t in texts)

    def test_tool_result_content(self):
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "content": "Result with AKIAIOSFODNN7EXAMPLE"
                        }
                    ]
                }
            ]
        }
        texts = _extract_prompt_text(body)
        assert any("AKIAIOSFODNN7EXAMPLE" in t for _, t in texts)


class TestBuildBlockedResponse:
    def test_response_format(self):
        findings = [
            Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=42, location="messages[0].content"),
        ]
        resp = json.loads(_build_blocked_response(findings))
        assert resp["error"]["type"] == "blocked_by_aigate"
        assert "aws keys" in resp["error"]["message"]
        assert len(resp["error"]["details"]) == 1
        assert resp["error"]["details"][0]["rule"] == "aws_keys"

    def test_multiple_findings(self):
        findings = [
            Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=10, location="messages[0].content"),
            Finding(rule="database_urls", match="postgres://u:p@h/d", offset=200, location="messages[1].content"),
        ]
        resp = json.loads(_build_blocked_response(findings))
        assert len(resp["error"]["details"]) == 2
