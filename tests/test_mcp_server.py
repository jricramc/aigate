"""Tests for the MCP server tools."""

import pytest

from aigate.mcp_server import (
    _line_number,
    _suggest_env_reference,
    _findings_to_response,
    aigate_scan_code,
    aigate_store_secret,
    aigate_scan_file,
)
from aigate.scanner import Finding


class TestLineNumber:
    def test_first_line(self):
        assert _line_number("hello world", 0) == 1

    def test_second_line(self):
        assert _line_number("line1\nline2", 6) == 2

    def test_third_line(self):
        assert _line_number("a\nb\nc", 4) == 3


class TestSuggestEnvReference:
    def test_python_default(self):
        assert _suggest_env_reference("API_KEY") == "os.environ['API_KEY']"

    def test_javascript(self):
        assert _suggest_env_reference("API_KEY", "app.js") == "process.env.API_KEY"

    def test_typescript(self):
        assert _suggest_env_reference("API_KEY", "app.ts") == "process.env.API_KEY"

    def test_ruby(self):
        assert _suggest_env_reference("API_KEY", "config.rb") == "ENV['API_KEY']"

    def test_go(self):
        assert _suggest_env_reference("API_KEY", "main.go") == 'os.Getenv("API_KEY")'

    def test_rust(self):
        assert _suggest_env_reference("API_KEY", "main.rs") == 'std::env::var("API_KEY")'


class TestFindingsToResponse:
    def test_clean_when_no_findings(self):
        result = _findings_to_response([], "some code")
        assert result == {"clean": True, "findings": []}

    def test_findings_include_line_and_suggestion(self):
        # Use an AWS key which has a simple, predictable env var mapping
        findings = [Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=20)]
        text = "import os\naws_key = AKIAIOSFODNN7EXAMPLE"
        result = _findings_to_response(findings, text, "app.py")
        assert result["clean"] is False
        assert len(result["findings"]) == 1
        f = result["findings"][0]
        assert f["rule"] == "aws_keys"
        assert f["line"] == 2
        assert "os.environ" in f["suggestion"]
        assert f["env_var"] == "AWS_ACCESS_KEY_ID"


class TestAigateScanCode:
    def test_clean_code(self):
        result = aigate_scan_code("x = 1 + 2")
        assert result["clean"] is True

    def test_detects_secret(self):
        result = aigate_scan_code("api_key = '[REDACTED_OPENAI_API_KEY]678'")
        assert result["clean"] is False
        assert len(result["findings"]) >= 1

    def test_with_file_path(self):
        result = aigate_scan_code(
            "const key = '[REDACTED_OPENAI_API_KEY]678'",
            file_path="app.js",
        )
        if not result["clean"]:
            assert "process.env" in result["findings"][0]["suggestion"]


class TestAigateStoreSecret:
    def test_stores_new_secret(self, tmp_path):
        env_file = tmp_path / ".env"
        result = aigate_store_secret("MY_KEY", "secret_value_123", file_path=str(env_file))
        assert result["stored"] is True
        assert "MY_KEY" in result["env_reference"]
        assert env_file.read_text().strip().endswith("MY_KEY=secret_value_123")

    def test_skip_existing_key(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("MY_KEY=old_value\n")
        result = aigate_store_secret("MY_KEY", "new_value", file_path=str(env_file))
        assert result["stored"] is False
        assert "already" in result["message"].lower() or "skipped" in result["message"].lower()


class TestAigateScanFile:
    def test_file_not_found(self):
        result = aigate_scan_file("/nonexistent/file.py")
        assert "error" in result

    def test_clean_file(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("x = 1 + 2\nprint(x)\n")
        result = aigate_scan_file(str(f))
        assert result["clean"] is True

    def test_dirty_file(self, tmp_path):
        f = tmp_path / "dirty.py"
        f.write_text("api_key = '[REDACTED_OPENAI_API_KEY]678'\n")
        result = aigate_scan_file(str(f))
        assert result["clean"] is False
        assert len(result["findings"]) >= 1
        assert result["file"] == str(f)
