"""Tests for the secret redactor."""

import os
import tempfile
import pytest
from aigate.scanner import Finding
from aigate.redactor import redact_text, save_to_dotenv, _env_var_name_for, _secret_value_for


class TestRedactText:
    def test_replaces_aws_key(self):
        text = "Use this key AKIAIOSFODNN7EXAMPLE to connect"
        findings = [Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=13)]
        result = redact_text(text, findings)
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text
        assert "[REDACTED_AWS_ACCESS_KEY_ID]" in result.redacted_text
        assert len(result.redactions) == 1
        assert result.redactions[0].env_var_name == "AWS_ACCESS_KEY_ID"

    def test_replaces_database_url(self):
        text = "db: postgres://admin:s3cret@db.host:5432/prod"
        findings = [Finding(rule="database_urls", match="postgres://admin:s3cret@db.host:5432/prod", offset=4)]
        result = redact_text(text, findings)
        assert "s3cret" not in result.redacted_text
        assert "[REDACTED_DATABASE_URL]" in result.redacted_text

    def test_replaces_env_file_entry(self):
        text = "API_KEY=sk-super-secret-key-12345"
        findings = [Finding(rule="env_files", match="API_KEY=sk-super-secret-key-12345", offset=0)]
        result = redact_text(text, findings)
        assert "sk-super-secret-key-12345" not in result.redacted_text
        assert result.redactions[0].env_var_name == "API_KEY"
        assert result.redactions[0].original_value == "sk-super-secret-key-12345"

    def test_multiple_secrets(self):
        text = "key=AKIAIOSFODNN7EXAMPLE db=postgres://u:p@h/d"
        findings = [
            Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=4),
            Finding(rule="database_urls", match="postgres://u:p@h/d", offset=28),
        ]
        result = redact_text(text, findings)
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text
        assert "postgres://u:p@h/d" not in result.redacted_text
        assert len(result.redactions) == 2

    def test_no_findings(self):
        text = "clean text"
        result = redact_text(text, [])
        assert result.redacted_text == "clean text"
        assert result.redactions == []

    def test_deduplicates_same_secret(self):
        text = "key AKIAIOSFODNN7EXAMPLE and again AKIAIOSFODNN7EXAMPLE"
        findings = [
            Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=4),
            Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=35),
        ]
        result = redact_text(text, findings)
        assert result.redacted_text.count("[REDACTED_AWS_ACCESS_KEY_ID]") == 2
        assert len(result.redactions) == 1  # deduplicated


class TestSystemInstruction:
    def test_generates_instruction(self):
        findings = [Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=0)]
        result = redact_text("AKIAIOSFODNN7EXAMPLE", findings)
        instr = result.system_instruction
        assert "os.environ['AWS_ACCESS_KEY_ID']" in instr
        assert "process.env.AWS_ACCESS_KEY_ID" in instr
        assert "redacted" in instr.lower()

    def test_no_instruction_when_clean(self):
        result = redact_text("clean", [])
        assert result.system_instruction == ""


class TestSaveToDotenv:
    def test_creates_new_env_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env")
            findings = [Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=0)]
            result = redact_text("AKIAIOSFODNN7EXAMPLE", findings)
            actions = save_to_dotenv(result.redactions, env_path)
            assert any("Added" in a for a in actions)
            content = open(env_path).read()
            assert "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" in content

    def test_appends_to_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env")
            with open(env_path, "w") as f:
                f.write("EXISTING=value\n")
            findings = [Finding(rule="database_urls", match="postgres://u:p@h/d", offset=0)]
            result = redact_text("postgres://u:p@h/d", findings)
            save_to_dotenv(result.redactions, env_path)
            content = open(env_path).read()
            assert "EXISTING=value" in content
            assert "DATABASE_URL=postgres://u:p@h/d" in content

    def test_skips_existing_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env")
            with open(env_path, "w") as f:
                f.write("AWS_ACCESS_KEY_ID=old-value\n")
            findings = [Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=0)]
            result = redact_text("AKIAIOSFODNN7EXAMPLE", findings)
            actions = save_to_dotenv(result.redactions, env_path)
            assert any("skipped" in a for a in actions)
            content = open(env_path).read()
            assert "old-value" in content
            assert "AKIAIOSFODNN7EXAMPLE" not in content


class TestEnvVarNaming:
    def test_aws_key(self):
        f = Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=0)
        assert _env_var_name_for(f, 0) == "AWS_ACCESS_KEY_ID"

    def test_env_file_extracts_name(self):
        f = Finding(rule="env_files", match="STRIPE_SECRET_KEY=sk_live_123", offset=0)
        assert _env_var_name_for(f, 0) == "STRIPE_SECRET_KEY"

    def test_multiple_same_rule(self):
        f = Finding(rule="api_tokens", match="sk-something", offset=0)
        assert _env_var_name_for(f, 0) == "API_KEY"
        assert _env_var_name_for(f, 1) == "API_KEY_2"

    def test_secret_value_for_env(self):
        f = Finding(rule="env_files", match="DB_PASSWORD=hunter2", offset=0)
        assert _secret_value_for(f) == "hunter2"

    def test_secret_value_for_regular(self):
        f = Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=0)
        assert _secret_value_for(f) == "AKIAIOSFODNN7EXAMPLE"
