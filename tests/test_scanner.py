"""Tests for the secret scanner."""

import pytest
from aigate.scanner import scan_text, shannon_entropy, Finding


class TestAWSKeys:
    def test_detects_aws_access_key(self):
        text = "Here is my key: AKIAIOSFODNN7EXAMPLE and some more text"
        findings = scan_text(text)
        assert any(f.rule == "aws_keys" for f in findings)

    def test_ignores_partial_match(self):
        text = "Not a real key: AKIA123"
        findings = scan_text(text, enabled_rules={"aws_keys": True})
        aws = [f for f in findings if f.rule == "aws_keys"]
        assert len(aws) == 0

    def test_allowlist_suppresses(self):
        text = "Key: AKIAIOSFODNN7EXAMPLE"
        findings = scan_text(text, allowlist=["AKIAIOSFODNN7EXAMPLE"])
        assert len([f for f in findings if f.rule == "aws_keys"]) == 0


class TestDatabaseURLs:
    def test_detects_postgres_url(self):
        text = 'DATABASE_URL=postgres://admin:s3cret@db.example.com:5432/mydb'
        findings = scan_text(text)
        assert any(f.rule == "database_urls" for f in findings)

    def test_detects_mysql_url(self):
        text = 'mysql://root:password123@localhost/prod'
        findings = scan_text(text)
        assert any(f.rule == "database_urls" for f in findings)

    def test_detects_mongodb_url(self):
        text = 'mongodb+srv://user:pass@cluster0.abc.mongodb.net/db'
        findings = scan_text(text)
        assert any(f.rule == "database_urls" for f in findings)


class TestPrivateKeys:
    def test_detects_rsa_private_key(self):
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbLOttGAPDdwMiCDMfQGW2aDkG
randomkeycontenthere1234567890abc
-----END RSA PRIVATE KEY-----"""
        findings = scan_text(text)
        assert any(f.rule == "private_keys" for f in findings)

    def test_detects_generic_private_key(self):
        text = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAAA
longkeycontenthere1234567890abcdef
-----END PRIVATE KEY-----"""
        findings = scan_text(text)
        assert any(f.rule == "private_keys" for f in findings)


class TestAPITokens:
    def test_detects_openai_key(self):
        text = "OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
        findings = scan_text(text)
        assert any(f.rule == "api_tokens" for f in findings)

    def test_detects_github_pat(self):
        text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
        findings = scan_text(text)
        assert any(f.rule == "api_tokens" for f in findings)

    def test_detects_gitlab_pat(self):
        text = "GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx"
        findings = scan_text(text)
        assert any(f.rule == "api_tokens" for f in findings)

    def test_detects_slack_bot_token(self):
        text = "SLACK_TOKEN=xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
        findings = scan_text(text)
        assert any(f.rule == "api_tokens" for f in findings)

    def test_detects_anthropic_key(self):
        text = "key = sk-ant-abc123def456ghi789jkl012"
        findings = scan_text(text)
        assert any(f.rule == "api_tokens" for f in findings)


class TestEnvFiles:
    def test_detects_env_variable(self):
        text = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        findings = scan_text(text)
        assert any(f.rule == "env_files" for f in findings)

    def test_detects_database_url_env(self):
        text = "DATABASE_URL=postgres://user:pass@host/db"
        findings = scan_text(text)
        # Should catch both database_urls and env_files
        rules = {f.rule for f in findings}
        assert "env_files" in rules or "database_urls" in rules

    def test_ignores_short_values(self):
        text = "API_KEY=short"
        findings = scan_text(text, enabled_rules={"env_files": True})
        env = [f for f in findings if f.rule == "env_files"]
        assert len(env) == 0  # too short (< 8 chars)


class TestGCPServiceAccounts:
    def test_detects_service_account(self):
        text = '''{
  "type": "service_account",
  "project_id": "my-project",
  "private_key_id": "abc123",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\\nMIIE..."
}'''
        findings = scan_text(text)
        assert any(f.rule == "gcp_service_accounts" for f in findings)


class TestTailscaleKeys:
    def test_detects_tailscale_auth_key(self):
        text = "TS_AUTHKEY=tskey-auth-kAbCdEfGhIjKlMnOpQrStUvWx"
        findings = scan_text(text)
        assert any(f.rule == "tailscale_keys" for f in findings)


class TestEntropySecrets:
    def test_detects_high_entropy_password(self):
        text = 'password = "aK9$mP2xLqR7nB4vZ8wF3hJ6"'
        findings = scan_text(text)
        assert any(f.rule == "entropy_secrets" for f in findings)

    def test_ignores_low_entropy(self):
        text = 'password = "aaaaaaaaaaaa"'
        findings = scan_text(text, enabled_rules={"entropy_secrets": True})
        entropy = [f for f in findings if f.rule == "entropy_secrets"]
        assert len(entropy) == 0


class TestShannonEntropy:
    def test_high_entropy(self):
        assert shannon_entropy("aK9$mP2xLqR7nB4v") > 3.5

    def test_low_entropy(self):
        assert shannon_entropy("aaaaaaaaaa") < 1.0

    def test_empty(self):
        assert shannon_entropy("") == 0.0


class TestCleanPassthrough:
    def test_normal_code_no_findings(self):
        text = """
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)

# Test
for i in range(10):
    print(fibonacci(i))
"""
        findings = scan_text(text)
        assert len(findings) == 0

    def test_normal_prose_no_findings(self):
        text = "Please help me write a Python function that sorts a list of integers."
        findings = scan_text(text)
        assert len(findings) == 0


class TestRedaction:
    def test_long_match_redacted(self):
        f = Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=0)
        assert "AKIA" in f.redacted
        assert "MPLE" in f.redacted
        assert "IOSFODNN7EXA" not in f.redacted

    def test_short_match_redacted(self):
        f = Finding(rule="test", match="short", offset=0)
        assert f.redacted == "****"
