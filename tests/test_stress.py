"""Stress tests for AiGate scanner, redactor, and proxy components."""

import json
import os
import random
import string
import tempfile
import time
import pytest

from aigate.scanner import scan_text, shannon_entropy, Finding
from aigate.redactor import redact_text, save_to_dotenv
from aigate.proxy import _extract_prompt_text, _build_blocked_response


# ---------------------------------------------------------------------------
# 1. VOLUME: Scan huge payloads
# ---------------------------------------------------------------------------

class TestLargePayloads:
    def test_scan_1mb_clean_text(self):
        """1MB of clean prose — should return zero findings quickly."""
        text = "The quick brown fox jumps over the lazy dog. " * 25_000  # ~1.1MB
        start = time.perf_counter()
        findings = scan_text(text)
        elapsed = time.perf_counter() - start
        assert len(findings) == 0
        assert elapsed < 2.0, f"Took {elapsed:.2f}s — too slow for 1MB clean text"

    def test_scan_1mb_with_secrets_scattered(self):
        """1MB of text with 50 secrets scattered throughout."""
        chunks = []
        for i in range(50):
            chunks.append("x" * 20_000)
            chunks.append(f" AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))} ")
        chunks.append("x" * 20_000)
        text = "".join(chunks)
        start = time.perf_counter()
        findings = scan_text(text)
        elapsed = time.perf_counter() - start
        assert len([f for f in findings if f.rule == "aws_keys"]) == 50
        assert elapsed < 3.0, f"Took {elapsed:.2f}s — too slow for 1MB with 50 secrets"

    def test_scan_10k_lines_env_file(self):
        """Massive .env file with 10K lines, 100 real secrets."""
        lines = []
        for i in range(10_000):
            if i % 100 == 0:
                lines.append(f"SECRET_KEY_{i}=sk-{''.join(random.choices(string.ascii_letters + string.digits, k=40))}")
            else:
                lines.append(f"HARMLESS_CONFIG_{i}=some_normal_value")
        text = "\n".join(lines)
        findings = scan_text(text)
        secret_findings = [f for f in findings if f.rule in ("api_tokens", "env_files", "entropy_secrets")]
        assert len(secret_findings) >= 50, f"Expected >=50 secret findings, got {len(secret_findings)}"

    def test_scan_deeply_nested_json(self):
        """Deeply nested JSON with secrets at various levels."""
        obj = {"messages": []}
        for i in range(100):
            obj["messages"].append({
                "role": "user",
                "content": [
                    {"type": "text", "text": f"Normal message {i}"},
                    {"type": "text", "text": f"Key is AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}"},
                ]
            })
        texts = _extract_prompt_text(obj)
        all_text = " ".join(t for _, t in texts)
        findings = scan_text(all_text)
        assert len([f for f in findings if f.rule == "aws_keys"]) == 100


# ---------------------------------------------------------------------------
# 2. PATTERN COVERAGE: Every detection target, edge cases, near-misses
# ---------------------------------------------------------------------------

class TestPatternEdgeCases:
    # AWS keys
    def test_aws_key_exact_20_chars(self):
        findings = scan_text("AKIAIOSFODNN7EXAMPLE1")  # 21 chars after AKIA — too long? No, AKIA + 16 = 20 total
        # AKIAIOSFODNN7EXAMPLE1 is 21 chars, AKIA + 17, should NOT match (needs exactly 16 after AKIA)
        aws = [f for f in findings if f.rule == "aws_keys"]
        assert len(aws) == 0

    def test_aws_key_embedded_in_url(self):
        text = "https://s3.amazonaws.com/?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&sig=abc"
        findings = scan_text(text)
        assert any(f.rule == "aws_keys" for f in findings)

    def test_aws_key_in_json(self):
        text = '{"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE"}'
        findings = scan_text(text)
        assert any(f.rule == "aws_keys" for f in findings)

    def test_aws_key_lowercase_no_match(self):
        text = "akiaiosfodnn7example"
        findings = scan_text(text)
        assert not any(f.rule == "aws_keys" for f in findings)

    # Database URLs
    def test_postgres_with_special_chars_in_password(self):
        text = "postgres://user:p%40ss%23word@host:5432/db"
        findings = scan_text(text)
        assert any(f.rule == "database_urls" for f in findings)

    def test_redis_url(self):
        text = "redis://default:mysecretpassword@redis.example.com:6379/0"
        findings = scan_text(text)
        assert any(f.rule == "database_urls" for f in findings)

    def test_mongodb_srv(self):
        text = "mongodb+srv://admin:hunter2@cluster0.abc123.mongodb.net/mydb"
        findings = scan_text(text)
        assert any(f.rule == "database_urls" for f in findings)

    def test_mssql_url(self):
        text = "mssql://sa:P@ssw0rd!@sqlserver.internal:1433/production"
        findings = scan_text(text)
        assert any(f.rule == "database_urls" for f in findings)

    def test_amqp_url(self):
        text = "amqp://guest:guest@rabbitmq.internal:5672/vhost"
        findings = scan_text(text)
        assert any(f.rule == "database_urls" for f in findings)

    def test_url_without_password_no_match(self):
        text = "postgres://localhost:5432/db"
        findings = scan_text(text)
        assert not any(f.rule == "database_urls" for f in findings)

    # Private keys
    def test_ec_private_key(self):
        text = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk=\n-----END EC PRIVATE KEY-----"
        findings = scan_text(text)
        assert any(f.rule == "private_keys" for f in findings)

    def test_openssh_private_key(self):
        text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHI=\n-----END OPENSSH PRIVATE KEY-----"
        findings = scan_text(text)
        assert any(f.rule == "private_keys" for f in findings)

    def test_public_key_no_match(self):
        text = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----"
        findings = scan_text(text)
        assert not any(f.rule == "private_keys" for f in findings)

    # API tokens
    def test_github_fine_grained_pat(self):
        text = f"github_pat_{''.join(random.choices(string.ascii_letters + string.digits + '_', k=30))}"
        findings = scan_text(text)
        assert any(f.rule == "api_tokens" for f in findings)

    def test_sendgrid_key(self):
        text = f"SG.{''.join(random.choices(string.ascii_letters + string.digits + '_-', k=22))}.{''.join(random.choices(string.ascii_letters + string.digits + '_-', k=22))}"
        findings = scan_text(text)
        assert any(f.rule == "api_tokens" for f in findings)

    def test_slack_app_token(self):
        text = "xapp-1-A123456-789012345-abcdef"
        findings = scan_text(text)
        assert any(f.rule == "api_tokens" for f in findings)

    def test_anthropic_key(self):
        text = "sk-ant-api03-abcdef1234567890abcdef1234567890"
        findings = scan_text(text)
        assert any(f.rule == "api_tokens" for f in findings)

    def test_square_token(self):
        text = f"sq0atp-{''.join(random.choices(string.ascii_letters + string.digits + '_-', k=22))}"
        findings = scan_text(text)
        assert any(f.rule == "api_tokens" for f in findings)

    def test_random_sk_prefix_too_short_no_match(self):
        text = "sk-short"
        findings = scan_text(text)
        assert not any(f.rule == "api_tokens" for f in findings)

    # GCP
    def test_gcp_service_account_with_real_structure(self):
        text = json.dumps({
            "type": "service_account",
            "project_id": "my-project-123",
            "private_key_id": "abc123def456",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
            "client_email": "test@my-project-123.iam.gserviceaccount.com",
        })
        findings = scan_text(text)
        assert any(f.rule == "gcp_service_accounts" for f in findings)

    def test_gcp_without_private_key_no_match(self):
        text = '{"type": "service_account", "project_id": "test"}'
        findings = scan_text(text)
        assert not any(f.rule == "gcp_service_accounts" for f in findings)

    # Tailscale
    def test_tailscale_api_key(self):
        text = f"tskey-api-{''.join(random.choices(string.ascii_letters + string.digits + '-', k=20))}"
        findings = scan_text(text)
        assert any(f.rule == "tailscale_keys" for f in findings)

    def test_tailscale_partial_no_match(self):
        text = "tskey-other-abc"
        findings = scan_text(text)
        assert not any(f.rule == "tailscale_keys" for f in findings)

    # Entropy
    def test_high_entropy_secret_field(self):
        text = 'secret = "x8Kj$mN2pQ9rL5vB7wY4zA1cE6fH3gI0"'
        findings = scan_text(text)
        assert any(f.rule == "entropy_secrets" for f in findings)

    def test_low_entropy_password_no_match(self):
        text = 'password = "passwordpassword"'
        findings = scan_text(text)
        ent = [f for f in findings if f.rule == "entropy_secrets"]
        assert len(ent) == 0

    def test_token_keyword_with_high_entropy_value(self):
        text = 'auth_token = "x8Kj3mN2pQ9rL5vB7wY4zA1cE6fH3gI0"'
        findings = scan_text(text)
        assert any(f.rule == "entropy_secrets" for f in findings)

    def test_uuid_below_entropy_threshold(self):
        """UUIDs have lower entropy than random secrets — borderline case."""
        text = 'auth_token = "550e8400-e29b-41d4-a716-446655440000"'
        # UUID entropy (~3.39) is below the 3.5 threshold — this is by design
        findings = scan_text(text)
        ent = [f for f in findings if f.rule == "entropy_secrets"]
        assert len(ent) == 0


# ---------------------------------------------------------------------------
# 3. FALSE POSITIVE RESISTANCE
# ---------------------------------------------------------------------------

class TestFalsePositives:
    def test_normal_python_code(self):
        text = """
import os
import json
from pathlib import Path

def process_data(input_path: str, output_path: str) -> dict:
    with open(input_path) as f:
        data = json.load(f)
    results = {k: v * 2 for k, v in data.items()}
    Path(output_path).write_text(json.dumps(results))
    return results

if __name__ == "__main__":
    process_data("input.json", "output.json")
"""
        findings = scan_text(text)
        assert len(findings) == 0

    def test_normal_javascript_code(self):
        text = """
const express = require('express');
const app = express();

app.get('/api/users/:id', async (req, res) => {
    const user = await db.findUser(req.params.id);
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json(user);
});

app.listen(3000, () => console.log('Server running on port 3000'));
"""
        findings = scan_text(text)
        assert len(findings) == 0

    def test_documentation_text(self):
        text = """
## Authentication

To authenticate with the API, you'll need an API key.
You can obtain one from the dashboard settings page.

Set the key in your environment:
    export API_KEY=your-key-here

Then use it in requests:
    curl -H "Authorization: Bearer $API_KEY" https://api.example.com
"""
        findings = scan_text(text)
        assert len(findings) == 0, f"False positives: {[(f.rule, f.match) for f in findings]}"

    def test_git_commit_hashes(self):
        text = "commit abc123def456789012345678901234567890abcd\nMerge: 1234567 abcdefg"
        findings = scan_text(text)
        assert len(findings) == 0

    def test_base64_encoded_image(self):
        text = "data:image/png;base64," + "".join(random.choices(string.ascii_letters + string.digits + "+/=", k=200))
        findings = scan_text(text)
        # Should not flag random base64 as a secret (no keyword proximity)
        assert not any(f.rule == "entropy_secrets" for f in findings)

    def test_css_hex_colors(self):
        text = "color: #ff5733; background: #2ecc71; border: 1px solid #333333;"
        findings = scan_text(text)
        assert len(findings) == 0

    def test_uuid_in_normal_context(self):
        text = 'user_id = "550e8400-e29b-41d4-a716-446655440000"'
        findings = scan_text(text)
        assert len(findings) == 0

    def test_markdown_with_code_blocks(self):
        text = """
Here's how to set up your project:

```python
import boto3

client = boto3.client('s3', region_name='us-east-1')
response = client.list_buckets()
```

Make sure to configure your AWS credentials using `aws configure`.
"""
        findings = scan_text(text)
        assert len(findings) == 0

    def test_example_placeholders_no_match(self):
        text = """
AWS_ACCESS_KEY_ID=<your-key>
DATABASE_URL=postgres://user:password@localhost/dev
"""
        # "<your-key>" is only 10 chars including brackets, and "password" is generic
        findings = scan_text(text)
        # The postgres URL has credentials, so database_urls should match
        db = [f for f in findings if f.rule == "database_urls"]
        assert len(db) >= 1
        # But the AWS placeholder should NOT match env_files (value too short or has <>)
        env = [f for f in findings if f.rule == "env_files" and "your-key" in f.match]
        assert len(env) == 0


# ---------------------------------------------------------------------------
# 4. ALLOWLIST STRESS
# ---------------------------------------------------------------------------

class TestAllowlistStress:
    def test_wildcard_patterns(self):
        text = "sk-test-abc123def456ghi789jkl"
        findings = scan_text(text, allowlist=["sk-test-*"])
        assert not any(f.rule == "api_tokens" for f in findings)

    def test_exact_match(self):
        text = "AKIAIOSFODNN7EXAMPLE"
        findings = scan_text(text, allowlist=["AKIAIOSFODNN7EXAMPLE"])
        assert len([f for f in findings if f.rule == "aws_keys"]) == 0

    def test_allowlist_doesnt_suppress_other_secrets(self):
        text = "AKIAIOSFODNN7EXAMPLE postgres://u:p@h/d"
        findings = scan_text(text, allowlist=["AKIAIOSFODNN7EXAMPLE"])
        assert not any(f.rule == "aws_keys" for f in findings)
        assert any(f.rule == "database_urls" for f in findings)

    def test_many_allowlist_patterns(self):
        allowlist = [f"sk-test-{i}*" for i in range(1000)]
        text = "sk-test-999-abcdefghijklmnopqrstuvwxyz"
        findings = scan_text(text, allowlist=allowlist)
        assert not any(f.rule == "api_tokens" for f in findings)

    def test_allowlist_with_special_chars(self):
        text = "AKIAIOSFODNN7EXAMPLE"
        # Pattern that should NOT match
        findings = scan_text(text, allowlist=["AKIA????????WRONG???"])
        assert any(f.rule == "aws_keys" for f in findings)


# ---------------------------------------------------------------------------
# 5. REDACTOR STRESS
# ---------------------------------------------------------------------------

class TestRedactorStress:
    def test_redact_many_different_secrets(self):
        secrets = [
            ("aws_keys", "AKIAIOSFODNN7EXAMPLE"),
            ("database_urls", "postgres://admin:hunter2@db.prod.com:5432/app"),
            ("api_tokens", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"),
            ("api_tokens", "sk-ant-api03-abcdef1234567890abcdef1234567890"),
        ]
        text = " | ".join(s[1] for s in secrets)
        findings_list = [Finding(rule=r, match=m, offset=text.index(m)) for r, m in secrets]
        result = redact_text(text, findings_list)

        for _, original in secrets:
            assert original not in result.redacted_text

        assert len(result.redactions) == 4
        assert "REDACTED" in result.redacted_text

    def test_redact_preserves_surrounding_text(self):
        text = "before AKIAIOSFODNN7EXAMPLE after"
        findings = [Finding(rule="aws_keys", match="AKIAIOSFODNN7EXAMPLE", offset=7)]
        result = redact_text(text, findings)
        assert result.redacted_text.startswith("before ")
        assert result.redacted_text.endswith(" after")

    def test_redact_100_secrets(self):
        """Redact 100 secrets in a single payload."""
        parts = []
        findings = []
        offset = 0
        for i in range(100):
            prefix = f"item {i}: "
            key = f"AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}"
            parts.append(prefix + key)
            findings.append(Finding(rule="aws_keys", match=key, offset=offset + len(prefix)))
            offset += len(prefix) + len(key) + 1
        text = " ".join(parts)
        result = redact_text(text, findings)
        # All 100 should be redacted (they're all unique)
        assert len(result.redactions) == 100
        for r in result.redactions:
            assert r.finding.match not in result.redacted_text

    def test_dotenv_concurrent_writes(self):
        """Write many secrets to .env in sequence."""
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env")
            for i in range(50):
                key = f"AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}"
                findings = [Finding(rule="aws_keys", match=key, offset=0)]
                result = redact_text(key, findings)
                # Override env var name to be unique
                result.redactions[0].env_var_name = f"AWS_KEY_{i}"
                save_to_dotenv(result.redactions, env_path)
            content = open(env_path).read()
            lines = [l for l in content.splitlines() if l.startswith("AWS_KEY_")]
            assert len(lines) == 50

    def test_system_instruction_with_many_redactions(self):
        findings = []
        for i in range(20):
            findings.append(Finding(rule="api_tokens", match=f"sk-fake-{i}-{'x'*20}", offset=i * 30))
        text = " ".join(f.match for f in findings)
        result = redact_text(text, findings)
        instr = result.system_instruction
        assert "os.environ" in instr
        assert instr.count("REDACTED") >= 20


# ---------------------------------------------------------------------------
# 6. PROXY EXTRACTION STRESS
# ---------------------------------------------------------------------------

class TestProxyExtractionStress:
    def test_extract_100_messages(self):
        body = {
            "messages": [
                {"role": "user" if i % 2 == 0 else "assistant", "content": f"Message {i}"}
                for i in range(100)
            ]
        }
        texts = _extract_prompt_text(body)
        assert len(texts) == 100

    def test_extract_nested_tool_results(self):
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "content": [
                                {"type": "text", "text": f"Result {i}"}
                                for i in range(50)
                            ]
                        }
                    ]
                }
            ]
        }
        texts = _extract_prompt_text(body)
        assert len(texts) >= 50

    def test_extract_mixed_content_types(self):
        body = {
            "system": [
                {"type": "text", "text": "System instruction 1"},
                {"type": "text", "text": "System instruction 2"},
            ],
            "messages": [
                {"role": "user", "content": "Simple string"},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Block text"},
                        {"type": "image", "source": {"data": "..."}},
                        {"type": "text", "text": "More text"},
                    ]
                },
            ],
            "tools": [
                {"description": "A tool", "input_schema": {"type": "object"}},
                {"function": {"description": "Another tool"}},
            ],
        }
        texts = _extract_prompt_text(body)
        text_values = [t for _, t in texts]
        assert any("System instruction 1" in t for t in text_values)
        assert any("Simple string" in t for t in text_values)
        assert any("Block text" in t for t in text_values)
        assert any("More text" in t for t in text_values)
        assert any("A tool" in t for t in text_values)
        assert any("Another tool" in t for t in text_values)

    def test_extract_empty_body(self):
        texts = _extract_prompt_text({})
        assert texts == []

    def test_extract_malformed_messages(self):
        body = {
            "messages": [
                {"role": "user"},  # no content
                {"role": "user", "content": None},
                {"role": "user", "content": 42},  # wrong type
                {"role": "user", "content": "valid"},
            ]
        }
        texts = _extract_prompt_text(body)
        assert any("valid" in t for _, t in texts)


# ---------------------------------------------------------------------------
# 7. SHANNON ENTROPY EDGE CASES
# ---------------------------------------------------------------------------

class TestEntropyEdgeCases:
    def test_single_char(self):
        assert shannon_entropy("a") == 0.0

    def test_two_unique_chars(self):
        e = shannon_entropy("ab")
        assert 0.9 < e < 1.1  # should be 1.0

    def test_all_printable_ascii(self):
        e = shannon_entropy(string.printable)
        assert e > 5.0  # very high entropy

    def test_repeated_pattern(self):
        e = shannon_entropy("abcabc" * 100)
        assert e < 2.0

    def test_binary_like_string(self):
        e = shannon_entropy("0" * 50 + "1" * 50)
        assert 0.9 < e < 1.1


# ---------------------------------------------------------------------------
# 8. BLOCKED RESPONSE FORMAT STRESS
# ---------------------------------------------------------------------------

class TestBlockedResponseStress:
    def test_response_with_many_findings(self):
        findings = [
            Finding(rule=f"rule_{i}", match=f"secret_{i}_{'x'*20}", offset=i * 100, location=f"messages[{i}].content")
            for i in range(50)
        ]
        resp_text = _build_blocked_response(findings)
        resp = json.loads(resp_text)
        assert resp["error"]["type"] == "blocked_by_aigate"
        assert len(resp["error"]["details"]) == 50

    def test_response_with_special_chars_in_match(self):
        findings = [
            Finding(rule="database_urls", match='postgres://user:"p@ss\'w<>rd"@host/db', offset=0)
        ]
        resp_text = _build_blocked_response(findings)
        resp = json.loads(resp_text)  # should be valid JSON
        assert len(resp["error"]["details"]) == 1

    def test_response_with_unicode(self):
        findings = [
            Finding(rule="test", match="secret_with_émojis_🔑", offset=0)
        ]
        resp_text = _build_blocked_response(findings)
        resp = json.loads(resp_text)
        assert "blocked_by_aigate" in resp["error"]["type"]


# ---------------------------------------------------------------------------
# 9. COMBINED PIPELINE: scan → redact → verify
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_scan_then_redact_then_verify_clean(self):
        """The redacted text should pass a second scan with zero findings."""
        text = (
            "Connect with AKIAIOSFODNN7EXAMPLE and "
            "postgres://admin:supersecret@db.prod.com:5432/app and "
            "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
        )
        # Scan
        findings = scan_text(text)
        assert len(findings) >= 3

        # Redact
        result = redact_text(text, findings)
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text
        assert "supersecret" not in result.redacted_text

        # Re-scan the redacted text — should be clean
        re_findings = scan_text(result.redacted_text)
        remaining = [f for f in re_findings if f.rule in ("aws_keys", "database_urls", "api_tokens")]
        assert len(remaining) == 0, f"Redacted text still has secrets: {[(f.rule, f.match) for f in remaining]}"

    def test_scan_then_redact_multiple_of_same_type(self):
        keys = [f"AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}" for _ in range(5)]
        text = " and ".join(keys)
        findings = scan_text(text)
        assert len([f for f in findings if f.rule == "aws_keys"]) == 5
        result = redact_text(text, findings)
        for key in keys:
            assert key not in result.redacted_text

    def test_redact_saves_all_to_dotenv(self):
        """Full pipeline: scan, redact, save to .env, verify .env."""
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env")
            text = "AKIAIOSFODNN7EXAMPLE postgres://u:secret@h:5432/d"
            findings = scan_text(text)
            result = redact_text(text, findings)
            save_to_dotenv(result.redactions, env_path)
            content = open(env_path).read()
            assert "AKIAIOSFODNN7EXAMPLE" in content
            assert "postgres://u:secret@h:5432/d" in content


# ---------------------------------------------------------------------------
# 10. PERFORMANCE BENCHMARKS
# ---------------------------------------------------------------------------

class TestPerformance:
    def test_scan_latency_under_50ms_for_typical_prompt(self):
        """Typical AI prompt should scan in under 50ms."""
        text = "Please help me write a Python function that connects to a PostgreSQL database and retrieves user records. Use SQLAlchemy."
        times = []
        for _ in range(100):
            start = time.perf_counter()
            scan_text(text)
            times.append(time.perf_counter() - start)
        avg_ms = (sum(times) / len(times)) * 1000
        p99_ms = sorted(times)[98] * 1000
        assert avg_ms < 50, f"Average scan time {avg_ms:.1f}ms exceeds 50ms"
        assert p99_ms < 100, f"P99 scan time {p99_ms:.1f}ms exceeds 100ms"

    def test_scan_latency_under_200ms_for_large_prompt(self):
        """Large prompt (100KB) should scan in under 200ms."""
        text = "Normal text. " * 8000  # ~100KB
        text += " AKIAIOSFODNN7EXAMPLE "  # one secret at the end
        times = []
        for _ in range(10):
            start = time.perf_counter()
            findings = scan_text(text)
            times.append(time.perf_counter() - start)
        assert len([f for f in findings if f.rule == "aws_keys"]) == 1
        avg_ms = (sum(times) / len(times)) * 1000
        assert avg_ms < 200, f"Average scan time {avg_ms:.1f}ms exceeds 200ms for 100KB"

    def test_redact_latency_under_100ms(self):
        """Redaction of 10 secrets should be under 100ms."""
        secrets = [f"AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}" for _ in range(10)]
        text = " text ".join(secrets)
        findings = [Finding(rule="aws_keys", match=s, offset=text.index(s)) for s in secrets]
        times = []
        for _ in range(50):
            start = time.perf_counter()
            redact_text(text, findings)
            times.append(time.perf_counter() - start)
        avg_ms = (sum(times) / len(times)) * 1000
        assert avg_ms < 100, f"Average redact time {avg_ms:.1f}ms exceeds 100ms"
