"""End-to-end tests for aigate v2 features.

Tests the real hook scripts, MCP server via JSON-RPC, and scan-dir pipeline
against actual file system operations. No mocking — exercises the full stack.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
HOOKS_DIR = REPO_ROOT / "src" / "aigate" / "hooks"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_hook(script_name: str, payload: dict, timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a hook script with JSON payload on stdin, return the result."""
    script = HOOKS_DIR / script_name
    assert script.exists(), f"Hook script not found: {script}"
    return subprocess.run(
        ["bash", str(script)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "PATH": os.environ["PATH"]},
    )


def run_mcp_jsonrpc(messages: list[dict], timeout: int = 10) -> list[dict]:
    """Send JSON-RPC messages to the MCP server via stdin, return parsed responses."""
    input_text = "\n".join(json.dumps(m) for m in messages) + "\n"
    result = subprocess.run(
        [sys.executable, "-m", "aigate.mcp_server"],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    responses = []
    for line in result.stdout.strip().splitlines():
        if line.strip():
            responses.append(json.loads(line))
    return responses


def mcp_initialize() -> list[dict]:
    """Return the JSON-RPC messages needed to initialize an MCP session."""
    return [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "e2e-test", "version": "1.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]


def parse_mcp_tool_result(responses: list[dict], call_id: int) -> dict:
    """Extract and parse the tool result from MCP responses."""
    call_resp = [r for r in responses if r.get("id") == call_id]
    assert len(call_resp) == 1, f"Expected 1 response for id={call_id}, got {len(call_resp)}"
    content = call_resp[0]["result"]["content"]
    result_text = content[0]["text"] if isinstance(content, list) else content
    return json.loads(result_text) if isinstance(result_text, str) else result_text


# ===========================================================================
# Hook E2E Tests
# ===========================================================================

class TestUserPromptSubmitHook:
    """Test scan_prompt.sh with real hook protocol payloads."""

    def test_allows_clean_prompt(self):
        result = run_hook("scan_prompt.sh", {
            "prompt": "Help me write a fibonacci function in Python",
            "session_id": "test-session-001",
        })
        assert result.returncode == 0

    def test_blocks_prompt_with_aws_key(self):
        result = run_hook("scan_prompt.sh", {
            "prompt": "My AWS key is AKIAIOSFODNN7EXAMPLE, please use it",
            "session_id": "test-session-002",
        })
        assert result.returncode == 2  # blocked
        assert "aigate" in result.stderr.lower() or "secret" in result.stderr.lower()

    def test_blocks_prompt_with_database_url(self):
        result = run_hook("scan_prompt.sh", {
            "prompt": "Connect to postgres://admin:s3cret@db.prod.com:5432/mydb",
            "session_id": "test-session-003",
        })
        assert result.returncode == 2

    def test_allows_empty_prompt(self):
        result = run_hook("scan_prompt.sh", {
            "prompt": "",
            "session_id": "test-session-004",
        })
        assert result.returncode == 0


class TestPreToolUseHook:
    """Test scan_tool.sh with real hook protocol payloads."""

    def test_allows_clean_tool_input(self):
        result = run_hook("scan_tool.sh", {
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/test.py", "content": "x = 1 + 2"},
            "session_id": "test-session-010",
        })
        assert result.returncode == 0

    def test_redacts_secret_in_tool_input(self):
        result = run_hook("scan_tool.sh", {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/tmp/config.py",
                "content": "api_key = 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901'"
            },
            "session_id": "test-session-011",
        })
        assert result.returncode == 0
        if result.stdout.strip():
            response = json.loads(result.stdout)
            hook_output = response.get("hookSpecificOutput", {})
            decision = hook_output.get("permissionDecision", "")
            assert decision in ("allow", "deny")
            if decision == "allow":
                updated = hook_output.get("updatedInput", {})
                content = json.dumps(updated)
                assert "sk-proj-" not in content or "REDACTED" in content

    def test_handles_empty_tool_input(self):
        result = run_hook("scan_tool.sh", {
            "tool_name": "Read",
            "tool_input": {},
            "session_id": "test-session-012",
        })
        assert result.returncode == 0


class TestPostToolUseHook:
    """Test scan_output.sh with real hook protocol payloads."""

    def test_ignores_non_write_tools(self):
        result = run_hook("scan_output.sh", {
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/something.py"},
            "tool_output": "file contents here",
            "session_id": "test-session-020",
        })
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_scans_written_file_with_secret(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("api_key = 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901'\n")
            f.flush()
            tmp_path = f.name

        try:
            result = run_hook("scan_output.sh", {
                "tool_name": "Write",
                "tool_input": {"file_path": tmp_path},
                "tool_output": "File written successfully",
                "session_id": "test-session-021",
            })
            assert result.returncode == 0
            assert "secret" in result.stdout.lower() or "aigate" in result.stdout.lower()
        finally:
            os.unlink(tmp_path)

    def test_no_feedback_for_clean_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("x = 1 + 2\nprint(x)\n")
            f.flush()
            tmp_path = f.name

        try:
            result = run_hook("scan_output.sh", {
                "tool_name": "Write",
                "tool_input": {"file_path": tmp_path},
                "tool_output": "File written successfully",
                "session_id": "test-session-022",
            })
            assert result.returncode == 0
            feedback = result.stdout.strip()
            assert feedback == "" or "secret" not in feedback.lower()
        finally:
            os.unlink(tmp_path)

    def test_handles_nonexistent_file(self):
        result = run_hook("scan_output.sh", {
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/nonexistent_e2e_test_file.py"},
            "tool_output": "File written successfully",
            "session_id": "test-session-023",
        })
        assert result.returncode == 0


# ===========================================================================
# MCP Server E2E Tests
# ===========================================================================

class TestMCPServerE2E:
    """Test the MCP server via actual JSON-RPC over stdio."""

    def test_initialize_handshake(self):
        responses = run_mcp_jsonrpc(mcp_initialize())
        assert len(responses) >= 1
        assert responses[0]["result"]["serverInfo"]["name"] == "aigate"

    def test_tools_list(self):
        messages = mcp_initialize() + [
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        responses = run_mcp_jsonrpc(messages)
        tools_resp = [r for r in responses if r.get("id") == 2]
        assert len(tools_resp) == 1
        tool_names = {t["name"] for t in tools_resp[0]["result"]["tools"]}
        assert tool_names == {"aigate_scan_code", "aigate_store_secret", "aigate_scan_file"}

    def test_scan_code_clean(self):
        messages = mcp_initialize() + [
            {
                "jsonrpc": "2.0", "id": 3,
                "method": "tools/call",
                "params": {"name": "aigate_scan_code", "arguments": {"code": "x = 1 + 2\nprint(x)"}},
            },
        ]
        result = parse_mcp_tool_result(run_mcp_jsonrpc(messages), 3)
        assert result["clean"] is True

    def test_scan_code_with_aws_key(self):
        messages = mcp_initialize() + [
            {
                "jsonrpc": "2.0", "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "aigate_scan_code",
                    "arguments": {
                        "code": "key = 'AKIAIOSFODNN7EXAMPLE'\nprint(key)",
                        "file_path": "config.py",
                    },
                },
            },
        ]
        result = parse_mcp_tool_result(run_mcp_jsonrpc(messages), 3)
        assert result["clean"] is False
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["env_var"] == "AWS_ACCESS_KEY_ID"

    def test_scan_code_with_js_file_path(self):
        messages = mcp_initialize() + [
            {
                "jsonrpc": "2.0", "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "aigate_scan_code",
                    "arguments": {
                        "code": "const key = 'AKIAIOSFODNN7EXAMPLE'",
                        "file_path": "config.js",
                    },
                },
            },
        ]
        result = parse_mcp_tool_result(run_mcp_jsonrpc(messages), 3)
        assert result["clean"] is False
        assert "process.env" in result["findings"][0]["suggestion"]

    def test_store_secret(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            tmp_env = f.name
        try:
            messages = mcp_initialize() + [
                {
                    "jsonrpc": "2.0", "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "aigate_store_secret",
                        "arguments": {"key": "TEST_API_KEY", "value": "test-secret-value-123", "file_path": tmp_env},
                    },
                },
            ]
            result = parse_mcp_tool_result(run_mcp_jsonrpc(messages), 3)
            assert result["stored"] is True
            assert "TEST_API_KEY=test-secret-value-123" in Path(tmp_env).read_text()
        finally:
            os.unlink(tmp_env)

    def test_store_secret_skips_duplicate(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("MY_KEY=existing_value\n")
            f.flush()
            tmp_env = f.name
        try:
            messages = mcp_initialize() + [
                {
                    "jsonrpc": "2.0", "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "aigate_store_secret",
                        "arguments": {"key": "MY_KEY", "value": "new_value", "file_path": tmp_env},
                    },
                },
            ]
            result = parse_mcp_tool_result(run_mcp_jsonrpc(messages), 3)
            assert result["stored"] is False
        finally:
            os.unlink(tmp_env)

    def test_scan_file_with_secret(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("aws_key = 'AKIAIOSFODNN7EXAMPLE'\n")
            f.flush()
            tmp_path = f.name
        try:
            messages = mcp_initialize() + [
                {
                    "jsonrpc": "2.0", "id": 3,
                    "method": "tools/call",
                    "params": {"name": "aigate_scan_file", "arguments": {"file_path": tmp_path}},
                },
            ]
            result = parse_mcp_tool_result(run_mcp_jsonrpc(messages), 3)
            assert result["clean"] is False
            assert result["file"] == tmp_path
        finally:
            os.unlink(tmp_path)

    def test_scan_file_not_found(self):
        messages = mcp_initialize() + [
            {
                "jsonrpc": "2.0", "id": 3,
                "method": "tools/call",
                "params": {"name": "aigate_scan_file", "arguments": {"file_path": "/nonexistent/file.py"}},
            },
        ]
        result = parse_mcp_tool_result(run_mcp_jsonrpc(messages), 3)
        assert "error" in result


# ===========================================================================
# scan-dir E2E Tests (CLI subprocess)
# ===========================================================================

class TestScanDirE2E:
    """Test scan-dir via actual CLI invocation."""

    def _run(self, *args, timeout=10):
        return subprocess.run(
            ["aigate", "scan-dir", *args],
            capture_output=True, text=True, timeout=timeout,
        )

    def test_detects_secrets(self, tmp_path):
        (tmp_path / "config.py").write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")
        (tmp_path / "clean.py").write_text("x = 1\n")
        r = self._run(str(tmp_path))
        assert r.returncode == 1
        assert "secret(s)" in r.stdout

    def test_json_output(self, tmp_path):
        (tmp_path / "app.py").write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")
        r = self._run(str(tmp_path), "-j")
        data = json.loads(r.stdout)
        assert data["clean"] is False
        assert data["files_with_secrets"] >= 1

    def test_clean_directory(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        r = self._run(str(tmp_path))
        assert r.returncode == 0
        assert "No secrets found" in r.stdout

    def test_fix_dry_run(self, tmp_path):
        original = "key = 'AKIAIOSFODNN7EXAMPLE'\n"
        (tmp_path / "app.py").write_text(original)
        r = self._run(str(tmp_path), "--fix", "--dry-run")
        assert r.returncode == 1
        assert (tmp_path / "app.py").read_text() == original
        assert "would" in r.stdout.lower()

    def test_fix_modifies_file(self, tmp_path):
        (tmp_path / "app.py").write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")
        self._run(str(tmp_path), "--fix")
        content = (tmp_path / "app.py").read_text()
        assert "AKIAIOSFODNN7EXAMPLE" not in content
        assert "REDACTED" in content

    def test_respects_gitignore(self, tmp_path):
        (tmp_path / ".gitignore").write_text("secret.txt\n")
        (tmp_path / "secret.txt").write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")
        (tmp_path / "clean.py").write_text("x = 1\n")
        r = self._run(str(tmp_path), "-j")
        data = json.loads(r.stdout)
        files = {f["file"] for f in data.get("findings", [])}
        assert "secret.txt" not in files

    def test_ignore_flag(self, tmp_path):
        (tmp_path / "config.py").write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")
        (tmp_path / "test.py").write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")
        r = self._run(str(tmp_path), "-j", "--ignore", "test.py")
        data = json.loads(r.stdout)
        files = {f["file"] for f in data["findings"]}
        assert "test.py" not in files
        assert "config.py" in files

    def test_skips_git_and_node_modules(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "pkg.js").write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")
        (tmp_path / "clean.py").write_text("x = 1\n")
        r = self._run(str(tmp_path))
        assert r.returncode == 0


# ===========================================================================
# Full Pipeline E2E
# ===========================================================================

class TestFullPipelineE2E:
    """Chain multiple features together to test realistic agent workflows."""

    def test_scan_find_then_store_then_verify(self, tmp_path):
        """Agent scans code -> finds secret -> stores to .env -> rescans clean."""
        # 1. Scan code with a secret
        messages = mcp_initialize() + [
            {
                "jsonrpc": "2.0", "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "aigate_scan_code",
                    "arguments": {"code": "key = 'AKIAIOSFODNN7EXAMPLE'\nprint(key)", "file_path": "app.py"},
                },
            },
        ]
        scan_result = parse_mcp_tool_result(run_mcp_jsonrpc(messages), 3)
        assert scan_result["clean"] is False
        env_var = scan_result["findings"][0]["env_var"]

        # 2. Store the secret
        env_file = tmp_path / ".env"
        messages2 = mcp_initialize() + [
            {
                "jsonrpc": "2.0", "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "aigate_store_secret",
                    "arguments": {"key": env_var, "value": "AKIAIOSFODNN7EXAMPLE", "file_path": str(env_file)},
                },
            },
        ]
        store_result = parse_mcp_tool_result(run_mcp_jsonrpc(messages2), 4)
        assert store_result["stored"] is True
        assert env_file.exists()

        # 3. Fixed code scans clean
        fixed = f"import os\nkey = os.environ['{env_var}']\nprint(key)\n"
        messages3 = mcp_initialize() + [
            {
                "jsonrpc": "2.0", "id": 5,
                "method": "tools/call",
                "params": {"name": "aigate_scan_code", "arguments": {"code": fixed}},
            },
        ]
        clean_result = parse_mcp_tool_result(run_mcp_jsonrpc(messages3), 5)
        assert clean_result["clean"] is True

    def test_scan_dir_find_then_mcp_store(self, tmp_path):
        """scan-dir finds secrets -> agent uses MCP to store them."""
        (tmp_path / "config.py").write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")

        # scan-dir finds it
        r = subprocess.run(
            ["aigate", "scan-dir", str(tmp_path), "-j"],
            capture_output=True, text=True, timeout=10,
        )
        data = json.loads(r.stdout)
        assert data["clean"] is False

        # Store via MCP
        env_file = tmp_path / ".env"
        messages = mcp_initialize() + [
            {
                "jsonrpc": "2.0", "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "aigate_store_secret",
                    "arguments": {"key": "AWS_ACCESS_KEY_ID", "value": "AKIAIOSFODNN7EXAMPLE", "file_path": str(env_file)},
                },
            },
        ]
        store_result = parse_mcp_tool_result(run_mcp_jsonrpc(messages), 3)
        assert store_result["stored"] is True
        assert "AKIAIOSFODNN7EXAMPLE" in env_file.read_text()

    def test_hook_then_mcp_flow(self):
        """PostToolUse hook detects -> agent uses MCP scan_file to confirm."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("key = 'AKIAIOSFODNN7EXAMPLE'\n")
            f.flush()
            tmp_path = f.name

        try:
            # Hook detects
            hook_result = run_hook("scan_output.sh", {
                "tool_name": "Write",
                "tool_input": {"file_path": tmp_path},
                "tool_output": "File written",
                "session_id": "test-pipeline",
            })
            assert "secret" in hook_result.stdout.lower()

            # Agent confirms via MCP scan_file
            messages = mcp_initialize() + [
                {
                    "jsonrpc": "2.0", "id": 3,
                    "method": "tools/call",
                    "params": {"name": "aigate_scan_file", "arguments": {"file_path": tmp_path}},
                },
            ]
            scan_result = parse_mcp_tool_result(run_mcp_jsonrpc(messages), 3)
            assert scan_result["clean"] is False
            assert scan_result["file"] == tmp_path
        finally:
            os.unlink(tmp_path)
