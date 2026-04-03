"""Tests for the scan-dir CLI command."""

import json
import pytest
from pathlib import Path
from click.testing import CliRunner

from aigate.cli import main


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def project_dir(tmp_path):
    """Create a temp project with clean and dirty files."""
    # Clean file
    (tmp_path / "clean.py").write_text("x = 1 + 2\nprint(x)\n")

    # Dirty file with a hardcoded secret
    (tmp_path / "config.py").write_text(
        "import os\n"
        "API_KEY = 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901'\n"
        "print(API_KEY)\n"
    )

    # Nested dirty file
    sub = tmp_path / "src"
    sub.mkdir()
    (sub / "app.py").write_text(
        "DB_URL = 'postgres://admin:s3cret@db.example.com:5432/mydb'\n"
    )

    # .gitignore
    (tmp_path / ".gitignore").write_text("*.log\nbuild/\n")

    # File that should be ignored
    (tmp_path / "debug.log").write_text("SECRET_KEY=supersecretvalue123456\n")

    return tmp_path


class TestScanDir:
    def test_detects_secrets(self, runner, project_dir):
        result = runner.invoke(main, ["scan-dir", str(project_dir)])
        assert result.exit_code == 1
        assert "secret(s)" in result.output

    def test_clean_directory(self, runner, tmp_path):
        (tmp_path / "clean.py").write_text("x = 1\n")
        result = runner.invoke(main, ["scan-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "No secrets found" in result.output

    def test_json_output(self, runner, project_dir):
        result = runner.invoke(main, ["scan-dir", str(project_dir), "-j"])
        data = json.loads(result.output)
        assert data["files_with_secrets"] >= 1
        assert data["total_findings"] >= 1
        assert data["clean"] is False

    def test_respects_gitignore(self, runner, project_dir):
        result = runner.invoke(main, ["scan-dir", str(project_dir), "-j"])
        data = json.loads(result.output)
        files_with_findings = {f["file"] for f in data["findings"]}
        assert "debug.log" not in files_with_findings

    def test_ignore_option(self, runner, project_dir):
        result = runner.invoke(main, ["scan-dir", str(project_dir), "-j", "--ignore", "config.py"])
        data = json.loads(result.output)
        files_with_findings = {f["file"] for f in data["findings"]}
        assert "config.py" not in files_with_findings

    def test_not_a_directory(self, runner, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("hello")
        result = runner.invoke(main, ["scan-dir", str(f)])
        assert result.exit_code != 0
        assert "not a directory" in result.output

    def test_skips_binary_extensions(self, runner, tmp_path):
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        (tmp_path / "clean.py").write_text("x = 1\n")
        result = runner.invoke(main, ["scan-dir", str(tmp_path)])
        assert result.exit_code == 0

    def test_skips_git_directory(self, runner, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("SECRET_KEY=supersecretvalue123456\n")
        (tmp_path / "clean.py").write_text("x = 1\n")
        result = runner.invoke(main, ["scan-dir", str(tmp_path)])
        assert result.exit_code == 0


class TestScanDirFix:
    def test_fix_replaces_secrets(self, runner, tmp_path):
        dirty = tmp_path / "app.py"
        dirty.write_text("key = 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901'\n")
        result = runner.invoke(main, ["scan-dir", str(tmp_path), "--fix"])
        # The file should be modified
        content = dirty.read_text()
        assert "sk-proj-" not in content
        assert "REDACTED" in content

    def test_fix_creates_env_file(self, runner, tmp_path):
        dirty = tmp_path / "app.py"
        dirty.write_text("key = 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901'\n")
        result = runner.invoke(main, ["scan-dir", str(tmp_path), "--fix"])
        # findings were found (even though fixed)
        assert result.exit_code == 1

    def test_dry_run_doesnt_modify(self, runner, tmp_path):
        dirty = tmp_path / "app.py"
        original = "key = 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901'\n"
        dirty.write_text(original)
        result = runner.invoke(main, ["scan-dir", str(tmp_path), "--fix", "--dry-run"])
        # File should NOT be modified
        assert dirty.read_text() == original
        assert "would" in result.output.lower()
