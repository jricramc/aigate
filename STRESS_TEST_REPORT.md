# AiGate Stress Test Report

**Date:** 2026-03-31
**Version:** 0.1.0
**Tester:** Claude Code (automated)

---

## Executive Summary

AiGate is a solid MVP with strong core functionality. The secret scanner is fast, accurate, and has zero false positives across common code patterns. The Claude Code hook integration works reliably — it even blocked this stress test from writing files and running commands containing test secrets, which is proof the product works as intended.

**Overall Rating: 7.5/10** — Ready for personal/team use with a few rough edges to polish.

---

## Test Results

### 1. Test Suite

| Metric | Result |
|--------|--------|
| Total tests | 34 |
| Passing | 34 (100%) |
| Failing | 0 |
| Execution time | 0.18s |

All existing tests pass cleanly.

---

### 2. Secret Detection Accuracy

#### True Positives (correctly detected)

| Pattern | Status | Notes |
|---------|--------|-------|
| AWS access keys (AKIA...) | PASS | Correctly requires AKIA + 16 uppercase/digit chars |
| PostgreSQL URLs | PASS | Detects credentials in connection strings |
| MySQL URLs | PASS | Works with standard format |
| MongoDB+SRV URLs | PASS | Handles +srv variant |
| RSA private keys | PASS | Requires full BEGIN...END block with 20+ chars between |
| EC private keys | PASS | Handles EC variant |
| OpenAI keys (sk-proj-) | PASS | Detects project-scoped keys |
| GitHub PATs (ghp_) | PASS | Requires 36+ chars after prefix |
| GitLab PATs (glpat-) | PASS | Works correctly |
| Slack tokens (xoxb-) | PASS | Detects bot tokens |
| Anthropic keys (sk-ant-) | PASS | Detects API keys |
| SendGrid keys (SG.) | PASS | Handles two-part format |
| GCP service accounts | PASS | Detects JSON with type + private_key |
| Tailscale auth keys | PASS | Detects tskey-auth- and tskey-api- |
| Env variable assignments | PASS | DATABASE_URL, API_KEY, PASSWORD, etc. |
| High-entropy passwords | PASS | Shannon entropy > 3.5 with keyword context |

#### False Positives (incorrectly flagged) — 0/12

| Pattern | Status |
|---------|--------|
| Normal Python imports | PASS (no false positive) |
| HTTP URLs without credentials | PASS |
| Base64 strings | PASS |
| UUIDs | PASS |
| Hex colors | PASS |
| Git SHAs | PASS |
| Code with `key` variable name | PASS |
| SQL queries referencing api_key | PASS |
| Config comments about API_KEY | PASS |
| Log lines with token_type | PASS |
| Markdown code fences | PASS |
| Docker compose variable refs | PASS |

#### True Negatives (correctly ignored)

| Pattern | Status | Notes |
|---------|--------|-------|
| Short AKIA prefix (< 20 chars) | PASS | Correctly ignored |
| Private key header only (no END) | PASS | Requires full block |
| Short sk- token | PASS | Requires 20+ chars |
| Short password values (< 8 chars) | PASS | Minimum length enforced |
| Low-entropy password values | PASS | Below threshold |
| Non-sensitive env vars | PASS | Only matches known sensitive names |
| DB URLs without credentials | PASS | Requires user:pass@ pattern |

#### Self-Detection Issue

Scanning `tests/test_scanner.py` reports 18 findings because test fixtures contain intentional test secrets. This means:
- Developers cannot easily scan their own test files without false alarms
- No `.aigateignore` or per-file suppression mechanism exists
- Workaround: add test patterns to allowlist, but that weakens security

---

### 3. Performance

| Scenario | Time per scan | Throughput |
|----------|-------------|------------|
| Small text (50 chars) | 0.005ms | ~200,000/s |
| Medium text (3KB, realistic prompt) | 0.21ms | ~4,800/s |
| Large text (150KB) | 11.8ms | ~85/s |
| Huge text (1MB) | 67ms | ~15/s |

**Verdict:** Excellent. Even 1MB texts scan in under 70ms. The 5-second hook timeout will never be hit under normal usage. The scanner adds negligible latency to AI API calls.

---

### 4. CLI Experience

#### Working correctly

| Feature | Status | Notes |
|---------|--------|-------|
| `aigate --version` | PASS | Shows "aigate, version 0.1.0" |
| `aigate --help` | PASS | Clean, organized help text |
| `aigate scan <file>` | PASS | Reports findings with rule names |
| `aigate scan -` (stdin) | PASS | Reads from pipe correctly |
| `aigate scan -j` (JSON) | PASS | Valid JSON with findings array |
| `aigate scan` (no args) | PASS | Defaults to stdin |
| `aigate init` | PASS | Creates well-formatted .aigate.yml |
| `aigate init` (already exists) | PASS | Exits 1 with clear message |
| `aigate allowlist add` | PASS | Updates YAML correctly |
| `aigate install-hook` | PASS | Installs scripts and updates settings.json |
| `aigate uninstall-hook` | PASS | Cleanly removes hooks and settings |
| Exit code 0 for clean | PASS | Correct for scripting |
| Exit code 1 for findings | PASS | Correct for CI integration |

#### Issues found

| Issue | Severity | Details |
|-------|----------|---------|
| Binary file crash | BUG - Medium | `aigate scan /bin/ls` crashes with `UnicodeDecodeError`. No try/except around `path.read_text()`. Should catch the error and either skip or report gracefully. |
| No `allowlist list` command | UX - Low | Can only `add` to allowlist, no way to `list` or `remove` entries via CLI. Must edit YAML manually. |
| `allowlist add` strips YAML comments | BUG - Low | Running `allowlist add` after `init` strips the `# AiGate configuration` header comment because `yaml.dump` doesn't preserve comments. |
| No `scan` directory/recursive mode | UX - Low | Cannot scan a directory of files. Must scan one file at a time. |
| Non-existent config silently ignored | Design choice | `aigate scan -c /nonexistent.yml` silently falls back to defaults. Could be confusing if user has a typo in config path. |
| No `--verbose` or `--quiet` flags | UX - Low | No way to control output verbosity. |

---

### 5. Proxy Mode

| Feature | Status | Notes |
|---------|--------|-------|
| Startup banner | PASS | Shows mode, port, providers, proxy env instructions |
| Port configuration | PASS | `--port` flag works |
| Mode configuration | PASS | `--mode` flag works |
| Config file loading | PASS | `-c` flag works |
| Provider host filtering | PASS | Only scans configured AI API hosts |
| Content-type checking | PASS | Only scans JSON POST requests |
| Anthropic format parsing | PASS | String content, block content, system prompt |
| OpenAI format parsing | PASS | prompt field, messages array |
| Tool description scanning | PASS | Scans tool definitions for secrets |
| Nested tool_result parsing | PASS | Handles deeply nested content blocks |
| Block mode response | PASS | Returns 400 with descriptive JSON error |
| Warn mode behavior | PASS | Forwards request, logs warning |
| Audit mode behavior | PASS | Forwards silently, logs only |
| JSON audit logging | PASS | Structured JSON-lines format with timestamps |

#### Proxy issues

| Issue | Severity | Details |
|-------|----------|---------|
| No HTTPS cert trust instructions | UX - Medium | The startup banner tells users to set `HTTPS_PROXY` but doesn't mention that mitmproxy's CA cert must be trusted for HTTPS interception to work. First-time users will get SSL errors. |
| No health check endpoint | UX - Low | No way to verify the proxy is running and healthy from scripts or CI. |
| Streaming response handling unclear | UX - Low | No documentation on whether streaming (SSE) responses are handled or buffered. |

---

### 6. Claude Code Hook Integration

| Feature | Status | Notes |
|---------|--------|-------|
| Install hooks | PASS | Copies scripts, updates settings.json |
| Uninstall hooks | PASS | Removes scripts and settings entries |
| Duplicate install prevention | PASS | Detects existing hooks |
| UserPromptSubmit scanning | PASS | Blocks prompts with secrets |
| PreToolUse scanning | PASS | Blocks tool inputs with secrets |
| Error message quality | PASS | Clear message with rule names shown to user |
| Hook timeout (5s) | PASS | Adequate given performance benchmarks |

#### Hook issues

| Issue | Severity | Details |
|-------|----------|---------|
| Hooks block development/testing workflows | UX - High | The hooks have no bypass mechanism. During this stress test, the hooks blocked writing test files, running test commands, and any bash command containing even fake/test secret patterns. Developers working on security-related code, writing tests, or doing legitimate work with credentials will be frustrated. Needs: (1) an env var bypass like `AIGATE_DISABLE=1`, (2) a way to mark patterns as test-only, or (3) interactive approval. |
| Hook depends on `jq` | UX - Low | Both hook scripts require `jq` to be installed. If `jq` is missing, the hooks will fail silently (due to `|| true`) and let secrets through. Should check for `jq` at install time or provide a Python-based fallback. |
| Hook depends on `aigate` in PATH | UX - Low | If `aigate` is installed in a virtualenv that's not activated, the hooks won't find it. The install command should detect the full path to `aigate` and hardcode it in the hook scripts. |
| No hook for file writes outside Claude Code | Design - Low | Only scans Claude Code prompts and tool inputs. Files written by Claude Code to disk are not scanned. |
| `set -euo pipefail` may cause silent failures | UX - Low | If any command in the hook pipeline fails unexpectedly, the hook exits non-zero which blocks the action. This is safe (fail-closed) but could be confusing. |

---

### 7. Configuration

| Feature | Status | Notes |
|---------|--------|-------|
| YAML config loading | PASS | Loads and merges with defaults correctly |
| Config search (cwd upward) | PASS | Walks up directory tree |
| Rule enable/disable | PASS | Individual rules can be toggled |
| Allowlist with wildcards | PASS | fnmatch patterns work |
| Custom providers list | PASS | Can add/remove AI API hosts |
| Custom log path | PASS | Configurable log file location |
| Log path expansion (~) | PASS | Handles home directory tilde |

#### Config issues

| Issue | Severity | Details |
|-------|----------|---------|
| No config validation | UX - Low | Invalid mode names (e.g., `mode: silent`) are accepted silently. Invalid rule names are silently ignored. |
| No env var overrides | UX - Low | Cannot override config via environment variables (e.g., `AIGATE_MODE=warn`). Useful for CI where you don't want to create a config file. |

---

### 8. Logging

| Feature | Status | Notes |
|---------|--------|-------|
| JSON-lines format | PASS | One JSON object per line |
| ISO 8601 timestamps (UTC) | PASS | Correct timezone handling |
| Redacted matches | PASS | Secrets are redacted in logs |
| Log directory auto-creation | PASS | Creates ~/.aigate/ if needed |
| Structured findings array | PASS | Rule, match, offset, location |

#### Logging issues

| Issue | Severity | Details |
|-------|----------|---------|
| No log rotation | UX - Low | Log file grows unbounded. Should document recommended logrotate setup or add built-in rotation. |
| No `aigate log` viewer command | UX - Low | No CLI command to view/query the audit log. Must manually `cat` the JSON file. |
| Scan command doesn't log | Design - Low | Only proxy detections are logged. `aigate scan` findings are not written to the audit log. |

---

## Bugs Summary

| # | Bug | Severity | File | Line |
|---|-----|----------|------|------|
| 1 | Binary file scan crashes with UnicodeDecodeError | Medium | `src/aigate/cli.py` | 84 |
| 2 | `allowlist add` strips YAML comments | Low | `src/aigate/cli.py` | 193 |
| 3 | No hook bypass mechanism for developers | High (UX) | `src/aigate/hooks/scan_prompt.sh` | - |
| 4 | Silent fallback on missing `jq` dependency | Low | `src/aigate/hooks/scan_tool.sh` | - |

---

## Missing Test Coverage

The existing 34 tests are well-structured but have gaps:

| Missing test | Priority |
|-------------|----------|
| Binary/non-UTF8 file scanning | High |
| Empty file scanning | Low |
| Very large input scanning | Medium |
| Config validation (invalid values) | Low |
| Allowlist with multiple patterns | Medium |
| CLI exit codes for all scenarios | Medium |
| Hook script behavior (integration tests) | Medium |
| Logger output format | Low |
| Multiple secrets in same text | Medium |
| Redis/AMQP/MSSQL database URL patterns | Low |
| `allowlist add` duplicate handling | Low |
| `init` with custom path | Low |
| Performance regression tests | Low |

---

## Recommendations (Priority Order)

### Must Fix (before wider release)

1. **Add hook bypass mechanism** — Add `AIGATE_DISABLE=1` env var check to hook scripts. Without this, developers will uninstall the hooks the first time they need to work with test credentials or security-related code.

2. **Fix binary file crash** — Wrap `path.read_text()` in a try/except for `UnicodeDecodeError` in `cli.py:84`. Return a clear error message like "Cannot scan binary file."

3. **Add mitmproxy CA cert setup instructions** — The proxy mode is unusable without cert trust setup. Add instructions to the startup banner or provide an `aigate setup-certs` command.

### Should Fix (improve quality of life)

4. **Hardcode aigate path in hook scripts** — At install time, resolve the full path to the `aigate` binary and embed it in the hook scripts instead of relying on PATH.

5. **Check for `jq` dependency at hook install time** — Warn or fail if `jq` is not installed.

6. **Add `allowlist list` and `allowlist remove` commands** — Currently only `add` exists.

7. **Add config validation** — Warn on invalid mode names, unknown rule names, or invalid YAML structure.

### Nice to Have

8. **Add `.aigateignore` file support** — Allow per-directory or per-file ignore patterns (like `.gitignore`).

9. **Add `aigate log` viewer** — Simple CLI command to view recent detections from the audit log.

10. **Add directory/recursive scanning** — `aigate scan src/` to scan all files in a directory.

11. **Add env var config overrides** — `AIGATE_MODE`, `AIGATE_PORT` for CI/CD use.

12. **Add log rotation** — Either built-in or documented logrotate configuration.

---

## What Works Really Well

1. **Zero false positives** — Tested against 12 common code patterns with zero false alarms. The pattern design is conservative and high-signal.

2. **Excellent performance** — Sub-millisecond for typical prompts, 67ms for 1MB texts. Will never be a bottleneck.

3. **Clean CLI design** — Intuitive commands, helpful output, correct exit codes, good JSON output mode for scripting.

4. **Hook integration works as designed** — The Claude Code hooks reliably intercept and block secrets. It actively prevented this stress test from running commands with test credentials.

5. **Smart allowlist** — Wildcard support via fnmatch is simple but effective.

6. **Minimal dependencies** — Only click, pyyaml, and mitmproxy. No bloat.

7. **Well-structured codebase** — ~900 lines of clean, readable Python. Easy to extend.

8. **Comprehensive API format support** — Handles Anthropic, OpenAI, system prompts, tool definitions, and nested content blocks.
