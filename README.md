# aigate

Secret hygiene for AI-generated code. Catches hardcoded credentials before they leak — in prompts, tool inputs, generated code, and existing files.

## Install

```bash
pip install aigate
```

Requires Python 3.11+ and `jq` (for hooks).

## Quick start

### One command (recommended)

```bash
pip install aigate && aigate setup-all
```

This sets up everything:
- HTTPS proxy (redact mode) running in the background
- PostToolUse hook that scans files after Write/Edit
- MCP server registered with Claude Code (3 tools for agents)
- CA cert installed and env vars added to shell profile

Restart Claude Code (or open a new terminal) for env vars to take effect.

### Hooks only (no proxy)

```bash
aigate install-hook
```

Installs all three hooks:
- **UserPromptSubmit** — blocks prompts containing secrets
- **PreToolUse** — redacts secrets in tool inputs, saves to `.env`
- **PostToolUse** — scans files after Write/Edit, alerts the agent to fix

### MCP server

Register with Claude Code:

```bash
claude mcp add aigate aigate-mcp
```

Exposes three tools to any MCP-compatible agent:
- **`aigate_scan_code`** — scan code for secrets before writing it
- **`aigate_store_secret`** — save a credential to `.env` instead of hardcoding it
- **`aigate_scan_file`** — scan an existing file for hardcoded secrets

The server includes instructions that tell the agent to use these tools proactively.

### Proxy only

```bash
aigate setup       # one-time: install CA cert (needs sudo)
aigate start -m redact
```

Set env vars in your AI tool's terminal:
```bash
source ~/.bashrc
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
```

### Scan files directly

```bash
aigate scan .env                          # scan a file
aigate scan .env --redact                 # redact and save to .env
aigate scan-dir .                         # scan a directory recursively
aigate scan-dir . --fix --dry-run         # preview auto-remediation
aigate scan-dir . --fix                   # replace secrets with env var refs
aigate scan-dir . --ignore "test/**"      # skip patterns
```

## How the layers work together

```
                    +-------------------+
                    |   scanner.py      |
                    |   (detection)     |
                    |   redactor.py     |
                    |   (remediation)   |
                    +--------+----------+
                             |
              +--------------+--------------+
              |              |              |
     +--------+---+  +------+------+  +----+-------+
     |   Proxy    |  |   Hooks     |  | MCP Server |
     | (network)  |  | (Claude CC) |  | (any agent)|
     +------------+  +-------------+  +------------+
```

- **Proxy** — intercepts HTTPS requests to AI APIs. Redacts secrets at the network level. Can't be bypassed.
- **Hooks** — Claude Code specific. PostToolUse scans written files. PreToolUse redacts tool inputs.
- **MCP server** — agent-initiated. The agent calls tools to scan its own code and store secrets properly.

With `setup-all`, the proxy handles prompt/tool input scanning (redact mode), and the PostToolUse hook catches secrets in generated files. The MCP server gives agents proactive scanning tools.

## Proxy modes

```bash
aigate start --mode block    # reject requests containing secrets (default)
aigate start --mode redact   # replace secrets with env var placeholders
aigate start --mode warn     # forward but log a warning
aigate start --mode audit    # forward silently, log only
```

## Detection rules

- **AWS keys** — `AKIA` access key IDs
- **API tokens** — OpenAI, Anthropic, GitHub, GitLab, Slack, SendGrid, Square
- **Database URLs** — postgres, mysql, mongodb, redis, amqp, mssql with credentials
- **Private keys** — RSA, EC, DSA, OPENSSH, PGP
- **Environment files** — `SECRET_KEY=value`, `DATABASE_URL=value`, etc.
- **GCP service accounts** — JSON with `type: service_account` and `private_key`
- **Tailscale keys** — `tskey-auth-*`, `tskey-api-*`
- **High-entropy secrets** — password/token/secret fields with entropy > 3.5 bits

## Env var mapping

| Token | Env var |
|-------|---------|
| `sk-ant-*` | `ANTHROPIC_API_KEY` |
| `sk-*`, `sk-proj-*` | `OPENAI_API_KEY` |
| `ghp_*`, `github_pat_*` | `GITHUB_TOKEN` |
| `glpat-*` | `GITLAB_TOKEN` |
| `xoxb-*` | `SLACK_BOT_TOKEN` |
| `SG.*` | `SENDGRID_API_KEY` |
| `AKIA*` | `AWS_ACCESS_KEY_ID` |

## Logs

```bash
aigate logs          # last 20 entries
aigate logs -n 50    # last 50
aigate logs -f       # live tail
```

Log file: `~/.aigate/scan.log`

## Uninstall

```bash
aigate stop-proxy                   # stop background proxy
aigate uninstall-hook               # remove hooks
claude mcp remove aigate            # remove MCP server
pip uninstall aigate                # remove package
rm -rf ~/.aigate ~/.mitmproxy       # remove logs and certs
```

Remove env vars from `~/.bashrc` or `~/.zshrc` — delete lines after `# aigate: proxy env vars` and `# aigate: trust mitmproxy CA`.

To remove the CA cert from the system trust store:

**macOS:**
```bash
sudo security delete-certificate -c mitmproxy /Library/Keychains/System.keychain
```

**Linux (Debian/Ubuntu):**
```bash
sudo rm /usr/local/share/ca-certificates/mitmproxy-aigate.crt && sudo update-ca-certificates --fresh
```

**Linux (RHEL/Fedora):**
```bash
sudo rm /etc/pki/ca-trust/source/anchors/mitmproxy-aigate.pem && sudo update-ca-trust
```
