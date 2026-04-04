# aigate

Secret hygiene for AI-generated code. Catches hardcoded credentials in prompts, tool inputs, generated code, and existing files.

## Quick start

```bash
pip install aigate && aigate setup-all
```

That's it. This installs a background proxy (redact mode), a PostToolUse hook for file scanning, and registers the MCP server with Claude Code. Restart your terminal for env vars to take effect.

Requires Python 3.11+ and `jq`.

## What it does

Three layers, one detection engine:

| Layer | Scope | How |
|-------|-------|-----|
| **Proxy** | Network-level | Intercepts HTTPS requests to AI APIs. Redacts secrets before they leave your machine. |
| **Hooks** | Claude Code | PostToolUse scans files after Write/Edit. PreToolUse redacts tool inputs. |
| **MCP Server** | Any agent | Three tools agents call to scan code, store secrets, and audit files. |

`setup-all` installs all three. Or pick what you need:

```bash
aigate install-hook              # hooks only (no proxy)
claude mcp add aigate aigate-mcp # MCP server only
aigate setup && aigate start     # proxy only
```

## Scan existing code

```bash
aigate scan-dir .                # find secrets in a directory
aigate scan-dir . --fix --dry-run # preview what would change
aigate scan-dir . --fix          # replace with env var refs, save to .env
```

## Detection

AWS keys, API tokens (OpenAI, Anthropic, GitHub, GitLab, Slack, SendGrid, Square), database URLs, private keys, GCP service accounts, Tailscale keys, env file secrets, and high-entropy password/token fields.

Detected secrets are mapped to conventional env var names:

| Token | Env var |
|-------|---------|
| `sk-ant-*` | `ANTHROPIC_API_KEY` |
| `sk-*`, `sk-proj-*` | `OPENAI_API_KEY` |
| `ghp_*`, `github_pat_*` | `GITHUB_TOKEN` |
| `glpat-*` | `GITLAB_TOKEN` |
| `xoxb-*` | `SLACK_BOT_TOKEN` |
| `SG.*` | `SENDGRID_API_KEY` |
| `AKIA*` | `AWS_ACCESS_KEY_ID` |

## Proxy modes

```bash
aigate start -m block    # reject requests (default)
aigate start -m redact   # replace secrets with env var placeholders
aigate start -m warn     # forward + log warning
aigate start -m audit    # forward + silent log
```

## Uninstall

```bash
aigate stop-proxy && aigate uninstall-hook && claude mcp remove aigate
pip uninstall aigate && rm -rf ~/.aigate ~/.mitmproxy
```

Remove the lines after `# aigate: proxy env vars` and `# aigate: trust mitmproxy CA` from your shell profile.

CA cert removal — macOS: `sudo security delete-certificate -c mitmproxy /Library/Keychains/System.keychain` | Debian: `sudo rm /usr/local/share/ca-certificates/mitmproxy-aigate.crt && sudo update-ca-certificates --fresh` | RHEL: `sudo rm /etc/pki/ca-trust/source/anchors/mitmproxy-aigate.pem && sudo update-ca-trust`
