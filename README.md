# aigate

Local secret scanner that intercepts AI API calls and prevents credentials from leaking to LLMs.

## Install

```bash
git clone https://github.com/jricramc/aigate.git
cd aigate
pip install -e .
```

Requires Python 3.11+ and `jq`.

## Quick start

### Claude Code (hooks — no proxy needed)

```bash
aigate install-hook
```

All prompts and tool calls are scanned automatically. Secrets are blocked before Claude sees them.

### Any AI tool (proxy mode)

```bash
aigate setup                                    # one-time: installs CA cert (needs sudo)
aigate start --mode redact                      # start the proxy
export HTTPS_PROXY=http://127.0.0.1:8080        # in another terminal
```

All AI API traffic is now scanned and redacted transparently. No code changes needed.

`aigate setup` installs the mitmproxy CA certificate into your system trust store and configures `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, and `REQUESTS_CA_BUNDLE` in your shell profile so Node.js (Claude Code), Python (httpx, requests), and curl all trust the proxy automatically.

### Scan a file directly

```bash
aigate scan .env
cat prompt.txt | aigate scan -
```

## Modes

```bash
aigate start --mode block    # reject requests containing secrets (default)
aigate start --mode redact   # replace secrets with env var placeholders
aigate start --mode warn     # forward but log a warning
aigate start --mode audit    # forward silently, log only
```

### Redact mode

Instead of blocking, redact mode rewrites the request before it reaches the AI:

1. Detects secrets in your prompt (AWS keys, API tokens, database URLs, private keys, etc.)
2. Replaces them with placeholders like `[REDACTED_ANTHROPIC_API_KEY]`
3. Saves the real credentials to a local `.env` file
4. Injects a system instruction telling the AI to use `os.environ[]` and load from `.env`
5. Forwards the sanitized request — the AI never sees the real credentials

The AI acknowledges the redaction, then writes secure code using environment variables automatically. Token prefixes are mapped to conventional env var names:

| Token | Env var |
|-------|---------|
| `sk-ant-*` | `ANTHROPIC_API_KEY` |
| `sk-*`, `sk-proj-*` | `OPENAI_API_KEY` |
| `ghp_*`, `github_pat_*` | `GITHUB_TOKEN` |
| `glpat-*` | `GITLAB_TOKEN` |
| `xoxb-*` | `SLACK_BOT_TOKEN` |
| `SG.*` | `SENDGRID_API_KEY` |
| `AKIA*` | `AWS_ACCESS_KEY_ID` |

## Detection rules

- **AWS keys** — `AKIA` access key IDs
- **API tokens** — OpenAI, Anthropic, GitHub, GitLab, Slack, SendGrid, Square
- **Database URLs** — postgres, mysql, mongodb, redis, amqp, mssql with credentials
- **Private keys** — RSA, EC, DSA, OPENSSH, PGP
- **Environment files** — `SECRET_KEY=value`, `DATABASE_URL=value`, etc.
- **GCP service accounts** — JSON with `type: service_account` and `private_key`
- **Tailscale keys** — `tskey-auth-*`, `tskey-api-*`
- **High-entropy secrets** — password/token/secret fields with entropy > 3.5 bits

## Logs

```bash
aigate logs          # last 20 entries
aigate logs -n 50    # last 50 entries
aigate logs -f       # live tail
```

Log file: `~/.aigate/scan.log`

## Docker

```bash
docker build -t aigate .
docker run --rm --entrypoint bash -it aigate
# inside the container, everything is pre-configured:
aigate start --mode redact &
curl -x http://127.0.0.1:8080 ...
```

## Uninstall

```bash
aigate uninstall-hook   # remove Claude Code hooks
```
