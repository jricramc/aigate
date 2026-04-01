# AiGate

Local secret scanner that blocks credentials before they reach AI APIs.

## Install

```bash
git clone https://github.com/jricramc/aigate.git
cd aigate
pip install -e .
```

Requires Python 3.11+ and `jq`.

## Usage

### Claude Code

```bash
aigate install-hook
```

Done. All prompts and tool calls are scanned automatically.

### Any AI tool (Cursor, API scripts, etc.)

```bash
sudo aigate setup    # one-time: installs CA cert for HTTPS interception
aigate start         # start the proxy
```

Then in your shell (or add to `~/.bashrc`):

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
```

All AI API traffic is now scanned transparently. No code changes needed.

### Scan a file directly

```bash
aigate scan .env
cat prompt.txt | aigate scan -
```

## Modes

```bash
aigate start --mode block    # Block requests containing secrets (default)
aigate start --mode redact   # Replace secrets with env var placeholders
aigate start --mode warn     # Forward but log a warning
aigate start --mode audit    # Forward silently, log only
```

### Redact mode

Instead of blocking, redact mode rewrites the request before it reaches the AI:

1. Detects secrets in your prompt
2. Replaces them with placeholders like `[REDACTED_AWS_ACCESS_KEY_ID]`
3. Injects a system instruction telling the AI to use `os.environ[]` instead
4. Saves the real secret to your local `.env` file
5. Forwards the sanitized request — the AI never sees the real credential

The AI writes code using environment variables automatically.

## Logs

```bash
aigate logs          # last 20 entries
aigate logs -n 50    # last 50 entries
aigate logs -f       # live tail
```

Log file: `~/.aigate/scan.log`

## Uninstall

```bash
aigate uninstall-hook   # remove Claude Code hooks
```
