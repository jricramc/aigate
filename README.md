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

### Claude Code (recommended)

```bash
aigate install-hook
```

Done. All prompts and tool calls are scanned automatically.

### Other AI tools (Cursor, API scripts, etc.)

```bash
aigate start
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

### Scan a file directly

```bash
aigate scan .env
cat prompt.txt | aigate scan -
```

## Logs

```bash
aigate logs          # last 20 entries
aigate logs -n 50    # last 50 entries
aigate logs -f       # live tail
```

Log file: `~/.aigate/scan.log`

## Uninstall hooks

```bash
aigate uninstall-hook
```
