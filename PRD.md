# PRD: AiGate — AI Prompt Secret Scanner

## Context

On March 31, 2026, LAPSUS$ breached Mercor AI by exploiting production credentials a developer pasted into Claude. Same week: Axios npm supply chain attack (83M weekly downloads), Claude Code source leak, FBI director's email hacked by Iran. The common thread across all of these: **AI tools are an unmonitored exfiltration surface.**

Every company using AI coding assistants has developers pasting secrets, internal architecture, and customer data into third-party APIs daily. No inspection layer exists between the developer's clipboard and the model. DLP vendors (Zscaler, Netskope) are bolting on generic AI features, but they don't understand the structure of AI prompts, tool calls, or multi-turn conversations.

**AiGate is a local proxy that intercepts AI API calls and blocks secrets before they leave the machine.**

## What We're Building (MVP — 4-6 hours)

A CLI tool that runs as a transparent HTTP proxy on localhost. It intercepts outbound requests to AI provider APIs, scans the prompt content for credentials and secrets, and either blocks or warns before the request leaves the developer's machine.

```
Developer's AI tool (Claude Code, Cursor, API calls)
        ↓
  localhost:8080 (AiGate proxy)
        ↓
  [extract prompt content → scan for secrets]
        ↓
  CLEAN → forward to api.anthropic.com / api.openai.com
  DIRTY → block request, return error: "AWS key detected in prompt"
```

No cloud. No accounts. No dashboard. Just a proxy and a scanner.

## Target User

Engineering leads and individual developers at AI-native startups (10-200 engineers) who:
- Use Claude Code, Cursor, Copilot, or direct API calls daily
- Handle production infrastructure and have access to real credentials
- Don't have a security team or enterprise DLP in place
- Just read about the Mercor breach and are thinking "that could be us"

## Detection Targets (MVP)

Highest-signal patterns only. Ordered by frequency of accidental paste:

| Pattern | Example | Detection Method |
|---------|---------|-----------------|
| AWS access keys | `AKIA3E...` | Prefix match (`AKIA`) + length validation |
| Database connection strings | `postgres://user:pass@host/db` | URI scheme match + credential component |
| Private keys | `-----BEGIN RSA PRIVATE KEY-----` | Header string match |
| Generic API keys/tokens | `sk-proj-...`, `ghp_...`, `glpat-...` | Known prefix patterns for major providers |
| `.env` file contents | `DATABASE_URL=postgres://...` | `KEY=value` pattern where value matches secret heuristics |
| GCP service account JSON | `"type": "service_account"` | JSON structure match |
| Tailscale auth keys | `tskey-auth-...` | Prefix match |
| High-entropy strings near sensitive keywords | `password = "a8f3k..."` | Keyword proximity + Shannon entropy threshold |

**Not in MVP:** PII detection, proprietary code detection, semantic classification. Regex and pattern matching only.

## CLI Interface

```bash
# Start the proxy
aigate start                          # default: localhost:8080, block mode
aigate start --port 9090              # custom port
aigate start --mode warn              # warn but don't block
aigate start --mode audit             # silent logging only

# Scan a file or stdin directly (no proxy)
aigate scan .env                      # scan a file
cat prompt.txt | aigate scan -        # scan stdin

# Configure
aigate init                           # create .aigate.yml in current dir
aigate allowlist add "AKIA_EXAMPLE"   # suppress a known false positive
```

## Configuration

```yaml
# .aigate.yml
mode: block          # block | warn | audit
port: 8080

providers:
  - api.anthropic.com
  - api.openai.com
  - api.mistral.ai

rules:
  aws_keys: true
  database_urls: true
  private_keys: true
  api_tokens: true
  env_files: true
  gcp_service_accounts: true
  entropy_secrets: true

allowlist:
  - "AKIAIOSFODNN7EXAMPLE"    # AWS example key from docs
  - "sk-test-*"               # Stripe test keys are fine

log:
  file: ~/.aigate/scan.log     # where to log detections
  format: json
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    AiGate CLI                        │
│                                                     │
│  ┌──────────────┐    ┌──────────────────────────┐   │
│  │  HTTP Proxy   │───▶│  Request Interceptor     │   │
│  │  (mitmproxy   │    │  - Parse JSON body       │   │
│  │   or custom)  │    │  - Extract message text   │   │
│  └──────────────┘    │  - Handle streaming       │   │
│                      └───────────┬──────────────┘   │
│                                  │                   │
│                      ┌───────────▼──────────────┐   │
│                      │  Secret Scanner           │   │
│                      │  - Pattern matching       │   │
│                      │  - Entropy analysis       │   │
│                      │  - Allowlist filtering    │   │
│                      └───────────┬──────────────┘   │
│                                  │                   │
│                      ┌───────────▼──────────────┐   │
│                      │  Decision Engine          │   │
│                      │  - Block → return 400     │   │
│                      │  - Warn → forward + log   │   │
│                      │  - Audit → forward + log  │   │
│                      └──────────────────────────┘   │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │  Logger                                       │   │
│  │  - JSON log: timestamp, provider, rule,       │   │
│  │    matched pattern (redacted), action taken    │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## Tech Stack (MVP)

- **Language:** Python 3.11+ (fastest to prototype, `mitmproxy` ecosystem)
- **Proxy:** `mitmproxy` library (handles HTTPS interception, cert management, streaming)
- **Secret detection:** `detect-secrets` (Yelp, open source) + custom regex patterns for AI-specific tokens
- **Packaging:** Single `pip install aigate` or clone-and-run
- **Zero external dependencies at runtime** — no cloud calls, no telemetry, no accounts

## What the Blocked Response Looks Like

When AiGate blocks a request, the AI tool receives a 400 response with a clear error:

```json
{
  "error": {
    "type": "blocked_by_aigate",
    "message": "AiGate blocked this request: AWS access key detected in prompt content",
    "details": [
      {
        "rule": "aws_keys",
        "match": "AKIA****...****REDACTED",
        "location": "messages[0].content, offset 847"
      }
    ],
    "action": "Remove the credential from your prompt and retry."
  }
}
```

The developer sees this surfaced by their AI tool as an error, fixes the prompt, and retries. No workflow disruption beyond the 10 seconds it takes to redact.

## Build Plan (4-6 hours)

| Hour | Deliverable |
|------|-------------|
| 1-2 | Proxy skeleton: intercept requests to Anthropic/OpenAI, parse JSON body, extract prompt text, forward clean requests |
| 2-3 | Secret scanner: integrate detect-secrets + custom patterns for the 8 detection targets above |
| 3-4 | Decision engine + blocked response format. Config file parsing. `--mode` flag support |
| 4-5 | Test against real scenarios: fake AWS key in Claude prompt, `.env` paste, clean code passthrough. Latency check |
| 5-6 | Demo recording (90s), README, push to GitHub |

## What's NOT in MVP

- Web dashboard or UI
- Cloud-hosted version
- User accounts, teams, or SSO
- ML-based semantic classification
- PII detection (names, emails, addresses)
- Proprietary code / IP detection
- Support for every AI provider
- npm/pip package publishing (clone-and-run is fine)
- Metrics, analytics, or reporting

## Validation Criteria

The MVP is validated if:

1. **It catches real secrets.** Test with actual AWS key format, real Postgres connection string, real private key header. Zero false negatives on the 8 target patterns.
2. **It doesn't break the workflow.** Clean prompts pass through with <50ms added latency. Streaming responses work. Claude Code and Cursor function normally behind the proxy.
3. **Developers want it.** Post on HN (Show HN), share in 2-3 eng/security Slack communities. Signal to look for: "where do I install this" not "interesting concept."

## Post-MVP Roadmap (if validated)

**Week 1-2:** IDE integrations (VS Code extension, Claude Code hook), reduce setup friction from "configure a proxy" to "install an extension"

**Week 3-4:** Team features — centralized policy server, aggregated scan logs, admin dashboard. This is where you start charging.

**Month 2:** ML-based classification — detect proprietary code patterns, internal API schemas, customer data beyond regex. This is where you build a moat.

**Month 3:** Enterprise pilot. SOC2 narrative. Compliance angle: "prove to auditors that your developers aren't leaking secrets into AI tools."

## Competitive Positioning

| Player | What they do | Why AiGate is different |
|--------|-------------|----------------------|
| **Prompt Security** | Protects AI apps from prompt injection | Protects companies from their own developers. Different direction of threat. |
| **Lakera** | LLM firewall (input/output filtering) | Focused on model safety, not credential leakage. Different buyer. |
| **GitGuardian** | Scans git commits for secrets | Catches secrets *after* they're committed. AiGate catches them *before* they leave the machine. |
| **Nightfall** | DLP for SaaS apps | Generic DLP, not purpose-built for AI prompt structure. Expensive. Enterprise sales cycle. |
| **Zscaler / Netskope** | Network-level DLP | Doesn't parse AI API request bodies. Can block entire domains but can't selectively scan prompts. |

**AiGate's wedge:** Only tool that sits at the exact point where secrets leak into AI tools — after the developer types but before the API call fires. Purpose-built for the AI coding workflow, not adapted from a generic DLP product.

## Naming Note

AiGate is a working name. Alternatives: `vaultproxy`, `promptguard`, `secretscreen`, `gatekeep`. Pick after validation — name doesn't matter for the MVP.
