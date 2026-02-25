# Eidolon — PII Redaction Proxy

[![Rust](https://img.shields.io/badge/Built%20with-Rust-orange?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Enterprise-Grade, Zero-Trust LLM Security Gateway**

Eidolon is a high-performance reverse proxy that secures Large Language Model interactions. It intercepts outgoing prompts to providers like **OpenAI**, **Google Gemini**, **Anthropic Claude**, and **Ollama**, automatically detects and redacts Personally Identifiable Information (PII) using a hybrid engine, and restores the original data in the response — all within your secure perimeter.

Built in Rust, Eidolon offers sub-millisecond regex overhead and creates an airtight privacy layer for your AI applications, ensuring data sovereignty without sacrificing speed.

---

## How It Works

```
┌──────────┐   ①   ┌──────────┐   ④   ┌──────────┐
│  Your    │──────▶│ Eidolon  │──────▶│  LLM     │
│  App     │◀──────│  Proxy   │◀──────│ Provider │
└──────────┘   ⑤   └──────────┘   ⑤   └──────────┘
                      │     ▲
                   ②③ │     │ ③
                      ▼     │
                   ┌──────────┐
                   │  Redis   │
                   └──────────┘
```

1. **Intercept** — Your application sends a standard LLM API request to Eidolon instead of the provider.
2. **Redact** — Eidolon scans the prompt and replaces PII with realistic synthetic values (e.g., `john.doe@company.com` → `jane.smith@example.org`).
3. **Store** — The bidirectional mapping is AES-256-GCM encrypted and stored in Redis with a configurable TTL.
4. **Forward** — The sanitized prompt is forwarded to the LLM provider.
5. **Restore** — The LLM's response is intercepted, synthetic tokens are swapped back to real PII, and an egress DLP scan catches any *hallucinated* PII before the response reaches your application.

---

## Why Eidolon?

Unlike SaaS-based redaction APIs that require sending sensitive data to yet another third party, Eidolon runs **entirely on your infrastructure**.

| Feature | Eidolon | SaaS Redaction Services | Naive Regex |
|---|---|---|---|
| **Data Sovereignty** | 100% Local (redaction happens within your VPC before forwarding) | Trust-Based (they process your PII) | Local |
| **Detection Engine** | Hybrid (Regex Speed + BERT Accuracy) | AI-Only (often slow/costly) | Regex-Only (high false positives) |
| **Re-Identification** | Context-Aware De-tokenization | Often One-Way Redaction | ❌ One-Way |
| **Performance** | <10ms Latency (Rust + ONNX Runtime) | >500ms (Network Hops) | <1ms |
| **Encryption at Rest** | AES-256-GCM on all Redis values | Varies | ❌ None |
| **Provider Support** | OpenAI, Gemini, Claude, Ollama | Single provider | N/A |

---

## Key Capabilities

### 1. Hybrid Detection Engine

Eidolon combines the speed of compiled Regex with the contextual understanding of a local BERT NER model.

**Instant Regex** — Detects structured data:
- Email addresses
- Credit card numbers (with Luhn validation)
- IPv4 addresses
- SSNs (`XXX-XX-XXXX`)
- API keys (`sk-...`, `AKIA...`)

**Contextual NLP (BERT)** — Detects unstructured entities:
- Person names (`PER`)
- Locations (`LOC`)
- Organizations (`ORG`)

### 2. Realistic Synthetic Substitution

Instead of opaque tokens like `[REDACTED]`, Eidolon substitutes realistic plausible values so the LLM can reason naturally about the data shape:

| PII Type | Real Value | Synthetic Value |
|---|---|---|
| Email | `john.doe@company.com` | `jane.smith@example.org` |
| Person Name | `John Doe` | `Alice Johnson` |
| IPv4 | `192.168.1.100` | `10.42.7.23` |
| Credit Card | `4532-0151-1283-0366` | `CC_a1b2c3d4` |
| SSN | `123-45-6789` | `SSN_f8e7d6c5` |

### 3. Egress DLP Scanning

Eidolon also scans LLM **responses** for hallucinated PII that wasn't in the original prompt. This catches cases where a model fabricates realistic-looking sensitive data (emails, SSNs, etc.) in its output.

### 4. Prompt Injection Shield

A multi-layer defense against adversarial prompts:

- **Regex blocklist** — Catches known jailbreak phrases (`"ignore previous instructions"`, `"DAN mode"`, etc.)
- **Unicode normalization** — NFKC normalization + zero-width character stripping defeats homoglyph and invisible-character attacks.
- **ML Shield** (optional) — A DeBERTa-based classifier for detecting prompt injection attempts.

### 5. Custom Enterprise Rules

Define domain-specific redaction rules in `config.toml` without touching the codebase:

```toml
[[custom]]
name = "PROJECT_ID"
regex = "Project-\\d{4}"   # Matches "Project-1234"
```

### 6. Vendor-Agnostic Drop-in Replacement

Works with any client compatible with the OpenAI API format. Routes automatically based on the `model` field:

| Model prefix | Routed to |
|---|---|
| `gpt-*`, `o1-*`, `o3-*` | OpenAI API |
| `gemini-*` | Google Generative Language API |
| `claude-*` | Anthropic Messages API |
| Everything else | Local Ollama instance |

Simply change the `base_url` in your existing SDKs.

### 7. Browser Extension Endpoint

A dedicated `POST /v1/redact` endpoint allows browser extensions to redact text client-side and receive substitution mappings for local un-redaction of model responses.

---

## Quick Start

### Docker Compose

```yaml
version: '3.8'

services:
  eidolon:
    build: .
    ports:
      - "3000:3000"
    environment:
      - REDIS__URL=redis://redis:6379
      - RUST_LOG=info
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    volumes:
      - redis-data:/data
    command: redis-server --save 60 1 --loglevel warning

volumes:
  redis-data:
```

```bash
docker-compose up -d
```

Eidolon is now protecting your traffic at `http://localhost:3000`.

### Building from Source

```bash
# 1. Clone the repository
git clone https://github.com/0m3rexe/eidolon.git
cd eidolon

# 2. Build the release binary
cargo build --release

# 3. Run (requires Redis running on localhost:6379)
./target/release/eidolon
```

> **Note:** Requires Rust 1.80+ and a running Redis instance.

---

## Usage Example

Once Eidolon is running, point your existing LLM SDKs to the proxy.

### Python (OpenAI SDK)

```python
from openai import OpenAI

# Point the client to Eidolon's local port.
# Your actual API key is securely passed through to the provider.
client = OpenAI(
    base_url="http://localhost:3000/v1",
    api_key="sk-your-actual-openai-key"
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "Draft an email to John.Doe@company.com about Q4 revenue."}
    ]
)

print(response.choices[0].message.content)
# The LLM never saw the real email, but you get the seamlessly restored output.
```

### Google Gemini (via OpenAI-compatible format)

```python
client = OpenAI(
    base_url="http://localhost:3000/v1",
    api_key="your-gemini-api-key"       # Gemini API key
)

response = client.chat.completions.create(
    model="gemini-2.5-flash",           # Routes automatically to Gemini
    messages=[
        {"role": "user", "content": "My SSN is 123-45-6789. What format is that?"}
    ]
)
```

### Anthropic Claude (via OpenAI-compatible format)

```python
client = OpenAI(
    base_url="http://localhost:3000/v1",
    api_key="your-anthropic-api-key"
)

response = client.chat.completions.create(
    model="claude-sonnet-4-20250514",
    messages=[
        {"role": "user", "content": "Contact alice@example.com regarding the contract."}
    ]
)
```

### Local Ollama

```python
client = OpenAI(
    base_url="http://localhost:3000/v1",
    api_key="not-needed"                # Ollama doesn't require a key
)

response = client.chat.completions.create(
    model="llama3.2",                   # Routes to local Ollama
    messages=[
        {"role": "user", "content": "My credit card is 4532-0151-1283-0366."}
    ]
)
```

---

## Configuration

All settings live in `config.toml` and can be overridden via environment variables using `__` (double underscore) as the section separator.

### `config.toml` Reference

```toml
[server]
port = 3000
host = "0.0.0.0"

[redis]
url = "redis://127.0.0.1:6379"
ttl_seconds = 3600                     # Mapping expiry (1 hour)

[security]
fail_open = false                       # false = block on Redis failure; true = pass through
encryption_key = "change-me-to-32-char-secret-!!!!"   # AES-256-GCM key for Redis PII values

[ollama]
base_url = "http://localhost:11434"

[logging]
level = "info"

[rate_limit]
requests_per_second = 20
burst_size = 10

[nlp]
model_path = "assets/bert-ner-quantized.onnx"
tokenizer_path = "assets/tokenizer.json"

[policy]
redact_email = true
redact_cc = true
redact_ip = true
redact_ssn = true
redact_apikey = true
redact_ner_person = true
redact_ner_location = true
redact_ner_org = true

[shield]
# model_path = "assets/deberta-v3-base-prompt-injection.onnx"
# tokenizer_path = "assets/shield-tokenizer.json"

# Custom patterns (repeatable)
[[custom]]
name = "PROJECT_ID"
regex = "Project-\\d{4}"
```

### Environment Variable Overrides

| Environment Variable | TOML Key | Description | Default |
|---|---|---|---|
| `SERVER__PORT` | `server.port` | Port to listen on | `3000` |
| `SERVER__HOST` | `server.host` | Bind address | `0.0.0.0` |
| `REDIS__URL` | `redis.url` | Redis connection string | `redis://127.0.0.1:6379` |
| `REDIS__TTL_SECONDS` | `redis.ttl_seconds` | Mapping TTL | `3600` |
| `SECURITY__FAIL_OPEN` | `security.fail_open` | Pass-through on Redis failure | `false` |
| `SECURITY__ENCRYPTION_KEY` | `security.encryption_key` | AES-256-GCM encryption key | *(must change)* |
| `RUST_LOG` | — | Log verbosity (`eidolon=debug`, `info`, etc.) | `eidolon=debug` |
| `LOGGING__FORMAT` | — | `text` or `json` | `text` |

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/chat/completions` | OpenAI-compatible chat proxy (PII redaction + egress DLP) |
| `POST` | `/v1/redact` | Browser extension — returns redacted text + substitution map |
| `GET` | `/v1/models` | Transparent passthrough to OpenAI or Ollama model list |
| `GET` | `/health` | Health check (verifies Redis connectivity) |
| `GET` | `/metrics` | Prometheus metrics endpoint |
| `POST` | `/api/chat` | Ollama native chat endpoint (with redaction) |
| `POST` | `/api/generate` | Ollama native generate endpoint (with redaction) |
| `GET` | `/api/tags` | Ollama model list passthrough |
| `POST` | `/api/show` | Ollama model info passthrough |

---

## Architecture

```
src/
├── main.rs                    # Entry point, server init, graceful shutdown
├── config.rs                  # TOML + env config deserialization
├── error.rs                   # Unified error types
├── lib.rs                     # Crate re-exports
├── api/
│   ├── handlers.rs            # Route handlers (proxy, health, ollama, redact)
│   ├── routes.rs              # Axum router with middleware stack
│   ├── models.rs              # OpenAI/Ollama request/response types
│   ├── gemini.rs              # Gemini API translation layer
│   └── anthropic.rs           # Anthropic API translation layer
├── engine/
│   ├── patterns.rs            # Compiled regex patterns + Luhn validator
│   ├── nlp.rs                 # BERT NER inference via ONNX Runtime
│   └── shield_model.rs        # DeBERTa prompt injection classifier
├── middleware/
│   ├── redaction.rs           # Ingress PII redaction middleware
│   ├── streaming.rs           # Streaming response unredactor (Aho-Corasick)
│   ├── preflight.rs           # Body buffering, shield check, token limit
│   ├── shield.rs              # Blocklist + Unicode normalization
│   ├── rate_limiter.rs        # Token-bucket rate limiter (per IP)
│   └── token_limiter.rs       # Prompt token counting
├── state/
│   ├── mod.rs                 # AppState (shared across handlers)
│   └── redis.rs               # Redis connection manager + encrypted storage
└── utils/
    ├── crypto.rs              # AES-256-GCM encrypt/decrypt, SHA-256 hashing
    ├── faker.rs               # Realistic fake data generation
    └── response.rs            # Strip leaked system-prompt blocks
```

---

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change. Please ensure to update tests as appropriate.

## License

This project is licensed under the [Apache 2.0 License](LICENSE).

![Visitor Count](https://komarev.com/ghpvc/?username=0M3REXE&repo=eidolon&style=for-the-badge&color=brightgreen)