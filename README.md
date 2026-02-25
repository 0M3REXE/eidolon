# Eidolon PII Redaction Proxy

![Build Status](https://img.shields.io/badge/build-passing-brightgreen) ![Docker Pulls](https://img.shields.io/badge/docker-ghcr.io%2F0m3rexe%2Feidolon-blue) ![Rust](https://img.shields.io/badge/rust-1.82%2B-orange) ![License](https://img.shields.io/badge/license-MIT-green)

**Enterprise-Grade, Zero-Trust LLM Security Gateway**

Eidolon is a high-performance reverse proxy designed to secure Large Language Model (LLM) interactions. It intercepts outgoing prompts to providers like OpenAI, Anthropic, or Google, automatically detects and redacts Personally Identifiable Information (PII) using a hybrid engine, and restores the original data in the response—all within your secure perimeter.

Built in **Rust**, Eidolon offers sub-millisecond overhead and creates an airtight privacy layer for your AI applications, ensuring compliance and data sovereignty without sacrificing speed.

---

## How It Works



1. **Intercept:** Your application sends a standard LLM API request to Eidolon instead of the provider.
2. **Redact:** Eidolon scans the prompt, replacing PII with secure tokens (e.g., `John Doe` -> `[PER_1]`).
3. **Store:** The mapping is temporarily securely stored in a local Redis instance.
4. **Forward:** The sanitized prompt is sent to the LLM.
5. **Restore:** The LLM's response is intercepted, and tokens are swapped back to the original PII before reaching your application.

---

## Why Eidolon? (Competitive Advantage)

Unlike SaaS-based redaction APIs that require sending sensitive data to yet another third party, Eidolon runs entirely on your infrastructure. 

| Feature | Eidolon | SaaS Redaction Services | Naive Regex |
| :--- | :--- | :--- | :--- |
| **Data Sovereignty** | **100% Local** (Data never leaves your VPC) | Trust-Based (They process your PII) | Local |
| **Detection Engine** | **Hybrid** (Regex Speed + BERT Accuracy) | AI-Only (Often slow/costly) | Regex-Only (High false positives) |
| **Re-Identification** | **Context-Aware De-tokenization** | Often One-Way Redaction | ❌ One-Way |
| **Performance** | **<10ms Latency** (Rust + ONNX Runtime) | >500ms (Network Hops) | <1ms |
| **Scalability** | **Stateless** (Horizontal Scaling + Redis) | Rate-Limited API | N/A |

---

## Key Capabilities

### 1. Hybrid Detection Engine
Eidolon combines the sheer speed of compiled Regex with the contextual understanding of a local NLP model (BERT).
- **Instant Regex**: Detects structured data (Emails, SSNs, Credit Cards, IPv4, API Keys).
- **Contextual NLP**: Detects unstructured entities (Person Names, Locations, Organizations).

### 2. Transparent Re-Identification
The proxy maintains a temporary, stateful mapping in Redis.
- **Request**: `"Call John Doe at 555-0199"` -> LLM sees `"Call PER_82a1 at PHONE_9b2c"`.
- **Response**: LLM says `"Calling PER_82a1..."` -> App receives `"Calling John Doe..."`.

### 3. Custom Enterprise Rules
Define domain-specific redaction rules in `config.toml` without touching the codebase.
```toml
[[custom]]
name = "Internal Project ID"
pattern = '\bPROJ-\d{4}\b'  # Matches PROJ-1234
replacement = "PROJECT_ID"
```
### 4. Vendor Agnostic Drop-in Replacement

Works with any client compatible with the OpenAI API format. Simply change the base_url in your existing Python, Node.js, or Go applications.

---

## Quick Start (Docker)

Eidolon is designed for containerized environments (Kubernetes, ECS, Docker Compose). The embedded NLP model means zero external dependencies aside from Redis.

### 1. Create docker-compose.yml
```
version: '3.8'
services:
  eidolon:
    image: ghcr.io/0m3rexe/eidolon:latest
    ports:
      - "3000:3000"
    environment:
      - EIDOLON__REDIS__URL=redis://redis:6379
      - EIDOLON__LOGGING__LEVEL=info
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data

volumes:
  redis-data:
```

### 2. Start the Gateway
```bash
docker-compose up -d
```

Eidolon is now actively protecting your traffic at http://localhost:3000.