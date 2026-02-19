# Eidolon PII Redaction Proxy

**Enterprise-Grade, Zero-Trust LLM Security Gateway**

Eidolon is a high-performance reverse proxy designed to secure Large Language Model (LLM) interactions. It intercepts outgoing prompts to providers like OpenAI, Anthropic, or Google, automatically detects and redacts Personally Identifiable Information (PII) using a hybrid engine, and restores the original data in the response—all within your secure perimeter.

Built in **Rust**, Eidolon offers sub-millisecond overhead and creates an airtight privacy layer for your AI applications.

---

## 🛡️ Why Eidolon? (Competitive Advantage)

Unlike SaaS-based redaction APIs that require sending sensitive data to yet another third party, Eidolon runs entirely on your infrastructure (or localhost).

| Feature | Eidolon | SaaS Redaction Services | Naive Regex |
| :--- | :--- | :--- | :--- |
| **Data Sovereignty** | **100% Local** (Data never leaves your VPC) | **Trust-Based** (They process your PII) | Local |
| **Detection Engine** | **Hybrid** (Regex Speed + BERT Accuracy) | AI-Only (Often slow/costly) | Regex-Only (High false positives) |
| **Re-Identification** | **Context-Aware De-tokenization** | Often One-Way Redaction | ❌ One-Way |
| **Performance** | **<10ms Latency** (Rust + ONNX Runtime) | >500ms (Network Hops) | <1ms |
| **Scalability** | **Stateless** (Horizontal Scaling + Redis) | Rate-Limited API | N/A |

---

## 🚀 Key Capabilities

### 1. Hybrid Detection Engine
Eidolon combines the speed of compiled Regex with the contextual understanding of a local NLP model (BERT).
- **Instant Regex**: Detecting structured data like Email, SSN, Credit Cards, IPv4, API Keys.
- **Contextual NLP**: Detecting unstructured entities like Person Names (PER), Locations (LOC), and Organizations (ORG).

### 2. Transparent Re-Identification
The proxy maintains a temporary, stateful mapping (in Redis) of redacted entities.
- **Request**: "Call John Doe at 555-0199" -> LLM sees "Call PER_82a1 at PHONE_9b2c".
- **Response**: LLM says "Calling PER_82a1..." -> App receives "Calling John Doe...".

### 3. Custom Enterprise Rules
Define domain-specific redaction rules in `config.toml` without code changes.
```toml
[[custom]]
name = "Internal Project ID"
pattern = '\bPROJ-\d{4}\b'  # Matches PROJ-1234
replacement = "PROJECT_ID"
```

### 4. Vendor Agnostic
Works with any client compatible with the OpenAI API format.
- Seamlessly drop into existing Python/Node.js/Go applications.
- Supports automatic routing for Google Gemini models.

---

## 🐳 Docker Deployment

Eidolon is designed for containerized environments (Kubernetes, ECS, Docker Compose).

### Rapid Deployment (GHCR)

Use our pre-built, optimized Docker image from the private GitHub Container Registry.

**1. Create `docker-compose.yml`**
```yaml
version: '3.8'
services:
  eidolon:
    image: ghcr.io/0m3rexe/eidolon:latest
    ports:
      - "3000:3000"
    environment:
      # Configure via Env Vars for security
      - REDIS__URL=redis://redis:6379
      - RUST_LOG=info
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data

volumes:
  redis-data:
```

**2. Start the Service**
```powershell
docker-compose up -d
```
The secure gateway is now active at `http://localhost:3000`.

### Production Considerations

- **Stateless Architecture**: The proxy itself is stateless. Scale it horizontally (e.g., 10 replicas) behind a load balancer.
- **Unified State**: All instances share the Redis backend for consistent de-tokenization.
- **Zero External Dependencies**: The NLP model is embedded in the Docker image. No external API calls are made for redaction.

---

## 🛠️ Configuration Reference

Configuration can be set via `config.toml` or Environment Variables (prefixed with `EIDOLON__`).

| Environment Variable | TOML Key | Description | Default |
| :--- | :--- | :--- | :--- |
| `EIDOLON__SERVER__PORT` | `server.port` | Port to listen on | `3000` |
| `EIDOLON__REDIS__URL` | `state.redis_url` | Redis connection string | `redis://127.0.0.1:6379` |
| `EIDOLON__LOGGING__LEVEL` | `logging.level` | Log verbosity | `info` |

---

## 📦 Building from Source

To build a production-optimized binary manually:

```powershell
# 1. Build
cargo build --release

# 2. Run
./target/release/eidolon
```

*Requires Rust 1.82+ due to modern dependency requirements.*
