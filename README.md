# Eidolon PII Redaction Proxy

Eidolon is a high-performance, transparent reverse proxy written in Rust that intercepts outgoing prompts to LLM providers (OpenAI, Google Gemini) to redact sensitive Personally Identifiable Information (PII) before it leaves your infrastructure. 

It uses a hybrid approach combining high-speed Regex patterns and a local NLP model (BERT NER) to detect and replace entities like names, emails, and locations with deterministic synthetic IDs. When the LLM responds, Eidolon re-injects the original data, ensuring a seamless experience for the end-user while maintaining strict data privacy.

## Features

- **Hybrid Redaction Engine**: 
  - **Regex**: Instant detection for Email, Credit Cards, IPv4, SSN, and API Keys.
  - **NLP (BERT)**: Context-aware Named Entity Recognition (NER) for Names (PER), Locations (LOC), and Organizations (ORG).
- **Multi-Provider Support**:
  - **OpenAI**: Native support for `/v1/chat/completions`.
  - **Google Gemini**: Automatic routing for `gemini-*` models via a native adapter.
- **Stateful Management**: Redis-backed mapping store to preserve context across turns and re-inject original data accurately.
- **High Performance**: Built on `Axum` and `Tokio` for asynchronous request handling.
- **Extensible**: Designed to support multimodal inputs (Vision) and additional providers.

## Prerequisites

- **Rust**: Latest stable toolchain (`rustup update`).
- **Redis**: Running instance for state management (default: `redis://127.0.0.1:6379`).
- **ONNX Runtime (ORT)**: 
  - Windows: Requires `onnxruntime.dll` (v1.20.1 recommended) placed in the project root and `target/debug/` directory.
  - The project attempts to download models, but the DLL might need manual placement.

## Setup

1.  **Start Redis**:
    ```bash
    docker run -d -p 6379:6379 --name eidolon-redis redis
    ```

2.  **Download Assets**:
    - Ensure `assets/bert-ner-quantized.onnx` exists. The application will attempt to load it on startup.

3.  **ONNX Runtime (Windows)**:
    - Download `onnxruntime-win-x64-1.20.1.zip` from GitHub Releases.
    - Extract `lib/onnxruntime.dll` to the project root `Eidolon/`.
    - **Crucial**: Also copy it to `target/debug/` if running via `cargo run`.

4.  **Run the Server**:
    ```bash
    cargo run
    ```
    The server will start on `http://0.0.0.0:3000`.

## Configuration

Configuration is managed via `config.toml` or Environment Variables.

| Variable | Description | Default |
| :--- | :--- | :--- |
| `SERVER__PORT` | Port to listen on | `3000` |
| `REDIS__URL` | Redis connection URL | `redis://127.0.0.1:6379` |
| `LOGGING__LEVEL` | Tracing log level | `info` |

## Usage

### 1. OpenAI (Standard)

Standard OpenAI models are routed to `api.openai.com`.

**PowerShell Example:**
```powershell
$headers = @{
    "Authorization" = "Bearer sk-your-openai-key"
    "Content-Type" = "application/json"
}
$body = @{
    model = "gpt-4"
    messages = @(
        @{
            role = "user"
            content = "My name is John Doe. Email me at john.doe@example.com."
        }
    )
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Uri "http://localhost:3000/v1/chat/completions" -Method Post -Headers $headers -Body $body
```

### 2. Google Gemini

Models starting with `gemini-` (e.g., `gemini-1.5-flash`, `gemini-2.5-flash`) are automatically routed to Google's API.
**Note**: Use a model available to your API Key/Region.

**PowerShell Example:**
```powershell
$headers = @{
    "Authorization" = "Bearer YOUR_GOOGLE_API_KEY"
    "Content-Type" = "application/json"
}
$body = @{
    model = "gemini-2.5-flash"
    messages = @(
        @{
            role = "user"
            content = "My name is John Doe and I live in New York."
        }
    )
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Uri "http://localhost:3000/v1/chat/completions" -Method Post -Headers $headers -Body $body
```

### 3. Ollama (Local / Open Source)

Any model that doesn't start with `gemini-`, `gpt-`, `text-embedding-`, `dall-e-`, `whisper-`, or `tts-` is automatically routed to your **Ollama** instance.
- **Default URL**: `http://localhost:11434` (Configurable via `config.toml` or `EIDOLON__OLLAMA__BASE_URL`).

**PowerShell Example:**
```powershell
$headers = @{
    "Content-Type" = "application/json"
    # Authorization header is optional for local Ollama, but Eidolon passes it if provided.
}
$body = @{
    model = "llama3"
    messages = @(
        @{
            role = "user"
            content = "Why is the sky blue?"
        }
    )
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Uri "http://localhost:3000/v1/chat/completions" -Method Post -Headers $headers -Body $body
```

## Testing

An integration test is included to verify the full PII redaction pipeline without hitting external APIs.

```bash
cargo test --test redaction_test -- --nocapture
```
This will spin up an ephemeral server, send a request with mixed PII (Email, Names), and verify that "John Doe" becomes `PER_...` and "New York" becomes `LOC_...`.

## Architecture

- **`src/api`**: Handlers for HTTP requests and the Gemini Adapter.
- **`src/engine`**: 
  - `nlp.rs`: ONNX Runtime wrapper for BERT inference.
  - `patterns.rs`: Regex compilation and management.
- **`src/middleware`**:
  - `redaction.rs`: Main logic for inspecting JSON bodies and invoking the engine.
- **`src/state`**: Redis managing logic for Synthetic ID <-> Real Value mapping.
