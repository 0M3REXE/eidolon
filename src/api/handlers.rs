use crate::api::models::OpenAIChatRequest;
use crate::error::AppError;
use crate::state::AppState;
use crate::utils::response::strip_internal_notice;
use axum::http::StatusCode;
use axum::{
    extract::{State, Json, Extension},
    response::{IntoResponse, Response, Sse},
    http::HeaderMap,
};
use std::sync::Arc;
use tokio_stream::StreamExt;
use axum::response::sse::{Event, KeepAlive};
use tracing::error;
use axum::body::Body;
use crate::middleware::streaming::StreamUnredactor;

// ══════════════════════════════════════════════════════════════════════════════
// Shared helpers
// ══════════════════════════════════════════════════════════════════════════════

/// Replaces synthetic IDs with real PII values AND strips any leaked
/// [INTERNAL] system-prompt block the model may have echoed.
fn unmask(mut text: String, substitutions: &[(String, String)]) -> String {
    for (fake, real) in substitutions {
        text = text.replace(fake, real);
    }
    strip_internal_notice(text)
}

/// Egress scan:
/// 1. Unmask the prompt's synthetic IDs back to real data.
/// 2. Protect that real data.
/// 3. Run the redaction engine to catch *new* (hallucinated) PII.
/// 4. Restore the protected original data.
async fn egress_sanitize(
    mut text: String,
    state: &Arc<AppState>,
    prompt_subs: &[(String, String)]
) -> String {
    text = unmask(text, prompt_subs);

    let mut protected = Vec::new();
    for (_fake, real) in prompt_subs {
        let id = format!("<PROTECTED_{}>", uuid::Uuid::new_v4());
        text = text.replace(real, &id);
        protected.push((id, real.clone()));
    }

    let mut dummy_subs = Vec::new();
    let (mut sanitized, _, _) = crate::middleware::redaction::sanitize_text_pub(&text, state, &mut dummy_subs)
        .await
        .unwrap_or((text.clone(), vec![], std::collections::HashMap::new()));

    for (id, real) in protected {
        sanitized = sanitized.replace(&id, &real);
    }

    sanitized
}


// ══════════════════════════════════════════════════════════════════════════════
// Health
// ══════════════════════════════════════════════════════════════════════════════

pub async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.redis.ping().await {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            error!("Health check failed — Redis unreachable: {}", e);
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Ollama CLI handshake routes
// The Ollama CLI does GET / and GET /api/version before sending any request.
// Without these, `ollama run` exits with "something went wrong".
// ══════════════════════════════════════════════════════════════════════════════

/// GET / — Ollama CLI connectivity check.
pub async fn ollama_root_handler() -> impl IntoResponse {
    (StatusCode::OK, "Ollama is running")
}

/// GET /api/version — Ollama CLI version handshake.
pub async fn ollama_version_handler() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "version": "0.1.0" }))
}

// ══════════════════════════════════════════════════════════════════════════════
// POST /v1/redact — browser extension endpoint
// Accepts plain text, returns redacted text + substitution map.
// The extension stores substitutions locally and uses them to un-redact
// model responses client-side. No LLM forwarding happens here.
// ══════════════════════════════════════════════════════════════════════════════

#[derive(serde::Deserialize)]
pub struct RedactRequest {
    pub text: String,
}

#[derive(serde::Serialize)]
pub struct RedactResponse {
    pub redacted: String,
    pub pii_found: bool,
    pub pii_count: u32,
    /// List of (synthetic_id, real_value) pairs so the extension can restore
    /// PII in model responses rendered in the browser DOM.
    pub substitutions: Vec<(String, String)>,
    /// Which PII types were detected (e.g. ["EMAIL", "SSN"])
    pub types_found: Vec<String>,
}

pub async fn redact_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RedactRequest>,
) -> Result<axum::Json<RedactResponse>, AppError> {
    use crate::middleware::redaction::sanitize_text_pub;

    if payload.text.is_empty() {
        return Ok(axum::Json(RedactResponse {
            redacted: String::new(),
            pii_found: false,
            pii_count: 0,
            substitutions: vec![],
            types_found: vec![],
        }));
    }

    let mut substitutions: Vec<(String, String)> = Vec::new();
    let (redacted, _subs, counts) =
        sanitize_text_pub(&payload.text, &state, &mut substitutions).await?;

    let pii_count: u32 = counts.values().sum();
    let types_found: Vec<String> = counts
        .into_iter()
        .filter(|(_, v)| *v > 0)
        .map(|(k, _)| k.to_string())
        .collect();

    Ok(axum::Json(RedactResponse {
        pii_found: pii_count > 0,
        pii_count,
        substitutions,
        types_found,
        redacted,
    }))
}


// ══════════════════════════════════════════════════════════════════════════════

/// Transparent passthrough for GET /v1/models.
/// Routes to OpenAI when Authorization header is present; falls back to Ollama.
pub async fn models_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Decide target: if the caller provided a Bearer token that looks like an
    // OpenAI key, proxy to OpenAI; otherwise proxy to Ollama.
    let auth_value = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let (url, forward_auth) = if auth_value.starts_with("Bearer sk-") {
        ("https://api.openai.com/v1/models".to_string(), true)
    } else {
        (format!("{}/v1/models", state.config.ollama.base_url), false)
    };

    let mut req = state.client.get(&url);
    if forward_auth {
        req = req.header("Authorization", auth_value);
    }

    let res = req.send().await?;
    let status = res.status();
    let body_bytes = res.bytes().await?;

    Ok(Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(body_bytes))
        .map_err(|_| AppError::Internal)?)
}

// ══════════════════════════════════════════════════════════════════════════════
// Main proxy handler  (/v1/chat/completions)
// ══════════════════════════════════════════════════════════════════════════════

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Extension(substitutions): Extension<Arc<Vec<(String, String)>>>,
    headers: HeaderMap,
    Json(payload): Json<OpenAIChatRequest>,
) -> Result<Response, AppError> {
    let client = &state.client;
    let api_key = headers
        .get("Authorization")
        .ok_or_else(|| AppError::BadRequest("Missing Authorization header".to_string()))?;

    // ── Route by model prefix ──────────────────────────────────────────────
    if payload.model.starts_with("gemini") {
        return handle_gemini(client, &state, &payload, api_key, &substitutions).await;
    }

    if payload.model.starts_with("claude") {
        return handle_anthropic(client, &state, &payload, api_key, &substitutions).await;
    }

    // OpenAI / Ollama path
    let is_openai = payload.model.starts_with("gpt-")
        || payload.model.starts_with("text-embedding")
        || payload.model.starts_with("dall-e")
        || payload.model.starts_with("whisper")
        || payload.model.starts_with("tts")
        || payload.model.starts_with("o1-")
        || payload.model.starts_with("o3-");

    let url = if is_openai {
        "https://api.openai.com/v1/chat/completions".to_string()
    } else {
        format!("{}/v1/chat/completions", state.config.ollama.base_url)
    };

    let auth_header_val = api_key.to_str().unwrap_or_default();

    if payload.stream.unwrap_or(false) {
        let stream = client
            .post(&url)
            .header("Authorization", auth_header_val)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?
            .bytes_stream();

        let mut unredactor = StreamUnredactor::new(
            substitutions.iter().cloned().collect(),
            state.clone(),
        );

        let sse_stream = async_stream::stream! {
            tokio::pin!(stream);
            while let Some(item) = stream.next().await {
                match item {
                    Ok(bytes) => {
                        let text = String::from_utf8_lossy(&bytes);
                        let clean = unredactor.process(&text).await;
                        if !clean.is_empty() {
                            yield Ok::<_, axum::Error>(Event::default().data(clean));
                        }
                    }
                    Err(e) => {
                        error!("Stream error: {}", e);
                        yield Err(axum::Error::new(e));
                    }
                }
            }
            let remaining = unredactor.flush().await;
            if !remaining.is_empty() {
                yield Ok::<_, axum::Error>(Event::default().data(remaining));
            }
        };

        return Ok(Sse::new(sse_stream).keep_alive(KeepAlive::default()).into_response());
    }

    // Non-streaming OpenAI / Ollama
    let res = client
        .post(&url)
        .header("Authorization", auth_header_val)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if !res.status().is_success() {
        let status = res.status();
        // Do NOT log raw error body — may echo PII.
        error!("Upstream error: HTTP {}", status);
        return Ok((status, axum::Json(serde_json::json!({"error": "Upstream error", "status": status.as_u16()}))).into_response());
    }

    let body_text = res.text().await?;
    let safe_body = egress_sanitize(body_text, &state, &substitutions).await;
    Ok(Response::builder()
        .header("Content-Type", "application/json")
        .body(Body::from(safe_body))
        .map_err(|_| AppError::Internal)?)
}

// ── Gemini ─────────────────────────────────────────────────────────────────

async fn handle_gemini(
    client: &reqwest::Client,
    _state: &Arc<AppState>,
    payload: &OpenAIChatRequest,
    api_key: &axum::http::HeaderValue,
    substitutions: &[(String, String)],
) -> Result<Response, AppError> {
    let key_str = api_key.to_str().unwrap_or_default();
    let key = key_str.strip_prefix("Bearer ").unwrap_or(key_str);

    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent",
        payload.model
    );

    let gemini_req = crate::api::gemini::GeminiRequest::from_openai(payload)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let res = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("x-goog-api-key", key)
        .json(&gemini_req)
        .send()
        .await?;

    if !res.status().is_success() {
        let status = res.status();
        error!("Gemini API error: HTTP {}", status);
        return Ok((StatusCode::BAD_GATEWAY, axum::Json(serde_json::json!({"error": "Upstream Gemini error"}))).into_response());
    }

    let gemini_resp: crate::api::gemini::GeminiResponse = res.json().await?;
    let openai_resp = crate::api::gemini::OpenAIChatResponse::from_gemini(gemini_resp, payload.model.clone())
        .map_err(|_| AppError::Internal)?;

    let resp_json = serde_json::to_string(&openai_resp).map_err(AppError::Serialization)?;
    let safe_body = egress_sanitize(resp_json, _state, substitutions).await;
    Ok(Response::builder()
        .header("Content-Type", "application/json")
        .body(Body::from(safe_body))
        .map_err(|_| AppError::Internal)?)
}

// ── Anthropic ──────────────────────────────────────────────────────────────

async fn handle_anthropic(
    client: &reqwest::Client,
    _state: &Arc<AppState>,
    payload: &OpenAIChatRequest,
    api_key: &axum::http::HeaderValue,
    substitutions: &[(String, String)],
) -> Result<Response, AppError> {
    let key_str = api_key.to_str().unwrap_or_default();
    let key = key_str.strip_prefix("Bearer ").unwrap_or(key_str);

    let anthropic_req = crate::api::anthropic::AnthropicRequest::from_openai(
        &payload.model,
        &payload.messages,
        payload.temperature,
        payload.unknown_fields
            .get("max_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(4096) as u32,
    );

    let res = client
        .post("https://api.anthropic.com/v1/messages")
        .header("Content-Type", "application/json")
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .json(&anthropic_req)
        .send()
        .await?;

    if !res.status().is_success() {
        let status = res.status();
        error!("Anthropic API error: HTTP {}", status);
        return Ok((StatusCode::BAD_GATEWAY, axum::Json(serde_json::json!({"error": "Upstream Anthropic error"}))).into_response());
    }

    let anthropic_resp: crate::api::anthropic::AnthropicResponse = res.json().await?;
    let openai_resp = crate::api::anthropic::OpenAIChatResponse::from_anthropic(anthropic_resp)
        .map_err(|_| AppError::Internal)?;

    let resp_json = serde_json::to_string(&openai_resp).map_err(AppError::Serialization)?;
    let safe_body = egress_sanitize(resp_json, _state, substitutions).await;
    Ok(Response::builder()
        .header("Content-Type", "application/json")
        .body(Body::from(safe_body))
        .map_err(|_| AppError::Internal)?)
}

// ══════════════════════════════════════════════════════════════════════════════
// Ollama native handlers
// ══════════════════════════════════════════════════════════════════════════════

pub async fn ollama_tags_handler(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let url = format!("{}/api/tags", state.config.ollama.base_url);
    let res = state.client.get(&url).send().await?;
    Ok(Response::builder()
        .header("Content-Type", "application/json")
        .body(Body::from_stream(res.bytes_stream()))
        .map_err(|_| AppError::Internal)?)
}

pub async fn ollama_proxy_handler(
    State(state): State<Arc<AppState>>,
    Extension(substitutions): Extension<Arc<Vec<(String, String)>>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Response, AppError> {
    let url = format!("{}/api/chat", state.config.ollama.base_url);
    let is_stream = payload.get("stream").and_then(|v| v.as_bool()).unwrap_or(true);

    let res = state.client.post(&url).json(&payload).send().await?;

    if !res.status().is_success() {
        let status = res.status();
        error!("Ollama upstream error: HTTP {}", status);
        return Ok((status, axum::Json(serde_json::json!({"error": "Ollama upstream error"}))).into_response());
    }

    if is_stream {
        let bytes_stream = res.bytes_stream();
        let mut unredactor = StreamUnredactor::new(substitutions.iter().cloned().collect(), state.clone());

        let body_stream = async_stream::stream! {
            tokio::pin!(bytes_stream);
            while let Some(item) = bytes_stream.next().await {
                match item {
                    Ok(bytes) => {
                        let text = String::from_utf8_lossy(&bytes);
                        let clean = unredactor.process(&text).await;
                        if !clean.is_empty() {
                            yield Ok::<_, axum::Error>(clean);
                        }
                    }
                    Err(e) => {
                        error!("Ollama stream error: {}", e);
                        yield Err(axum::Error::new(e));
                    }
                }
            }
            let remaining = unredactor.flush().await;
            if !remaining.is_empty() {
                yield Ok::<_, axum::Error>(remaining);
            }
        };

        return Ok(Response::builder()
            .header("Content-Type", "application/json")
            .header("X-Eidolon-Proxy", "Active")
            .body(Body::from_stream(body_stream))
            .map_err(|_| AppError::Internal)?);
    }

    let body_text = res.text().await?;
    let safe_body = egress_sanitize(body_text, &state, &substitutions).await;
    Ok(Response::builder()
        .header("Content-Type", "application/json")
        .header("X-Eidolon-Proxy", "Active")
        .body(Body::from(safe_body))
        .map_err(|_| AppError::Internal)?)
}

pub async fn ollama_show_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Response, AppError> {
    let url = format!("{}/api/show", state.config.ollama.base_url);
    let res = state.client.post(&url).json(&payload).send().await?;
    Ok(Response::builder()
        .header("Content-Type", "application/json")
        .body(Body::from_stream(res.bytes_stream()))
        .map_err(|_| AppError::Internal)?)
}

/// POST /api/generate — used by `ollama run model "prompt"` (non-interactive).
/// The redaction middleware has already replaced PII in the `prompt` field
/// before this handler is called.
pub async fn ollama_generate_handler(
    State(state): State<Arc<AppState>>,
    Extension(substitutions): Extension<Arc<Vec<(String, String)>>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Response, AppError> {
    let url = format!("{}/api/generate", state.config.ollama.base_url);
    let is_stream = payload.get("stream").and_then(|v| v.as_bool()).unwrap_or(true);

    let res = state.client.post(&url).json(&payload).send().await?;

    if !res.status().is_success() {
        let status = res.status();
        error!("Ollama generate upstream error: HTTP {}", status);
        return Ok((status, axum::Json(serde_json::json!({"error": "Ollama upstream error"}))).into_response());
    }

    if is_stream {
        let bytes_stream = res.bytes_stream();
        let mut unredactor = StreamUnredactor::new(substitutions.iter().cloned().collect(), state.clone());

        let body_stream = async_stream::stream! {
            tokio::pin!(bytes_stream);
            while let Some(item) = bytes_stream.next().await {
                match item {
                    Ok(bytes) => {
                        let text = String::from_utf8_lossy(&bytes);
                        let clean = unredactor.process(&text).await;
                        if !clean.is_empty() {
                            yield Ok::<_, axum::Error>(clean);
                        }
                    }
                    Err(e) => {
                        error!("Ollama generate stream error: {}", e);
                        yield Err(axum::Error::new(e));
                    }
                }
            }
            let remaining = unredactor.flush().await;
            if !remaining.is_empty() {
                yield Ok::<_, axum::Error>(remaining);
            }
        };

        return Ok(Response::builder()
            .header("Content-Type", "application/json")
            .header("X-Eidolon-Proxy", "Active")
            .body(Body::from_stream(body_stream))
            .map_err(|_| AppError::Internal)?);
    }

    let body_text = res.text().await?;
    let safe_body = egress_sanitize(body_text, &state, &substitutions).await;
    Ok(Response::builder()
        .header("Content-Type", "application/json")
        .header("X-Eidolon-Proxy", "Active")
        .body(Body::from(safe_body))
        .map_err(|_| AppError::Internal)?)
}
