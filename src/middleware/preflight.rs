use axum::{
    body::Body,
    extract::Request,
    middleware::Next,
    response::Response,
};
use bytes::Bytes;
use http_body_util::BodyExt;
use tokenizers::Tokenizer;
use std::sync::OnceLock;
use tracing::warn;
use crate::middleware::shield::{normalize_for_shield, find_blocked_phrase, blocked_response};

// ── Token counting ─────────────────────────────────────────────────────────

static TOKENIZER: OnceLock<Tokenizer> = OnceLock::new();

/// Maximum tokens allowed in a prompt (GPT-4 8k window, reserving 1k for response).
const MAX_PROMPT_TOKENS: usize = 7000;

/// Initialise the token-counting tokenizer from a local file at startup.
/// Call this from `main.rs` before starting the server.
pub fn init_tokenizer(tokenizer_path: &str) -> anyhow::Result<()> {
    let tokenizer = Tokenizer::from_file(tokenizer_path)
        .map_err(|e| anyhow::anyhow!("Failed to load tokenizer from '{}': {}", tokenizer_path, e))?;
    let _ = TOKENIZER.set(tokenizer);
    Ok(())
}

fn count_tokens(text: &str) -> usize {
    if let Some(t) = TOKENIZER.get() {
        if let Ok(encoding) = t.encode(text, false) {
            return encoding.get_ids().len();
        }
    }
    // Fallback heuristic when tokenizer is unavailable.
    text.len() / 4
}

// ── Pre-flight middleware (single body read) ───────────────────────────────

/// Single body-buffering middleware that replaces the previous `shield_middleware`
/// + `token_limiter_middleware` duo.
///
/// Reads the HTTP body **once**, then:
/// 1. Checks for adversarial prompt-injection phrases (with NFKC normalization).
/// 2. Checks the token count against `MAX_PROMPT_TOKENS`.
/// 3. Injects the buffered bytes as a request extension so the downstream
///    `redact_request_middleware` can retrieve them without re-buffering.
pub async fn pre_flight_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();

    // ── 1. Buffer the body (single allocation) ────────────────────────────
    let bytes: Bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return blocked_response("Failed to read request body");
        }
    };

    // ── 2. Shield check ────────────────────────────────────────────────────
    if !bytes.is_empty() {
        let body_str = String::from_utf8_lossy(&bytes);
        let normalized = normalize_for_shield(&body_str);

        if let Some(phrase) = find_blocked_phrase(&normalized) {
            warn!(
                shield = true,
                blocked_phrase = phrase,
                "SHIELD: Blocked prompt containing adversarial phrase"
            );
            metrics::counter!("eidolon_shield_blocked_total", "reason" => "prompt_injection").increment(1);
            return blocked_response(phrase);
        }

        // ML Shield check
        match crate::engine::shield_model::ShieldEngine::is_injection(&body_str) {
            Ok(true) => {
                warn!(
                    shield = true,
                    "SHIELD: ML Model detected prompt injection / jailbreak attempt"
                );
                metrics::counter!("eidolon_shield_blocked_total", "reason" => "ml_prompt_injection").increment(1);
                return blocked_response("ML Shield detected adversarial intent");
            }
            Ok(false) => {} // safe
            Err(e) => {
                tracing::debug!("ML Shield execution error: {}", e);
            }
        }

        // ── 3. Token limit check ───────────────────────────────────────────
        let token_count = count_tokens(&body_str);
        if token_count > MAX_PROMPT_TOKENS {
            warn!(
                token_count,
                limit = MAX_PROMPT_TOKENS,
                "TOKEN LIMIT EXCEEDED"
            );
            metrics::counter!("eidolon_token_limit_exceeded_total").increment(1);
            return blocked_response(&format!(
                "Prompt too large: {} tokens (limit {})", token_count, MAX_PROMPT_TOKENS
            ));
        }
    }

    // ── 4. Reconstruct request with buffered bytes ─────────────────────────
    // The redaction middleware can pull the `Bytes` from extensions instead of
    // calling body.collect() again.
    let mut request = Request::from_parts(parts, Body::from(bytes.clone()));
    request.extensions_mut().insert(bytes);

    next.run(request).await
}
