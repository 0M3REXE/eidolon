use axum::{
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use bytes::Bytes;
use http_body_util::BodyExt;
use tokenizers::Tokenizer;
use tracing::warn;
use std::sync::{Arc, OnceLock};
use crate::middleware::shield::{normalize_for_shield, find_blocked_phrase, blocked_response};
use crate::state::AppState;

// ── Token counting ─────────────────────────────────────────────────────────

static TOKENIZER: OnceLock<Tokenizer> = OnceLock::new();

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
    text.len() / 4
}

// ── Pre-flight middleware (single body read) ───────────────────────────────

pub async fn pre_flight_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();

    let bytes: Bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return blocked_response("Failed to read request body");
        }
    };

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

        match crate::engine::shield_model::ShieldEngine::is_injection(&body_str) {
            Ok(true) => {
                warn!(
                    shield = true,
                    "SHIELD: ML Model detected prompt injection / jailbreak attempt"
                );
                metrics::counter!("eidolon_shield_blocked_total", "reason" => "ml_prompt_injection").increment(1);
                return blocked_response("ML Shield detected adversarial intent");
            }
            Ok(false) => {}
            Err(e) => {
                if state.config.security.fail_open {
                    warn!(
                        shield = true,
                        error = %e,
                        "ML Shield execution error — failing open per config"
                    );
                } else {
                    tracing::error!(
                        shield = true,
                        error = %e,
                        "ML Shield execution error — blocking request (fail_open=false)"
                    );
                    metrics::counter!("eidolon_fail_open_events_total").increment(1);
                    return blocked_response("ML Shield execution error");
                }
            }
        }

        if state.config.limits.max_prompt_tokens > 0 {
            let token_count = count_tokens(&body_str);
            if token_count > state.config.limits.max_prompt_tokens {
                warn!(
                    token_count,
                    limit = state.config.limits.max_prompt_tokens,
                    "TOKEN LIMIT EXCEEDED"
                );
                metrics::counter!("eidolon_token_limit_exceeded_total").increment(1);
                return blocked_response(&format!(
                    "Prompt too large: {} tokens (limit {})",
                    token_count,
                    state.config.limits.max_prompt_tokens
                ));
            }
        }
    }

    let mut request = Request::from_parts(parts, Body::from(bytes.clone()));
    request.extensions_mut().insert(bytes);

    next.run(request).await
}