use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use http_body_util::BodyExt;
use tokenizers::Tokenizer;
use std::sync::OnceLock;
use tracing::warn;

// Global Tokenizer (Singleton)
static TOKENIZER: OnceLock<Tokenizer> = OnceLock::new();

// Configuration: Max tokens allowed for a prompt (conservative limit)
// e.g., GPT-4 8k context, reserve 1k for response -> 7k max prompt.
const MAX_PROMPT_TOKENS: usize = 7000;

pub async fn token_limiter_middleware(request: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let (parts, body) = request.into_parts();

    // 1. Buffer body
    let bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    // 2. Estimate Tokens
    // We use a simple approximation if tokenizer fails to load, or the actual tokenizer.
    let text = String::from_utf8_lossy(&bytes);
    
    let token_count = count_tokens(&text);
    
    if token_count > MAX_PROMPT_TOKENS {
        warn!("TOKEN LIMIT EXCEEDED: Prompt size {} tokens > limit {}", token_count, MAX_PROMPT_TOKENS);
        return Err(StatusCode::BAD_REQUEST);
    }

    // 3. Reconstruct
    let request = Request::from_parts(parts, Body::from(bytes));
    Ok(next.run(request).await)
}

fn count_tokens(text: &str) -> usize {
    // Try to use the loaded tokenizer
    if let Some(tokenizer) = TOKENIZER.get() {
        if let Ok(encoding) = tokenizer.encode(text, false) {
            tracing::debug!("Token count (cached): {}", encoding.get_ids().len());
            return encoding.get_ids().len();
        }
    } else {
        // Try to load it lazily (this might block, but fine for prototype)
        tracing::info!("Initializing Tokenizer from HF...");
        // Ideally load in main.rs
        match Tokenizer::from_pretrained("Xenova/gpt-4", None) {
            Ok(tokenizer) => {
                 let _ = TOKENIZER.set(tokenizer);
                 tracing::info!("Tokenizer loaded successfully.");
                 // Retry
                 if let Some(t) = TOKENIZER.get() {
                     if let Ok(encoding) = t.encode(text, false) {
                         tracing::debug!("Token count (fresh): {}", encoding.get_ids().len());
                         return encoding.get_ids().len();
                     }
                 }
            },
            Err(e) => {
                tracing::warn!("Failed to load tokenizer: {}. Using fallback.", e);
            }
        }
    }
    
    // Fallback: Char / 4 heuristic
    let est = text.len() / 4;
    tracing::debug!("Token count (fallback): {}", est);
    est
}
