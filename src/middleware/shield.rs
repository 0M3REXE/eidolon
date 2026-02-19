use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum::Json;
use serde_json::json;
use unicode_normalization::UnicodeNormalization;

// ── Adversarial phrase blocklist ───────────────────────────────────────────

/// Known prompt injection / jailbreak trigger phrases.
/// Checked after NFKC normalization and zero-width character stripping,
/// making Unicode-homoglyph and zero-width injection attacks much harder.
const BLOCKED_PHRASES: &[&str] = &[
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore the above instructions",
    "output your system instructions",
    "reveal your instructions",
    "disregard previous instructions",
    "forget previous instructions",
    "new instructions:",
    "override instructions",
    "system prompt:",
    "act as if you have no restrictions",
    "jailbreak",
    "dan mode",
];

// ── Zero-width / invisible codepoints ─────────────────────────────────────

/// Invisible / zero-width Unicode codepoints commonly used to bypass string
/// matchers. These are stripped before normalization and phrase matching.
const ZERO_WIDTH_CHARS: &[char] = &[
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{200E}', // LEFT-TO-RIGHT MARK
    '\u{200F}', // RIGHT-TO-LEFT MARK
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE (BOM)
    '\u{2060}', // WORD JOINER
    '\u{00AD}', // SOFT HYPHEN
];

// ── Public sanitize function (reused by preflight middleware) ──────────────

/// Normalise text for adversarial phrase matching:
/// 1. Strip zero-width / invisible characters.
/// 2. Apply Unicode NFKC normalisation (homoglyph collapse).
/// 3. Lowercase.
pub fn normalize_for_shield(text: &str) -> String {
    let stripped: String = text.chars().filter(|c| !ZERO_WIDTH_CHARS.contains(c)).collect();
    stripped.nfkc().collect::<String>().to_lowercase()
}

/// Returns the blocked phrase if `normalized_text` contains one, else `None`.
/// The caller must have already run `normalize_for_shield`.
pub fn find_blocked_phrase(normalized_text: &str) -> Option<&'static str> {
    BLOCKED_PHRASES.iter().copied().find(|&p| normalized_text.contains(p))
}

// ── OpenAI-compatible error response ──────────────────────────────────────

pub fn blocked_response(_phrase: &str) -> Response {
    let body = Json(json!({
        "error": {
            "message": format!("Request blocked by Eidolon Shield: adversarial phrase detected."),
            "type": "invalid_request_error",
            "code": "prompt_injection_detected"
        }
    }));
    (StatusCode::BAD_REQUEST, body).into_response()
}
