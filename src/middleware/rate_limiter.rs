use axum::{
    body::Body,
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use axum::Json;
use dashmap::DashMap;
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::InMemoryState,
};
use std::{
    net::IpAddr,
    num::NonZeroU32,
    sync::Arc,
};
use serde_json::json;

pub type SharedIpLimiter = Arc<RateLimiter<IpAddr, DashMap<IpAddr, InMemoryState>, DefaultClock>>;

/// Constructs a per-IP token-bucket rate limiter.
pub fn build_rate_limiter(requests_per_second: u64, burst_size: u32) -> SharedIpLimiter {
    let rps = NonZeroU32::new(requests_per_second.max(1) as u32).unwrap();
    let burst = NonZeroU32::new(burst_size.max(1)).unwrap();
    let quota = Quota::per_second(rps).allow_burst(burst);
    Arc::new(RateLimiter::dashmap(quota))
}

/// Axum middleware: per-IP rate limiting.
/// Returns `429 Too Many Requests` with an OpenAI-compatible JSON body on
/// exceeding the configured rate.
pub async fn rate_limit_middleware(
    request: Request<Body>,
    next: Next,
    limiter: SharedIpLimiter,
) -> Response {
    let client_ip = extract_ip(&request).unwrap_or(IpAddr::from([127, 0, 0, 1]));

    match limiter.check_key(&client_ip) {
        Ok(_) => next.run(request).await,
        Err(_) => {
            tracing::warn!(ip = %client_ip, "Rate limit exceeded");
            metrics::counter!("eidolon_rate_limited_total").increment(1);
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": {
                        "message": "Rate limit exceeded. Please slow down.",
                        "type": "rate_limit_error",
                        "code": "too_many_requests"
                    }
                })),
            )
                .into_response()
        }
    }
}

fn extract_ip(request: &Request<Body>) -> Option<IpAddr> {
    if let Some(xff) = request.headers().get("X-Forwarded-For") {
        if let Ok(xff_str) = xff.to_str() {
            if let Ok(ip) = xff_str.split(',').next().unwrap_or("").trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    if let Some(xri) = request.headers().get("X-Real-IP") {
        if let Ok(ip_str) = xri.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}
