use crate::api::handlers::{
    proxy_handler,
    health_handler,
    models_handler,
    redact_handler,
    ollama_root_handler,
    ollama_version_handler,
    ollama_tags_handler,
    ollama_proxy_handler,
    ollama_generate_handler,
    ollama_show_handler,
};
use crate::middleware::redaction::redact_request_middleware;
use crate::middleware::preflight::pre_flight_middleware;
use crate::middleware::rate_limiter::{rate_limit_middleware, build_rate_limiter};
use crate::state::AppState;
use std::sync::Arc;
use axum::{
    routing::{get, post},
    middleware::{self, from_fn},
    Router,
};

pub async fn app_router(
    state: Arc<AppState>,
    metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
) -> Router {
    // ── Rate limiter (shared state) ────────────────────────────────────────
    let rps = state.config.rate_limit.requests_per_second;
    let burst = state.config.rate_limit.burst_size;
    let limiter = build_rate_limiter(rps, burst);

    // ── Sub-router for routes that need PII redaction ─────────────────────
    let redacted_router = Router::new()
        .route("/v1/chat/completions", post(proxy_handler))
        .route("/api/chat", post(ollama_proxy_handler))          // interactive
        .route("/api/generate", post(ollama_generate_handler))   // `ollama run model "prompt"`
        .layer(middleware::from_fn_with_state(
            state.clone(),
            redact_request_middleware,
        ));


    Router::new()
        // ── Health & metrics ─────────────────────────────────────────────
        .route("/health", get(health_handler))
        .route("/metrics", get(move || std::future::ready(metrics_handle.render())))

        // ── Ollama CLI handshake (checked before every `ollama run`) ────────────
        .route("/", get(ollama_root_handler))
        .route("/api/version", get(ollama_version_handler))

        // ── Browser extension redact endpoint ──────────────────────────────
        .route("/v1/redact", post(redact_handler))

        // ── OpenAI-compatible passthrough ─────────────────────────────
        .route("/v1/models", get(models_handler))

        // ── Ollama passthrough routes ─────────────────────────────────────
        .route("/api/tags", get(ollama_tags_handler))
        .route("/api/show", post(ollama_show_handler))


        // ── Merge redacted routes ─────────────────────────────────────────
        .merge(redacted_router)

        // ── Middleware stack (last layer = outermost = runs first) ────────
        .layer(from_fn({
            let limiter = limiter.clone();
            move |req, next| rate_limit_middleware(req, next, limiter.clone())
        }))
        .layer(middleware::from_fn(pre_flight_middleware))
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(tower_http::trace::DefaultMakeSpan::new())
                .on_request(|request: &axum::http::Request<_>, _span: &tracing::Span| {
                    metrics::counter!(
                        "eidolon_http_requests_total",
                        "path" => request.uri().path().to_string(),
                        "method" => request.method().to_string()
                    ).increment(1);
                })
                .on_response(|response: &axum::http::Response<_>, latency: std::time::Duration, _span: &tracing::Span| {
                    metrics::histogram!(
                        "eidolon_http_response_latency_ms",
                        "status" => response.status().as_str().to_string()
                    ).record(latency.as_millis() as f64);
                }),
        )
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state)
}
