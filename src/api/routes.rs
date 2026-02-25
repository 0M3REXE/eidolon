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
    extract::State,
    http::{HeaderMap, StatusCode, Method, HeaderValue},
    response::{IntoResponse, Response},
    body::Body,
    extract::Request,
    middleware::Next,
};
use tower_http::cors::CorsLayer;

/// Middleware: require `Authorization: Bearer <token>` for the /v1/redact endpoint.
async fn redact_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Response {
    if let Some(required_token) = &state.config.security.redact_api_token {
        let auth = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let provided = auth.strip_prefix("Bearer ").unwrap_or("");
        if provided != required_token {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({
                    "error": {
                        "message": "Invalid or missing Authorization token for /v1/redact",
                        "type": "authentication_error",
                        "code": "unauthorized"
                    }
                })),
            ).into_response();
        }
    }
    next.run(request).await
}

/// Build a CORS layer from the configured allowed origins.
fn build_cors_layer(config: &crate::config::Config) -> CorsLayer {
    let origins = &config.security.allowed_origins;
    if origins.is_empty() {
        // Default: restrictive — only localhost
        CorsLayer::new()
            .allow_origin([
                "http://localhost:3000".parse::<HeaderValue>().unwrap(),
                "http://127.0.0.1:3000".parse::<HeaderValue>().unwrap(),
            ])
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(tower_http::cors::Any)
    } else {
        let parsed: Vec<HeaderValue> = origins
            .iter()
            .filter_map(|o| o.parse::<HeaderValue>().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(parsed)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(tower_http::cors::Any)
    }
}

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

    // ── CORS ─────────────────────────────────────────────────────────────
    let cors = build_cors_layer(&state.config);

    Router::new()
        // ── Health & metrics ─────────────────────────────────────────────
        .route("/health", get(health_handler))
        .route("/metrics", get(move || std::future::ready(metrics_handle.render())))

        // ── Ollama CLI handshake (checked before every `ollama run`) ────────────
        .route("/", get(ollama_root_handler))
        .route("/api/version", get(ollama_version_handler))

        // ── Browser extension redact endpoint (with optional auth) ─────────
        .merge(Router::new()
            .route("/v1/redact", post(redact_handler))
            .layer(middleware::from_fn_with_state(state.clone(), redact_auth_middleware))
        )

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
        .layer(cors)
        .with_state(state)
}

