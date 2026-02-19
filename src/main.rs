use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Tracing ────────────────────────────────────────────────────────────
    let format = std::env::var("LOGGING__FORMAT").unwrap_or_else(|_| "text".to_string());
    let filter = tracing_subscriber::EnvFilter::new(
        std::env::var("RUST_LOG").unwrap_or_else(|_| "eidolon=debug,tower_http=debug".into()),
    );

    if format.eq_ignore_ascii_case("json") {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    // ── Prometheus ────────────────────────────────────────────────────────
    let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let metrics_handle = builder
        .install_recorder()
        .expect("Failed to install Prometheus recorder");

    // ── Configuration ──────────────────────────────────────────────────────
    let config = eidolon::config::Config::from_env()?;

    // ── Redis (with encryption key) ────────────────────────────────────────
    let redis = eidolon::state::RedisState::new(&config.redis, &config.security.encryption_key)
        .await
        .expect("Failed to connect to Redis");

    // ── HTTP Client (per-upstream pool tuning) ─────────────────────────────
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(10))
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .pool_max_idle_per_host(20)
        .build()
        .expect("Failed to create HTTP client");

    let state = std::sync::Arc::new(eidolon::state::AppState::new(
        redis,
        config.clone(),
        client,
    ));

    // ── NLP Engine (local files only — no network calls) ──────────────────
    if let Err(e) = eidolon::engine::nlp::NlpEngine::init(
        &config.nlp.model_path,
        &config.nlp.tokenizer_path,
    ) {
        tracing::warn!(
            "Failed to load NLP model: {}. PII redaction will rely on regex only.",
            e
        );
    }

    // ── Token-counting tokenizer (eagerly loaded from local file) ─────────
    if let Err(e) = eidolon::middleware::preflight::init_tokenizer(&config.nlp.tokenizer_path) {
        tracing::warn!(
            "Failed to load tokenizer for token counting: {}. Using char/4 fallback.",
            e
        );
    }

    // ── Router ────────────────────────────────────────────────────────────
    let app = eidolon::api::routes::app_router(state, metrics_handle).await;

    // ── Bind & serve ──────────────────────────────────────────────────────
    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
    let listener = TcpListener::bind(addr).await?;

    info!("Eidolon proxy listening on {}", addr);
    info!("Rate limit: {} req/s per IP (burst {})", config.rate_limit.requests_per_second, config.rate_limit.burst_size);
    info!("Fail-open mode: {}", config.security.fail_open);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received, draining connections...");
}
