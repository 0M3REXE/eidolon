use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Tracing ────────────────────────────────────────────────────────────
    let format = std::env::var("LOGGING__FORMAT").ok().unwrap_or_else(|| "text".to_string());
    let filter = tracing_subscriber::EnvFilter::new(
        std::env::var("RUST_LOG").ok().unwrap_or_else(|| "eidolon=debug,tower_http=debug".into()),
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

    // ── Security sanity check — refuse to start with known-weak key ──────────
    const KNOWN_DEFAULT_KEY: &str = "change-me-to-32-char-secret-!!!!";
    const MIN_KEY_LEN: usize = 32;
    if config.security.encryption_key == KNOWN_DEFAULT_KEY {
        tracing::error!(
            "FATAL: encryption_key is still set to the default value. \
             All PII in Redis would be encrypted with a publicly known key. \
             Set SECURITY__ENCRYPTION_KEY to a strong {MIN_KEY_LEN}+ character secret."
        );
        std::process::exit(1);
    }
    if config.security.encryption_key.len() < MIN_KEY_LEN {
        tracing::error!(
            "FATAL: encryption_key is only {} characters (minimum {}). \
             PII encryption requires a strong key.",
            config.security.encryption_key.len(),
            MIN_KEY_LEN
        );
        std::process::exit(1);
    }

    // ── HTTP Client (per-upstream pool tuning) ─────────────────────────────
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(10))
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .pool_max_idle_per_host(20)
        .build()
        .expect("Failed to create HTTP client");

    let state = std::sync::Arc::new(eidolon::state::AppState::new(
        eidolon::state::RedisState::new(&config.redis, &config.security.encryption_key)
            .await
            .expect("Failed to connect to Redis"),
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

    // ── Shield Engine ────────────────────────────────────────────────────────
    if let (Some(model_path), Some(tokenizer_path)) = (&config.shield.model_path, &config.shield.tokenizer_path) {
        if let Err(e) = eidolon::engine::shield_model::ShieldEngine::init(model_path, tokenizer_path) {
            tracing::warn!(
                "Failed to load Shield ML model: {}. Shielding will fall back to regex only.",
                e
            );
        }
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
    let host: std::net::IpAddr = config.server.host.parse().unwrap_or_else(|_| [0, 0, 0, 0].into());
    let addr = SocketAddr::from((host, config.server.port));
    let listener = TcpListener::bind(addr).await?;

    info!("Eidolon proxy listening on {}", addr);
    info!("Rate limit: {} req/s per IP (burst {})", config.rate_limit.requests_per_second, config.rate_limit.burst_size);
    info!("Fail-open mode: {}", config.security.fail_open);

    const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    let shutdown = shutdown_signal();
    let server = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown);

    if timeout(SHUTDOWN_TIMEOUT, server).await.is_err() {
        tracing::warn!("Server shutdown timed out after {}s — forcing exit.", SHUTDOWN_TIMEOUT.as_secs());
    } else {
        info!("Graceful shutdown complete.");
    }

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