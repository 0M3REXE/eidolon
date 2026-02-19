use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Unknown error: {0}")]
    Unknown(#[from] anyhow::Error),

    #[error("Axum error: {0}")]
    Axum(#[from] axum::Error),

    #[error("NLP Engine error: {0}")]
    Nlp(String),

    #[error("Internal Server Error")]
    Internal,
    #[error("Bad Request: {0}")]
    BadRequest(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Config(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Config error: {}", e)),
            AppError::Redis(e) => (StatusCode::SERVICE_UNAVAILABLE, format!("Redis unavailable: {}", e)),
            AppError::Io(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("IO error: {}", e)),
            AppError::Network(e) => (StatusCode::BAD_GATEWAY, format!("Upstream error: {}", e)),
            AppError::Serialization(e) => (StatusCode::BAD_REQUEST, format!("Serialization error: {}", e)),
            AppError::Unknown(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Unknown error: {}", e)),
            AppError::Axum(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Axum error: {}", e)),
            AppError::Nlp(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("NLP error: {}", e)),
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
