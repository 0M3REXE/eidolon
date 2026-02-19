use config::{Config as ConfigLoader, ConfigError, Environment, File};
use serde::Deserialize;
use std::env;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub port: u16,
    pub host: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RedisConfig {
    pub url: String,
    pub ttl_seconds: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub fail_open: bool,
    /// 32-character secret used for AES-256-GCM encryption of Redis PII values.
    /// Override via SECURITY__ENCRYPTION_KEY env var.
    pub encryption_key: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OllamaConfig {
    pub base_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    /// Sustained requests per second per IP address.
    pub requests_per_second: u64,
    /// Burst capacity above the sustained rate.
    pub burst_size: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NlpConfig {
    /// Path to the ONNX NER model (e.g. "assets/bert-ner-quantized.onnx").
    pub model_path: String,
    /// Path to the HuggingFace tokenizer JSON (e.g. "assets/tokenizer.json").
    pub tokenizer_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CustomPattern {
    pub name: String,
    pub regex: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub redis: RedisConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    pub ollama: OllamaConfig,
    pub rate_limit: RateLimitConfig,
    pub nlp: NlpConfig,
    #[serde(default)]
    pub custom: Vec<CustomPattern>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let _run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());

        let s = ConfigLoader::builder()
            .add_source(File::with_name("config"))
            .add_source(Environment::default().separator("__"))
            .build()?;

        s.try_deserialize()
    }
}
