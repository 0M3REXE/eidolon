use config::{Config as ConfigLoader, ConfigError, Environment, File};
use serde::Deserialize;

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
    #[serde(default = "default_false")]
    pub fail_open: bool,
    /// 32-character secret used for AES-256-GCM encryption of Redis PII values.
    /// Override via SECURITY__ENCRYPTION_KEY env var.
    pub encryption_key: String,
    /// Origins allowed for CORS. Empty = restrictive localhost-only default.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Bearer token required for `/v1/redact`. None = no auth (open).
    #[serde(default)]
    pub redact_api_token: Option<String>,
    /// Bearer token required for `/metrics`. None = open (backwards-compatible).
    #[serde(default)]
    pub metrics_token: Option<String>,
}

fn default_false() -> bool { false }

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyConfig {
    #[serde(default = "default_true")]
    pub redact_email: bool,
    #[serde(default = "default_true")]
    pub redact_cc: bool,
    #[serde(default = "default_true")]
    pub redact_ip: bool,
    #[serde(default = "default_true")]
    pub redact_ssn: bool,
    #[serde(default = "default_true")]
    pub redact_apikey: bool,
    #[serde(default = "default_true")]
    pub redact_phone: bool,
    #[serde(default = "default_true")]
    pub redact_ner_person: bool,
    #[serde(default = "default_true")]
    pub redact_ner_location: bool,
    #[serde(default = "default_true")]
    pub redact_ner_org: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            redact_email: true,
            redact_cc: true,
            redact_ip: true,
            redact_ssn: true,
            redact_apikey: true,
            redact_phone: true,
            redact_ner_person: true,
            redact_ner_location: true,
            redact_ner_org: true,
        }
    }
}

fn default_true() -> bool { true }

#[derive(Debug, Deserialize, Clone, Default)]
pub struct PromptInjectionConfig {
    #[serde(default)]
    pub model_path: Option<String>,
    #[serde(default)]
    pub tokenizer_path: Option<String>,
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
    /// Trust X-Forwarded-For / X-Real-IP for client IP extraction.
    /// Set to true only if behind a trusted reverse proxy.
    #[serde(default = "default_false")]
    pub trust_proxy: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct LimitsConfig {
    /// Maximum tokens allowed in a prompt. 0 = unlimited.
    #[serde(default)]
    pub max_prompt_tokens: usize,
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
    pub policy: PolicyConfig,
    #[serde(default)]
    pub shield: PromptInjectionConfig,
    #[serde(default)]
    pub custom: Vec<CustomPattern>,
    #[serde(default)]
    pub limits: LimitsConfig,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        // Fix 5.1: Search for config.toml in multiple locations:
        // 1. Next to the executable (for Docker / packaged deployments)
        // 2. Current working directory (for local development)
        // 3. /etc/eidolon/ (for system-wide installs)
        let mut builder = ConfigLoader::builder();

        let mut config_found = false;

        // Try executable's directory first
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let exe_config = exe_dir.join("config.toml");
                if exe_config.exists() {
                    builder = builder.add_source(File::from(exe_config));
                    config_found = true;
                }
            }
        }

        // Then try CWD (default behavior)
        if !config_found {
            let cwd_config = std::path::Path::new("config.toml");
            if cwd_config.exists() {
                builder = builder.add_source(File::with_name("config"));
                config_found = true;
            }
        }

        // Then try /etc/eidolon/ (Linux system-wide)
        #[cfg(unix)]
        if !config_found {
            let etc_config = std::path::Path::new("/etc/eidolon/config.toml");
            if etc_config.exists() {
                builder = builder.add_source(File::from(etc_config.to_path_buf()));
                config_found = true;
            }
        }

        // Fallback: try the default name (will error if not found)
        if !config_found {
            builder = builder.add_source(File::with_name("config"));
        }

        let s = builder
            .add_source(Environment::default().separator("__"))
            .build()?;

        s.try_deserialize()
    }
}
