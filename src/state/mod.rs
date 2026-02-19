pub mod redis;

pub use self::redis::RedisState;
use crate::config::Config;
use std::sync::Arc;

use regex::Regex;

#[derive(Clone)]
pub struct AppState {
    pub redis: RedisState,
    pub config: Arc<Config>,
    pub client: reqwest::Client,
    pub custom_regexes: Arc<Vec<(String, Regex)>>,
}

impl AppState {
    pub fn new(redis: RedisState, config: Config, client: reqwest::Client) -> Self {
        let mut custom_regexes = Vec::new();
        for pattern in &config.custom {
            match Regex::new(&pattern.regex) {
                Ok(re) => custom_regexes.push((pattern.name.clone(), re)),
                Err(e) => {
                    tracing::warn!("Failed to compile custom regex '{}': {}", pattern.name, e);
                }
            }
        }

        Self {
            redis,
            config: Arc::new(config),
            client,
            custom_regexes: Arc::new(custom_regexes),
        }
    }
}
