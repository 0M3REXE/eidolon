use crate::config::RedisConfig;
use crate::utils::crypto::{decrypt_pii, encrypt_pii, hash_input};
use redis::{aio::ConnectionManager, AsyncCommands, Client, RedisError};
use anyhow::Result;
use tracing::{error, info};

/// Redis state: holds a multiplexed connection manager and the AES-256-GCM key
/// used to encrypt PII values at rest.
#[derive(Clone)]
pub struct RedisState {
    conn_manager: ConnectionManager,
    ttl_seconds: usize,
    /// Encryption key for PII values stored in Redis.
    encryption_key: String,
}

impl RedisState {
    pub async fn new(config: &RedisConfig, encryption_key: &str) -> Result<Self> {
        let log_url = if let Some((auth, rest)) = config.url.rsplit_once('@') {
            if let Some((scheme, _)) = auth.split_once("://") {
                format!("{}://***:***@{}", scheme, rest)
            } else {
                "***redacted***".to_string()
            }
        } else {
            config.url.clone()
        };
        info!("Connecting to Redis at {}", log_url);
        let client = Client::open(config.url.as_str())?;

        let conn_manager = client.get_connection_manager().await.map_err(|e| {
            error!("Failed to connect to Redis connection manager: {}", e);
            e
        })?;

        info!("Redis connection established");
        Ok(Self {
            conn_manager,
            ttl_seconds: config.ttl_seconds as usize,
            encryption_key: encryption_key.to_string(),
        })
    }

    /// Low-level helper: returns a clone of the connection manager.
    /// All operations use this single multiplexed path.
    fn conn(&self) -> ConnectionManager {
        self.conn_manager.clone()
    }

    // ── Bidirectional mapping (forward: synthetic → real, reverse: hash → synthetic) ──

    /// Stores an encrypted bidirectional mapping.
    ///
    /// * Forward key  : `synthetic_id`            → encrypted(real_data)
    /// * Reverse key  : `rev:{sha256(real_data)}`  → synthetic_id (no PII in key)
    pub async fn save_bidirectional_mapping(&self, synthetic_id: &str, real_data: &str) -> Result<()> {
        let mut conn = self.conn();

        // Encrypt PII before writing to Redis.
        let encrypted_value = encrypt_pii(real_data, &self.encryption_key)?;

        // 1. Synthetic → Encrypted real PII
        let _: () = conn.set_ex(synthetic_id, &encrypted_value, self.ttl_seconds as u64).await?;

        // 2. Reverse: hash(real) → synthetic_id  (no PII in key or value)
        let rev_key = format!("rev:{}", hash_input(real_data));
        let _: () = conn.set_ex(rev_key, synthetic_id, self.ttl_seconds as u64).await?;

        Ok(())
    }

    /// Returns the *decrypted* real PII for a given synthetic ID, or `None` if
    /// the key does not exist (expired or never created).
    pub async fn get_mapping(&self, synthetic_id: &str) -> std::result::Result<Option<String>, RedisError> {
        let mut conn = self.conn();
        let raw: Option<String> = conn.get(synthetic_id).await?;
        match raw {
            None => Ok(None),
            Some(ciphertext) => {
                match decrypt_pii(&ciphertext, &self.encryption_key) {
                    Ok(plaintext) => Ok(Some(plaintext)),
                    Err(e) => {
                        error!("Failed to decrypt Redis value for key '{}': {}", synthetic_id, e);
                        Ok(None) // Treat decryption failure as a cache miss
                    }
                }
            }
        }
    }

    /// Looks up the synthetic ID for a given real PII value (reverse mapping).
    pub async fn get_synthetic_mapping(&self, real_data: &str) -> std::result::Result<Option<String>, RedisError> {
        let mut conn = self.conn();
        let rev_key = format!("rev:{}", hash_input(real_data));
        conn.get(rev_key).await
    }

    // ── Legacy single-direction mapping (kept for compatibility) ──────────────

    pub async fn save_mapping(&self, synthetic_id: &str, real_data: &str) -> Result<()> {
        self.save_bidirectional_mapping(synthetic_id, real_data).await
    }

    // ── Health ────────────────────────────────────────────────────────────────

    pub async fn ping(&self) -> std::result::Result<(), RedisError> {
        let mut conn = self.conn();
        redis::cmd("PING").query_async(&mut conn).await
    }
}
