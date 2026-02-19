use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use sha2::{Sha256, Digest};

// ── Synthetic ID (deterministic hash-based) ────────────────────────────────

/// Generates a deterministic, short synthetic ID from the given input and a
/// category prefix.  The output looks like `EMAIL_a1b2c3d4`.
pub fn generate_synthetic_id(input: &str, prefix: &str) -> String {
    let hash_hex = hex::encode(&sha256_bytes(input)[..4]);
    format!("{}_{}", prefix, hash_hex)
}

/// SHA-256 of `input` returned as a hex string.
pub fn hash_input(input: &str) -> String {
    hex::encode(sha256_bytes(input))
}

fn sha256_bytes(input: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}

// ── AES-256-GCM at-rest encryption ────────────────────────────────────────

/// Encrypts `plaintext` with AES-256-GCM using the supplied 32-byte key
/// (padded/truncated if shorter/longer).
///
/// Output format: `<12-byte nonce hex><ciphertext hex>`  — stored as a plain
/// ASCII hex string in Redis.
pub fn encrypt_pii(plaintext: &str, key_str: &str) -> anyhow::Result<String> {
    let key = derive_key(key_str);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encrypt failed: {e}"))?;

    // Encode nonce + ciphertext as hex so the Redis value is ASCII-safe.
    let mut encoded = hex::encode(nonce);
    encoded.push_str(&hex::encode(&ciphertext));
    Ok(encoded)
}

/// Decrypts a value produced by [`encrypt_pii`].
pub fn decrypt_pii(encoded: &str, key_str: &str) -> anyhow::Result<String> {
    if encoded.len() < 24 {
        anyhow::bail!("Ciphertext too short");
    }
    // First 24 hex chars = 12 bytes nonce.
    let nonce_bytes = hex::decode(&encoded[..24])
        .map_err(|e| anyhow::anyhow!("Nonce decode failed: {e}"))?;
    let ct_bytes = hex::decode(&encoded[24..])
        .map_err(|e| anyhow::anyhow!("Ciphertext decode failed: {e}"))?;

    let key = derive_key(key_str);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ct_bytes.as_ref())
        .map_err(|e| anyhow::anyhow!("Decrypt failed: {e}"))?;

    String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("UTF-8 error: {e}"))
}

/// Derives a 32-byte key from an arbitrary-length string by SHA-256 hashing.
fn derive_key(key_str: &str) -> [u8; 32] {
    let hash = sha256_bytes(key_str);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    key
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = "test-key-32-chars-padding-padded";
        let plaintext = "john.doe@example.com";
        let encrypted = encrypt_pii(plaintext, key).unwrap();
        let decrypted = decrypt_pii(&encrypted, key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_encryptions_are_unique() {
        // AES-GCM uses a random nonce, so the same plaintext encrypted twice
        // should produce different ciphertexts.
        let key = "test-key-32-chars-padding-padded";
        let pt = "john.doe@example.com";
        let e1 = encrypt_pii(pt, key).unwrap();
        let e2 = encrypt_pii(pt, key).unwrap();
        assert_ne!(e1, e2, "Same plaintext should produce different ciphertexts (random nonce)");
    }

    #[test]
    fn test_generate_synthetic_id() {
        let id = generate_synthetic_id("test@example.com", "EMAIL");
        assert!(id.starts_with("EMAIL_"));
        assert_eq!(id.len(), "EMAIL_".len() + 8);
    }
}
