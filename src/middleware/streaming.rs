use aho_corasick::AhoCorasick;
use std::sync::Arc;
use crate::state::AppState;

/// A streaming unredactor that replaces synthetic IDs with real PII in real time,
/// and then runs egress DLP scanning on hallucinated text.
pub struct StreamUnredactor {
    ac: Option<AhoCorasick>,
    pairs: Vec<(String, String)>,
    max_key_len: usize,
    buffer: String,
    state: Arc<AppState>,
}

impl StreamUnredactor {
    pub fn new(substitutions: Vec<(String, String)>, state: Arc<AppState>) -> Self {
        if substitutions.is_empty() {
            return Self {
                ac: None,
                pairs: vec![],
                max_key_len: 0,
                buffer: String::new(),
                state,
            };
        }

        let fakes: Vec<&str> = substitutions.iter().map(|(f, _)| f.as_str()).collect();
        let max_key_len = fakes.iter().map(|s| s.len()).max().unwrap_or(0);

        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(false)
            .build(fakes)
            .ok();

        Self { ac, pairs: substitutions, max_key_len, buffer: String::new(), state }
    }

    pub async fn process(&mut self, chunk: &str) -> String {
        self.buffer.push_str(chunk);

        // 1. Replace all complete matches in the buffer
        let replaced = if let Some(ac) = &self.ac {
            let reals: Vec<&str> = self.pairs.iter().map(|(_, r)| r.as_str()).collect();
            ac.replace_all(&self.buffer, &reals)
        } else {
            self.buffer.clone()
        };
        self.buffer = replaced;

        // 2. Determine safe_len (safe from synthetic ID splitting).
        let mut safe_len = self.buffer.len();
        if self.ac.is_some() {
            for (fake, _) in &self.pairs {
                let check_len = self.max_key_len.min(self.buffer.len());
                let tail = &self.buffer[self.buffer.len() - check_len..];
                for i in 0..tail.len() {
                    let suffix = &tail[i..];
                    if fake.starts_with(suffix) {
                        let match_start = self.buffer.len() - suffix.len();
                        if match_start < safe_len {
                            safe_len = match_start;
                        }
                        break;
                    }
                }
            }
        }

        // 3. To safely run regex on streams, we should also align safe_len to a word boundary
        // to prevent splitting hallucinated PII (e.g. an email address) in half.
        if safe_len > 0 && safe_len < self.buffer.len() {
            let prefix = &self.buffer[..safe_len];
            if let Some(last_ws) = prefix.rfind(|c: char| c.is_whitespace() || c == '\n') {
                safe_len = last_ws + 1; // Include the whitespace
            } else {
                // If it's a huge block of text without spaces, force break at 100 chars
                if safe_len > 100 {
                    safe_len -= 50; 
                } else {
                    return String::new(); // wait for more context
                }
            }
        }

        let mut to_emit = self.buffer[..safe_len].to_string();
        self.buffer = self.buffer[safe_len..].to_string();

        if to_emit.is_empty() {
            return String::new();
        }

        // 4. Egress DLP scan
        let mut protected = Vec::new();
        for (_fake, real) in &self.pairs {
            let id = format!("<PROTECTED_{}>", uuid::Uuid::new_v4());
            to_emit = to_emit.replace(real, &id);
            protected.push((id, real.clone()));
        }

        let mut dummy = Vec::new();
        let (mut sanitized, _, _) = crate::middleware::redaction::sanitize_text_pub(&to_emit, &self.state, &mut dummy)
            .await
            .unwrap_or((to_emit.clone(), vec![], std::collections::HashMap::new()));

        for (id, real) in protected {
            sanitized = sanitized.replace(&id, &real);
        }

        sanitized
    }

    pub async fn flush(&mut self) -> String {
        let mut to_emit = std::mem::take(&mut self.buffer);
        if to_emit.is_empty() {
            return String::new();
        }

        let mut protected = Vec::new();
        for (_fake, real) in &self.pairs {
            let id = format!("<PROTECTED_{}>", uuid::Uuid::new_v4());
            to_emit = to_emit.replace(real, &id);
            protected.push((id, real.clone()));
        }

        let mut dummy = Vec::new();
        let (mut sanitized, _, _) = crate::middleware::redaction::sanitize_text_pub(&to_emit, &self.state, &mut dummy)
            .await
            .unwrap_or((to_emit.clone(), vec![], std::collections::HashMap::new()));

        for (id, real) in protected {
            sanitized = sanitized.replace(&id, &real);
        }

        sanitized
    }
}
