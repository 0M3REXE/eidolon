use aho_corasick::AhoCorasick;
use std::sync::Arc;
use crate::state::AppState;

const STREAMLIT_BREAK_CHARS: usize = 100;
const STREAMLIT_BACKOFF_CHARS: usize = 50;

#[derive(Clone)]
struct ProtectedId {
    id: String,
    real: String,
}

impl ProtectedId {
    fn new(real: String) -> Self {
        Self {
            id: format!("<PROTECTED_{}>", uuid::Uuid::new_v4()),
            real,
        }
    }
}

pub struct StreamUnredactor {
    ac: Option<AhoCorasick>,
    pairs: Vec<(String, String)>,
    protected_ids: Vec<ProtectedId>,
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
                protected_ids: vec![],
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

        let protected_ids: Vec<ProtectedId> = substitutions
            .iter()
            .map(|(_, real)| ProtectedId::new(real.clone()))
            .collect();

        Self {
            ac,
            pairs: substitutions,
            protected_ids,
            max_key_len,
            buffer: String::new(),
            state,
        }
    }

    pub async fn process(&mut self, chunk: &str) -> String {
        self.buffer.push_str(chunk);

        let replaced = if let Some(ac) = &self.ac {
            let reals: Vec<&str> = self.pairs.iter().map(|(_, r)| r.as_str()).collect();
            ac.replace_all(&self.buffer, &reals)
        } else {
            self.buffer.clone()
        };
        self.buffer = replaced;

        let mut safe_len = self.buffer.len();
        if self.ac.is_some() {
            for (fake, _) in &self.pairs {
                let check_len = self.max_key_len.min(self.buffer.len());
                if check_len == 0 {
                    continue;
                }
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

        if safe_len > 0 && safe_len < self.buffer.len() {
            let prefix = &self.buffer[..safe_len];
            if let Some(last_ws) = prefix.rfind(|c: char| c.is_whitespace() || c == '\n') {
                safe_len = last_ws + 1;
            } else if safe_len > STREAMLIT_BREAK_CHARS {
                safe_len -= STREAMLIT_BACKOFF_CHARS;
            } else {
                return String::new();
            }
        }

        let mut to_emit = self.buffer[..safe_len].to_string();
        self.buffer = self.buffer[safe_len..].to_string();

        if to_emit.is_empty() {
            return String::new();
        }

        for protected in &self.protected_ids {
            to_emit = to_emit.replace(&protected.real, &protected.id);
        }

        let mut sanitized = crate::middleware::redaction::sanitize_text_regex_only(&to_emit, &self.state.config);

        for protected in &self.protected_ids {
            sanitized = sanitized.replace(&protected.id, &protected.real);
        }

        sanitized
    }

    pub async fn flush(&mut self) -> String {
        let mut to_emit = std::mem::take(&mut self.buffer);
        if to_emit.is_empty() {
            return String::new();
        }

        for protected in &self.protected_ids {
            to_emit = to_emit.replace(&protected.real, &protected.id);
        }

        let mut sanitized = crate::middleware::redaction::sanitize_text_regex_only(&to_emit, &self.state.config);

        for protected in &self.protected_ids {
            sanitized = sanitized.replace(&protected.id, &protected.real);
        }

        sanitized
    }
}