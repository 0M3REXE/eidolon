use std::collections::HashMap;
use aho_corasick::AhoCorasick;

/// A streaming unredactor that replaces synthetic IDs with real PII in real time.
///
/// Uses Aho-Corasick for O(n) multi-pattern matching even with many substitution
/// keys. A small tail buffer is kept to handle tokens split across chunk boundaries.
pub struct StreamUnredactor {
    /// Pre-built Aho-Corasick automaton over the fake (synthetic) keys.
    ac: Option<AhoCorasick>,
    /// Ordered list of (fake, real) pairs matching the automaton's pattern order.
    pairs: Vec<(String, String)>,
    /// Max length of any fake key — determines the minimum safe-to-emit prefix.
    max_key_len: usize,
    /// Rolling buffer for incomplete tokens at chunk boundaries.
    buffer: String,
}

impl StreamUnredactor {
    pub fn new(substitutions: HashMap<String, String>) -> Self {
        if substitutions.is_empty() {
            return Self {
                ac: None,
                pairs: vec![],
                max_key_len: 0,
                buffer: String::new(),
            };
        }

        let pairs: Vec<(String, String)> = substitutions.into_iter().collect();
        let fakes: Vec<&str> = pairs.iter().map(|(f, _)| f.as_str()).collect();
        let max_key_len = fakes.iter().map(|s| s.len()).max().unwrap_or(0);

        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(false)
            .build(fakes)
            .ok();

        Self { ac, pairs, max_key_len, buffer: String::new() }
    }

    /// Process a new chunk of text and return the safe-to-emit portion with all
    /// complete synthetic IDs replaced by their real values.
    pub fn process(&mut self, chunk: &str) -> String {
        if self.ac.is_none() {
            return chunk.to_string();
        }

        self.buffer.push_str(chunk);

        // Replace all complete matches in the buffer using the Aho-Corasick automaton.
        let reals: Vec<&str> = self.pairs.iter().map(|(_, r)| r.as_str()).collect();
        let replaced = self.ac.as_ref().unwrap().replace_all(&self.buffer, &reals);
        self.buffer = replaced;

        // Determine how many bytes of the buffer are "safe" to emit — i.e., no
        // suffix of the buffer is a prefix of any fake key (partial match risk).
        let mut safe_len = self.buffer.len();

        for (fake, _) in &self.pairs {
            let check_len = self.max_key_len.min(self.buffer.len());
            let tail = &self.buffer[self.buffer.len() - check_len..];

            // Find the longest suffix of `tail` that is a prefix of `fake`.
            for i in 0..tail.len() {
                let suffix = &tail[i..];
                if fake.starts_with(suffix) {
                    let match_start = self.buffer.len() - suffix.len();
                    if match_start < safe_len {
                        safe_len = match_start;
                    }
                    break; // Longest suffix match found for this key.
                }
            }
        }

        let to_emit = self.buffer[..safe_len].to_string();
        self.buffer = self.buffer[safe_len..].to_string();
        to_emit
    }

    /// Flush remaining buffer at end of stream.
    pub fn flush(&mut self) -> String {
        // Any remaining content in the buffer is incomplete by definition, but
        // the stream has ended — emit it as-is (partial synthetic IDs are rare).
        std::mem::take(&mut self.buffer)
    }
}
