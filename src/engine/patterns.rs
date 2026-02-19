use regex::Regex;
use std::sync::OnceLock;

// ── Email ──────────────────────────────────────────────────────────────────
pub static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn email_regex() -> &'static Regex {
    EMAIL_REGEX.get_or_init(|| {
        Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").expect("Invalid Email Regex")
    })
}

// ── Credit Card ───────────────────────────────────────────────────────────
pub static CREDIT_CARD_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn credit_card_regex() -> &'static Regex {
    CREDIT_CARD_REGEX.get_or_init(|| {
        Regex::new(r"\b(?:\d[ -]*?){13,16}\b").expect("Invalid Credit Card Regex")
    })
}

/// Luhn algorithm — returns true if the digit string passes the checksum.
/// Strips spaces and dashes before validation.
pub fn luhn_check(number: &str) -> bool {
    let digits: Vec<u8> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c as u8 - b'0')
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = (d * 2) as u32;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d as u32
            }
        })
        .sum();

    sum % 10 == 0
}

// ── IPv4 ──────────────────────────────────────────────────────────────────
pub static IPV4_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn ipv4_regex() -> &'static Regex {
    IPV4_REGEX.get_or_init(|| {
        Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").expect("Invalid IPv4 Regex")
    })
}

// ── SSN ───────────────────────────────────────────────────────────────────
pub static SSN_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn ssn_regex() -> &'static Regex {
    SSN_REGEX.get_or_init(|| {
        Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("Invalid SSN Regex")
    })
}

// ── API Key ───────────────────────────────────────────────────────────────
pub static API_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn api_key_regex() -> &'static Regex {
    API_KEY_REGEX.get_or_init(|| {
        Regex::new(r"(?i)(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})").expect("Invalid API Key Regex")
    })
}

// ── Synthetic ID ─────────────────────────────────────────────────────────
pub static SYNTHETIC_ID_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn synthetic_id_regex() -> &'static Regex {
    SYNTHETIC_ID_REGEX.get_or_init(|| {
        Regex::new(r"(EMAIL|CC|IP|SSN|APIKEY)_[a-f0-9]{8}").expect("Invalid Synthetic ID Regex")
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_regex() {
        let re = email_regex();
        assert!(re.is_match("test@example.com"));
        assert!(re.is_match("user.name+tag@domain.co.uk"));
        assert!(!re.is_match("invalid-email"));
        assert!(!re.is_match("@domain.com"));
    }

    #[test]
    fn test_credit_card_regex() {
        let re = credit_card_regex();
        assert!(re.is_match("1234-5678-9012-3456"));
        assert!(re.is_match("1234567890123456"));
        assert!(!re.is_match("1234-5678"));
    }

    #[test]
    fn test_luhn_valid() {
        // Visa test number
        assert!(luhn_check("4532015112830366"));
        // Mastercard test number
        assert!(luhn_check("5425233430109903"));
        // Amex test number (15-digit)
        assert!(luhn_check("378282246310005"));
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!luhn_check("1234567890123456")); // random digits, fails Luhn
        assert!(!luhn_check("123-45-6789"));       // SSN format, too short and invalid
        assert!(!luhn_check("55555"));             // too short
    }

    #[test]
    fn test_ipv4_regex() {
        let re = ipv4_regex();
        assert!(re.is_match("192.168.1.1"));
        assert!(re.is_match("10.0.0.1"));
        assert!(!re.is_match("192.168.1"));
    }

    #[test]
    fn test_ssn_regex() {
        let re = ssn_regex();
        assert!(re.is_match("123-45-6789"));
        assert!(!re.is_match("123-45-678"));
    }

    #[test]
    fn test_api_key_regex() {
        let re = api_key_regex();
        assert!(re.is_match("sk-1234567890abcdef1234567890abcdef"));
        assert!(re.is_match("AKIA1234567890ABCDEF"));
        assert!(!re.is_match("sk-short"));
    }
}
