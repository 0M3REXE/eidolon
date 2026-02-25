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
//  Validates each octet is 0-255 instead of blindly matching any 1-3 digits.
pub static IPV4_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn ipv4_regex() -> &'static Regex {
    IPV4_REGEX.get_or_init(|| {
        Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ).expect("Invalid IPv4 Regex")
    })
}

// ── SSN ───────────────────────────────────────────────────────────────────
//  Matches US SSNs in both dashed (123-45-6789) and dashless (123456789)
//  formats, plus UK NINOs (AB123456C).
pub static SSN_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn ssn_regex() -> &'static Regex {
    SSN_REGEX.get_or_init(|| {
        Regex::new(concat!(
            r"(?:",
            r"\b\d{3}-\d{2}-\d{4}\b",             // US SSN dashed
            r"|\b\d{9}\b",                          // US SSN dashless
            r"|\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b", // UK NINO
            r")",
        )).expect("Invalid SSN Regex")
    })
}

// ── Phone Number ─────────────────────────────────────────────────────────
//  Catches common phone formats: +1-234-567-8901, (234) 567-8901, etc.
pub static PHONE_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn phone_regex() -> &'static Regex {
    PHONE_REGEX.get_or_init(|| {
        Regex::new(concat!(
            r"(?:",
            r"\+?\d{1,3}[-.\s]?\(?\d{2,3}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}",  // international
            r"|\(\d{3}\)\s?\d{3}[-.\s]?\d{4}",                              // (xxx) xxx-xxxx
            r")",
        )).expect("Invalid Phone Regex")
    })
}

// ── API Key ───────────────────────────────────────────────────────────────
//  Covers well-known prefixed key/token formats across major providers.
//  Each alternative is anchored to a distinctive prefix to minimise false
//  positives while catching the vast majority of real-world keys.
pub static API_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn api_key_regex() -> &'static Regex {
    API_KEY_REGEX.get_or_init(|| {
        Regex::new(concat!(
            r"(?:",
            // ── OpenAI ──────────────────────────────────────────────
            r"sk-[a-zA-Z0-9]{20,}",                         // classic sk-…
            r"|sk-proj-[a-zA-Z0-9_-]{20,}",                  // project-scoped
            // ── AWS ─────────────────────────────────────────────────
            r"|AKIA[0-9A-Z]{16}",                            // access-key-id
            // ── GitHub ──────────────────────────────────────────────
            r"|ghp_[a-zA-Z0-9]{36}",                         // personal access
            r"|gho_[a-zA-Z0-9]{36}",                         // OAuth
            r"|ghs_[a-zA-Z0-9]{36}",                         // app installation
            r"|ghr_[a-zA-Z0-9]{36}",                         // refresh
            r"|github_pat_[a-zA-Z0-9_]{22,}",                // fine-grained PAT
            // ── GitLab ──────────────────────────────────────────────
            r"|glpat-[a-zA-Z0-9_-]{20,}",                    // personal access
            // ── Stripe ──────────────────────────────────────────────
            r"|[spr]k_(?:live|test)_[a-zA-Z0-9]{10,}",       // secret / public / restricted
            // ── Slack ───────────────────────────────────────────────
            r"|xox[bpsar]-[a-zA-Z0-9-]{10,}",                // bot / user / app tokens
            // ── Google Cloud ────────────────────────────────────────
            r"|AIza[0-9A-Za-z_-]{35}",                       // API key
            // ── Twilio ──────────────────────────────────────────────
            r"|SK[0-9a-fA-F]{32}",                           // API key SID
            // ── SendGrid ────────────────────────────────────────────
            r"|SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{22,}", // API key
            // ── Mailgun ─────────────────────────────────────────────
            r"|key-[a-zA-Z0-9]{32}",                         // API key
            // ── npm ─────────────────────────────────────────────────
            r"|npm_[a-zA-Z0-9]{36}",                         // access token
            // ── PyPI ────────────────────────────────────────────────
            r"|pypi-[a-zA-Z0-9_-]{16,}",                     // API token
            r")",
        ))
        .expect("Invalid API Key Regex")
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
        assert!(re.is_match("255.255.255.255"));
        assert!(re.is_match("0.0.0.0"));
        assert!(!re.is_match("192.168.1"));     // incomplete
        assert!(!re.is_match("999.999.999.999")); // invalid octets
        assert!(!re.is_match("256.1.1.1"));       // octet > 255
    }

    #[test]
    fn test_ssn_regex() {
        let re = ssn_regex();
        // US dashed
        assert!(re.is_match("123-45-6789"));
        // US dashless
        assert!(re.is_match("123456789"));
        // UK NINO
        assert!(re.is_match("AB123456C"));
        // Should NOT match
        assert!(!re.is_match("123-45-678"));  // too short
        assert!(!re.is_match("12345678"));    // 8 digits
    }

    #[test]
    fn test_phone_regex() {
        let re = phone_regex();
        assert!(re.is_match("+1-234-567-8901"));
        assert!(re.is_match("(234) 567-8901"));
        assert!(re.is_match("+44 20 7946 0958"));
        assert!(!re.is_match("12345"));          // too short
    }

    #[test]
    fn test_api_key_regex() {
        let re = api_key_regex();

        // ── Should match ────────────────────────────────────────────
        // OpenAI
        assert!(re.is_match("sk-1234567890abcdef1234567890abcdef"));
        assert!(re.is_match("sk-proj-abc123_def456_ghi789xyz"));
        // AWS
        assert!(re.is_match("AKIA1234567890ABCDEF"));
        // GitHub
        assert!(re.is_match("ghp_ABCDEFghijklmnopqrstuvwxyz1234567890"));
        assert!(re.is_match("ghs_ABCDEFghijklmnopqrstuvwxyz1234567890"));
        assert!(re.is_match("github_pat_AAAAAA_BBBBBBBBBBBBBBBBBBBBBBBB"));
        // GitLab
        assert!(re.is_match("glpat-abcdefghijklmnopqrstuvwx"));
        // Stripe
        assert!(re.is_match("sk_live_abcdefghij1234567890"));
        assert!(re.is_match("pk_test_abcdefghij1234567890"));
        // Slack
        assert!(re.is_match("xoxb-1234-5678-abcdef"));
        assert!(re.is_match("xoxp-1234-5678-abcdef"));
        // Google Cloud
        assert!(re.is_match("AIzaSyA1234567890abcdefghijklmnopqrstuv"));
        // Twilio
        assert!(re.is_match("SKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        // SendGrid
        assert!(re.is_match("SG.abcdefghijklmnopqrstuv_.ABCDEFghijklmnopqrstuvwxyz"));
        // Mailgun
        assert!(re.is_match("key-1234567890abcdef1234567890abcdef"));
        // npm
        assert!(re.is_match("npm_abcdefghijklmnopqrstuvwxyz1234567890"));
        // PyPI
        assert!(re.is_match("pypi-abcdefghijklmnop"));

        // ── Should NOT match ────────────────────────────────────────
        assert!(!re.is_match("sk-short"));           // too short
        assert!(!re.is_match("randomgarbage"));       // no recognised prefix
        assert!(!re.is_match("ghp_tooshort"));        // wrong length
    }
}
