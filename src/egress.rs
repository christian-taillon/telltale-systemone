//! Fail-closed check before projection text leaves the host.
//!
//! Telltale redacts before projection; this is a second, deliberately small
//! net for high-confidence credential shapes. It is not a redaction system and
//! does not rewrite text: a hit means the request is not sent. Broader
//! deterministic detection belongs in Token Guard
//! (<https://christiant.io/token_guard>).

use std::sync::OnceLock;

use regex::Regex;

const PATTERNS: &[(&str, &str)] = &[
    ("private_key", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    ("aws_access_key_id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    (
        "github_token",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b",
    ),
    (
        "provider_api_key",
        r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}",
    ),
    ("slack_token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    ),
];

fn compiled() -> &'static [(&'static str, Regex)] {
    static CELL: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    CELL.get_or_init(|| {
        PATTERNS
            .iter()
            .map(|(id, pattern)| (*id, Regex::new(pattern).expect("static pattern compiles")))
            .collect()
    })
}

/// Returns the first matching pattern ID, if any.
pub fn scan(text: &str) -> Option<&'static str> {
    compiled()
        .iter()
        .find(|(_, re)| re.is_match(text))
        .map(|(id, _)| *id)
}

#[cfg(test)]
mod tests {
    use super::scan;

    #[test]
    fn blocks_high_confidence_shapes_only() {
        assert_eq!(
            scan("cat <<EOF\n-----BEGIN OPENSSH PRIVATE KEY-----"),
            Some("private_key")
        );
        assert_eq!(
            scan("export AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF"),
            Some("aws_access_key_id")
        );
        assert_eq!(
            scan(&format!("token ghp_{}", "a".repeat(36))),
            Some("github_token")
        );
        assert_eq!(
            scan(&format!("sk-ant-{}", "b".repeat(40))),
            Some("provider_api_key")
        );
        assert_eq!(scan("git commit -m 'skip ci'"), None);
        assert_eq!(scan("npm install left-pad@1.3.0"), None);
        assert_eq!(scan("[REDACTED:api_key]"), None);
    }
}
