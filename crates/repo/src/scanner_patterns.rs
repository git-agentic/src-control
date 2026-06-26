//! Compile-time secret-detection patterns. Reviewed at PR time, never loaded at
//! runtime. High precision over recall — the entropy detector handles recall.

/// One detection pattern.
pub struct Pattern {
    pub name: &'static str,
    pub regex: &'static str,
    pub description: &'static str,
}

/// The active pattern set. Each regex is high-precision (low false-positive).
pub const PATTERNS: &[Pattern] = &[
    Pattern { name: "github_pat", regex: r"gh[posr]_[A-Za-z0-9_]{36,}", description: "GitHub personal access token" },
    Pattern { name: "aws_access_key", regex: r"AKIA[0-9A-Z]{16}", description: "AWS access key id" },
    Pattern { name: "anthropic_api_key", regex: r"sk-ant-(?:api|admin)[A-Za-z0-9_-]{20,}", description: "Anthropic API key" },
    Pattern { name: "openai_api_key", regex: r"sk-(?:proj-)?[A-Za-z0-9]{40,}", description: "OpenAI API key" },
    Pattern { name: "stripe_live", regex: r"(?:sk|pk)_live_[A-Za-z0-9]{20,}", description: "Stripe live key" },
    Pattern { name: "gcp_service_account", regex: r#""type"\s*:\s*"service_account""#, description: "GCP service-account JSON marker" },
    Pattern { name: "private_key_pem", regex: r"-----BEGIN [A-Z ]*PRIVATE KEY-----", description: "PEM private-key header" },
];
