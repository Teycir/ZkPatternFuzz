//! AI context construction and redaction helpers.

use crate::config::FuzzConfig;
use regex::Regex;
use sha2::{Digest, Sha256};

const DEFAULT_SOURCE_PREVIEW_MAX_CHARS: usize = 1024;
const MIN_SOURCE_PREVIEW_MAX_CHARS: usize = 128;
const MAX_SOURCE_PREVIEW_MAX_CHARS: usize = 16_384;

const AI_INCLUDE_SOURCE_ENV: &str = "ZKF_AI_INCLUDE_CIRCUIT_SOURCE";
const AI_SOURCE_MAX_CHARS_ENV: &str = "ZKF_AI_CIRCUIT_SOURCE_MAX_CHARS";

#[derive(Debug, Clone, Copy)]
pub struct AICircuitContextOptions {
    pub include_circuit_source: bool,
    pub source_preview_max_chars: usize,
}

impl Default for AICircuitContextOptions {
    fn default() -> Self {
        Self {
            include_circuit_source: false,
            source_preview_max_chars: DEFAULT_SOURCE_PREVIEW_MAX_CHARS,
        }
    }
}

impl AICircuitContextOptions {
    pub fn from_env() -> Self {
        let include_circuit_source = std::env::var(AI_INCLUDE_SOURCE_ENV)
            .ok()
            .map(|raw| {
                matches!(
                    raw.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        let source_preview_max_chars = std::env::var(AI_SOURCE_MAX_CHARS_ENV)
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(DEFAULT_SOURCE_PREVIEW_MAX_CHARS)
            .clamp(MIN_SOURCE_PREVIEW_MAX_CHARS, MAX_SOURCE_PREVIEW_MAX_CHARS);
        Self {
            include_circuit_source,
            source_preview_max_chars,
        }
    }
}

pub fn build_ai_circuit_context(config: &FuzzConfig) -> String {
    build_ai_circuit_context_with_options(config, AICircuitContextOptions::from_env())
}

pub fn build_ai_circuit_context_with_options(
    config: &FuzzConfig,
    options: AICircuitContextOptions,
) -> String {
    let attack_types = config
        .attacks
        .iter()
        .map(|attack| format!("{:?}", attack.attack_type))
        .collect::<Vec<_>>()
        .join(", ");
    let input_names = config
        .inputs
        .iter()
        .map(|input| input.name.clone())
        .collect::<Vec<_>>()
        .join(", ");

    let source = std::fs::read_to_string(&config.campaign.target.circuit_path).ok();
    let source_available = source.is_some();
    let source_bytes = source.as_ref().map_or(0usize, |raw| raw.len());
    let source_lines = source.as_ref().map_or(0usize, |raw| raw.lines().count());
    let source_sha256 = source
        .as_ref()
        .map(|raw| format!("{:x}", Sha256::digest(raw.as_bytes())))
        .unwrap_or_else(|| "unavailable".to_string());

    let source_preview_included = source_available && options.include_circuit_source;
    let preview = if source_preview_included {
        source
            .as_ref()
            .map(|raw| {
                redact_sensitive_text(&truncate_chars(raw, options.source_preview_max_chars))
            })
            .unwrap_or_else(|| "<circuit source unavailable>".to_string())
    } else {
        format!(
            "<omitted_by_default; set {}=1 to include preview>",
            AI_INCLUDE_SOURCE_ENV
        )
    };

    let context = format!(
        "campaign={}\nframework={:?}\ncircuit_path={}\nmain_component={}\nattacks=[{}]\ninputs=[{}]\nsource_available={}\nsource_bytes={}\nsource_lines={}\nsource_sha256={}\nsource_preview_included={}\n\ncircuit_preview:\n{}",
        config.campaign.name,
        config.campaign.target.framework,
        config.campaign.target.circuit_path.display(),
        config.campaign.target.main_component,
        attack_types,
        input_names,
        source_available,
        source_bytes,
        source_lines,
        source_sha256,
        source_preview_included,
        preview
    );

    redact_sensitive_text(&context)
}

pub fn redact_sensitive_text(input: &str) -> String {
    let patterns: [(&str, &str); 3] = [
        (
            r#"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password)\b(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;]+)"#,
            "$1$2<redacted>",
        ),
        (
            r#"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"#,
            "$1<redacted>",
        ),
        (
            r#"(?i)([?&](?:api[_-]?key|token|secret|password)=)[^&\s]+"#,
            "$1<redacted>",
        ),
    ];

    patterns.iter().fold(
        input.to_string(),
        |acc, (pattern, replacement)| match Regex::new(pattern) {
            Ok(re) => re.replace_all(&acc, *replacement).into_owned(),
            Err(_) => acc,
        },
    )
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }

    let mut out = String::new();
    for (idx, ch) in value.chars().enumerate() {
        if idx >= max_chars {
            break;
        }
        out.push(ch);
    }
    out.push_str("\n...[truncated]");
    out
}
