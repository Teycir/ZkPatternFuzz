use chrono::Utc;
use std::path::Path;

pub(crate) fn sanitize_slug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed
    }
}

fn derive_campaign_slug(campaign_path: &str) -> String {
    let slug = Path::new(campaign_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(sanitize_slug);
    match slug {
        Some(value) => value,
        None => "campaign".to_string(),
    }
}

pub(crate) fn make_run_id(command: &str, campaign_path: Option<&str>) -> String {
    let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let pid = std::process::id();
    let campaign = match campaign_path {
        Some(path) => derive_campaign_slug(path),
        None => "no_campaign".to_string(),
    };
    format!("{}_{}_{}_pid{}", ts, sanitize_slug(command), campaign, pid)
}
