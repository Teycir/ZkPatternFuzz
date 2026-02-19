use std::path::Path;

use chrono::{DateTime, Utc};

use crate::cli::ChainRunOptions;

pub(crate) struct ChainRunContext<'a> {
    pub output_dir: &'a Path,
    pub command: &'a str,
    pub run_id: &'a str,
    pub config_path: &'a str,
    pub campaign_name: &'a str,
    pub started_utc: DateTime<Utc>,
    pub timeout_seconds: Option<u64>,
}

impl<'a> ChainRunContext<'a> {
    pub(crate) fn from_options(
        output_dir: &'a Path,
        command: &'a str,
        run_id: &'a str,
        config_path: &'a str,
        campaign_name: &'a str,
        started_utc: DateTime<Utc>,
        options: &ChainRunOptions,
    ) -> Self {
        Self {
            output_dir,
            command,
            run_id,
            config_path,
            campaign_name,
            started_utc,
            timeout_seconds: Some(options.timeout),
        }
    }
}
