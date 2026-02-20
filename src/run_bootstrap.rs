use chrono::{DateTime, Utc};
use zk_fuzzer::config::{apply_profile, FuzzConfig, ProfileName};

use crate::run_lifecycle::{write_failed_run_artifact_with_error, FailedRunArtifactErrorContext};
use crate::scan_output::apply_scan_output_suffix_if_present;
use crate::set_run_log_context_for_campaign;

pub(crate) fn announce_report_dir_and_bind_log_context(
    dry_run: bool,
    run_id: &str,
    command: &str,
    config_path: &str,
    started_utc: &DateTime<Utc>,
) {
    let report_dir = crate::engagement_root_dir(run_id);
    tracing::info!("Report directory: {}", report_dir.display());

    // Put `session.log` under the engagement folder from the very start (even if YAML parsing
    // fails). This avoids scattering logs across multiple locations.
    set_run_log_context_for_campaign(
        dry_run,
        run_id,
        command,
        config_path,
        None,
        None,
        started_utc,
    );
}

pub(crate) fn load_campaign_config_with_optional_profile(
    load_label: &str,
    run_id: &str,
    command: &str,
    config_path: &str,
    started_utc: &DateTime<Utc>,
    profile_name: Option<&str>,
) -> anyhow::Result<FuzzConfig> {
    tracing::info!("Loading {} from: {}", load_label, config_path);
    let mut config = match FuzzConfig::from_yaml(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            let ended_utc = Utc::now();
            write_failed_run_artifact_with_error(FailedRunArtifactErrorContext {
                run_id,
                command,
                stage: "load_config",
                config_path,
                started_utc,
                ended_utc: &ended_utc,
                error: format!("{:#}", err),
                output_dir: None,
            });
            return Err(err);
        }
    };

    if let Some(profile_name) = profile_name {
        match profile_name.parse::<ProfileName>() {
            Ok(parsed_profile) => apply_profile(&mut config, parsed_profile),
            Err(err) => {
                let ended_utc = Utc::now();
                let parse_error = err.to_string();
                write_failed_run_artifact_with_error(FailedRunArtifactErrorContext {
                    run_id,
                    command,
                    stage: "apply_profile",
                    config_path,
                    started_utc,
                    ended_utc: &ended_utc,
                    error: parse_error.clone(),
                    output_dir: Some(config.reporting.output_dir.as_path()),
                });
                return Err(anyhow::anyhow!(
                    "Invalid --profile '{}': {}",
                    profile_name,
                    parse_error
                ));
            }
        }
    }

    apply_scan_output_suffix_if_present(&mut config)?;
    Ok(config)
}
