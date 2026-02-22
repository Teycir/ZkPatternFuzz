use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const POST_ROADMAP_SCHEMA_VERSION: &str = "1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum TrackKind {
    Boundary,
    Compiler,
    Semantic,
    Crypto,
}

impl TrackKind {
    pub fn execution_order(self) -> u8 {
        match self {
            Self::Boundary => 0,
            Self::Compiler => 1,
            Self::Semantic => 2,
            Self::Crypto => 3,
        }
    }
}

impl Default for TrackKind {
    fn default() -> Self {
        Self::Boundary
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct TrackInput {
    pub campaign_id: String,
    pub run_id: String,
    pub seed: Option<u64>,
    pub corpus_dir: PathBuf,
    pub evidence_dir: PathBuf,
    pub output_dir: PathBuf,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for FindingSeverity {
    fn default() -> Self {
        Self::Medium
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct TrackFinding {
    pub id: String,
    pub track: TrackKind,
    pub title: String,
    pub summary: String,
    pub severity: FindingSeverity,
    pub reproducible: bool,
    #[serde(default)]
    pub evidence_paths: Vec<PathBuf>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct ReplayArtifact {
    pub replay_id: String,
    pub track: TrackKind,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub evidence_paths: Vec<PathBuf>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ScorecardMetric {
    pub name: String,
    pub value: f64,
    pub threshold: Option<f64>,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Scorecard {
    pub track: TrackKind,
    pub schema_version: String,
    pub evaluated_at: DateTime<Utc>,
    #[serde(default)]
    pub coverage_counts: BTreeMap<String, u64>,
    #[serde(default)]
    pub metrics: Vec<ScorecardMetric>,
    pub false_positive_budget: u64,
    pub false_positive_count: u64,
}

impl Default for Scorecard {
    fn default() -> Self {
        Self {
            track: TrackKind::Boundary,
            schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
            evaluated_at: Utc::now(),
            coverage_counts: BTreeMap::new(),
            metrics: Vec::new(),
            false_positive_budget: 0,
            false_positive_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrackExecution {
    pub track: TrackKind,
    pub run_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    #[serde(default)]
    pub findings: Vec<TrackFinding>,
    #[serde(default)]
    pub replay_artifacts: Vec<ReplayArtifact>,
    pub scorecard: Option<Scorecard>,
}

impl TrackExecution {
    pub fn empty(track: TrackKind, run_id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            track,
            run_id: run_id.into(),
            started_at: now,
            finished_at: now,
            findings: Vec::new(),
            replay_artifacts: Vec::new(),
            scorecard: None,
        }
    }
}

impl Default for TrackExecution {
    fn default() -> Self {
        Self::empty(TrackKind::Boundary, String::new())
    }
}
