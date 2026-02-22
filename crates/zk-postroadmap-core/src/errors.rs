use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::TrackKind;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum RunnerStage {
    Prepare,
    Run,
    Validate,
    Emit,
}

impl std::fmt::Display for RunnerStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prepare => write!(f, "prepare"),
            Self::Run => write!(f, "run"),
            Self::Validate => write!(f, "validate"),
            Self::Emit => write!(f, "emit"),
        }
    }
}

#[derive(Debug, Clone, Error, Eq, PartialEq)]
pub enum PostRoadmapError {
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("toolchain error: {0}")]
    Toolchain(String),
    #[error("adapter error: {0}")]
    Adapter(String),
    #[error("contract error: {0}")]
    Contract(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("replay error: {0}")]
    Replay(String),
    #[error("persistence error: {0}")]
    Persistence(String),
    #[error("infrastructure error: {0}")]
    Infrastructure(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("track `{track:?}` failed in `{stage}` stage: {message}")]
    TrackStage {
        track: TrackKind,
        stage: RunnerStage,
        message: String,
    },
}

pub type PostRoadmapResult<T> = Result<T, PostRoadmapError>;
