use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PropertyCheckRecord {
    pub property: String,
    pub passed: bool,
    pub expected: String,
    pub observed: String,
    pub reason: String,
}

impl PropertyCheckRecord {
    pub fn pass(property: impl Into<String>, expected: impl Into<String>) -> Self {
        let expected = expected.into();
        Self {
            property: property.into(),
            passed: true,
            expected: expected.clone(),
            observed: expected,
            reason: "ok".to_string(),
        }
    }

    pub fn fail(
        property: impl Into<String>,
        expected: impl Into<String>,
        observed: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            property: property.into(),
            passed: false,
            expected: expected.into(),
            observed: observed.into(),
            reason: reason.into(),
        }
    }
}

pub fn bool_property(property: &str, expected: bool, observed: bool, reason: &str) -> PropertyCheckRecord {
    if expected == observed {
        PropertyCheckRecord::pass(property.to_string(), expected.to_string())
    } else {
        PropertyCheckRecord::fail(
            property.to_string(),
            expected.to_string(),
            observed.to_string(),
            reason.to_string(),
        )
    }
}
