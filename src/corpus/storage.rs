//! Corpus storage and persistence

use super::CorpusEntry;
use crate::fuzzer::{FieldElement, TestCase, TestMetadata};
use std::path::Path;

/// Save a single test case to disk
pub fn save_test_case(entry: &CorpusEntry, dir: &Path, index: usize) -> anyhow::Result<()> {
    let filename = format!("test_case_{:06}.json", index);
    let path = dir.join(filename);

    let data = serde_json::json!({
        "inputs": entry.test_case.inputs.iter().map(|fe| fe.to_hex()).collect::<Vec<_>>(),
        "coverage_hash": entry.coverage_hash,
        "discovered_new_coverage": entry.discovered_new_coverage,
        "execution_count": entry.execution_count,
    });

    std::fs::write(path, serde_json::to_string_pretty(&data)?)?;
    Ok(())
}

/// Load a single test case from disk
pub fn load_test_case(path: &Path) -> anyhow::Result<CorpusEntry> {
    let data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;

    let inputs: Vec<FieldElement> = data["inputs"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Invalid inputs"))?
        .iter()
        .filter_map(|v| v.as_str())
        .filter_map(|hex| FieldElement::from_hex(hex).ok())
        .collect();

    let coverage_hash = data["coverage_hash"].as_u64().unwrap_or(0);
    let discovered_new_coverage = data["discovered_new_coverage"].as_bool().unwrap_or(false);

    let test_case = TestCase {
        inputs,
        expected_output: None,
        metadata: TestMetadata::default(),
    };

    let mut entry = CorpusEntry::new(test_case, coverage_hash);
    if discovered_new_coverage {
        entry = entry.with_new_coverage();
    }

    Ok(entry)
}

/// Load all test cases from a directory
pub fn load_corpus_from_dir(dir: &Path) -> anyhow::Result<Vec<CorpusEntry>> {
    let mut entries = Vec::new();

    if !dir.exists() {
        return Ok(entries);
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map_or(false, |ext| ext == "json") {
            match load_test_case(&path) {
                Ok(corpus_entry) => entries.push(corpus_entry),
                Err(e) => {
                    tracing::warn!("Failed to load test case {:?}: {}", path, e);
                }
            }
        }
    }

    Ok(entries)
}

/// Export interesting test cases for external analysis
pub fn export_interesting_cases(
    entries: &[CorpusEntry],
    output_dir: &Path,
) -> anyhow::Result<usize> {
    std::fs::create_dir_all(output_dir)?;

    let interesting: Vec<_> = entries
        .iter()
        .filter(|e| e.discovered_new_coverage)
        .collect();

    for (i, entry) in interesting.iter().enumerate() {
        save_test_case(entry, output_dir, i)?;
    }

    Ok(interesting.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_save_load_test_case() {
        let temp_dir = TempDir::new().unwrap();
        let entry = CorpusEntry::new(
            TestCase {
                inputs: vec![FieldElement::one(), FieldElement::from_u64(42)],
                expected_output: None,
                metadata: TestMetadata::default(),
            },
            12345,
        )
        .with_new_coverage();

        save_test_case(&entry, temp_dir.path(), 0).unwrap();

        let loaded = load_test_case(&temp_dir.path().join("test_case_000000.json")).unwrap();
        assert_eq!(loaded.coverage_hash, entry.coverage_hash);
        assert!(loaded.discovered_new_coverage);
        assert_eq!(loaded.test_case.inputs.len(), 2);
    }
}
