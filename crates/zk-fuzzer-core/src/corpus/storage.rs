//! Corpus storage and persistence

use super::CorpusEntry;
use std::path::Path;
use zk_core::{FieldElement, TestCase, TestMetadata};

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

    let input_array = data["inputs"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Invalid inputs array"))?;

    let mut inputs = Vec::with_capacity(input_array.len());
    for (i, v) in input_array.iter().enumerate() {
        let hex = v
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Input {} is not a string", i))?;
        let fe = FieldElement::from_hex_checked(hex)
            .map_err(|e| anyhow::anyhow!("Invalid hex at input {}: {}", i, e))?;
        inputs.push(fe);
    }

    let coverage_hash = data["coverage_hash"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid coverage_hash"))?;
    let discovered_new_coverage = data["discovered_new_coverage"]
        .as_bool()
        .unwrap_or_default();
    let execution_count = data["execution_count"].as_u64().unwrap_or_default() as usize;

    let test_case = TestCase {
        inputs,
        expected_output: None,
        metadata: TestMetadata::default(),
    };

    let mut entry = CorpusEntry::new(test_case, coverage_hash);
    if discovered_new_coverage {
        entry = entry.with_new_coverage();
    }
    entry.execution_count = execution_count as u64;

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

        if path.extension().is_some_and(|ext| ext == "json") {
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
#[path = "storage_tests.rs"]
mod tests;
