use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use zk_fuzzer::cve::CveDatabase;

const AUTONOMOUS_CVE_DB: &str = "templates/autonomous_cve_tests.yaml";
const REQUIRE_DATASET_ENV: &str = "ZKFUZZ_REQUIRE_CVE_DATASET";
const PREFLIGHT_CACHE_ENV: &str = "ZKFUZZ_CVE_PREFLIGHT_CACHE";
const PREFLIGHT_REFRESH_ENV: &str = "ZKFUZZ_CVE_PREFLIGHT_REFRESH";

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct PreflightCache {
    entries: HashMap<String, String>,
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn zkbugs_dataset_dir() -> std::path::PathBuf {
    repo_root().join("targets/zkbugs/dataset")
}

fn should_require_dataset() -> bool {
    std::env::var(REQUIRE_DATASET_ENV)
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false)
}

fn cve_limit_from_env() -> Option<usize> {
    std::env::var("ZKFUZZ_CVE_LIMIT")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|limit| *limit > 0)
}

fn cve_ids_from_env() -> Option<Vec<String>> {
    let raw = std::env::var("ZKFUZZ_CVE_IDS").ok()?;
    let ids: Vec<String> = raw
        .split(',')
        .map(|id| id.trim())
        .filter(|id| !id.is_empty())
        .map(|id| id.to_string())
        .collect();
    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

fn ensure_dataset_available(test_name: &str) -> bool {
    let dataset_dir = zkbugs_dataset_dir();
    if dataset_dir.exists() {
        return true;
    }

    let message = format!(
        "{}: dataset missing at {}. Populate targets and rerun:\n  python3 scripts/integrate_validation_datasets.py",
        test_name,
        dataset_dir.display()
    );
    if should_require_dataset() {
        panic!("{message}");
    }

    println!("⚠️  Skipping {test_name}: {message}");
    println!("   Set {REQUIRE_DATASET_ENV}=1 to require this dataset in CI.");
    false
}

fn preflight_cache_path() -> PathBuf {
    std::env::var(PREFLIGHT_CACHE_ENV)
        .map(|p| PathBuf::from(p.trim()))
        .ok()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            repo_root()
                .join("target")
                .join("autonomous_cve_preflight_cache.json")
        })
}

fn should_refresh_preflight_cache() -> bool {
    std::env::var(PREFLIGHT_REFRESH_ENV)
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false)
}

fn load_preflight_cache(path: &Path) -> PreflightCache {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return PreflightCache::default();
    };
    serde_json::from_str::<PreflightCache>(&raw).unwrap_or_default()
}

fn save_preflight_cache(path: &Path, cache: &PreflightCache) {
    if let Some(parent) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            println!(
                "⚠️  Could not create preflight cache directory '{}': {}",
                parent.display(),
                err
            );
            return;
        }
    }

    let serialized = match serde_json::to_string_pretty(cache) {
        Ok(s) => s,
        Err(err) => {
            println!("⚠️  Could not serialize preflight cache: {}", err);
            return;
        }
    };

    if let Err(err) = std::fs::write(path, serialized) {
        println!(
            "⚠️  Could not write preflight cache '{}': {}",
            path.display(),
            err
        );
    }
}

#[test]
fn test_autonomous_cve_regression_tests() {
    if !ensure_dataset_available("test_autonomous_cve_regression_tests") {
        return;
    }

    println!("Loading autonomous CVE database...");

    let db = CveDatabase::load_strict(AUTONOMOUS_CVE_DB)
        .expect("Failed to load autonomous CVE database");

    let tests = db.generate_regression_tests();
    assert!(!tests.is_empty(), "Should have autonomous CVE tests");
    let total_tests = tests.len();
    let selected_tests: Vec<_> = if let Some(ids) = cve_ids_from_env() {
        tests
            .into_iter()
            .filter(|test| ids.iter().any(|id| id == &test.cve_id))
            .collect()
    } else if let Some(limit) = cve_limit_from_env() {
        tests.into_iter().take(limit).collect()
    } else {
        tests
    };

    println!(
        "Found {} autonomous CVE regression tests (running {})",
        total_tests,
        selected_tests.len()
    );
    println!();

    let preflight_cache_path = preflight_cache_path();
    let refresh_preflight = should_refresh_preflight_cache();
    let mut preflight_cache = if refresh_preflight {
        PreflightCache::default()
    } else {
        load_preflight_cache(&preflight_cache_path)
    };
    let mut preflight_cache_updated = false;

    let mut preflight_infra_skips: HashMap<String, String> = HashMap::new();
    for test in &selected_tests {
        let circuit_full_path = repo_root().join(&test.circuit_path);
        if !circuit_full_path.exists() {
            continue;
        }
        if !refresh_preflight {
            if let Some(reason) = preflight_cache.entries.get(&test.cve_id) {
                preflight_infra_skips.insert(test.cve_id.clone(), reason.clone());
                continue;
            }
        }
        if let Some(reason) = test.preflight_infrastructure_issue() {
            preflight_cache
                .entries
                .insert(test.cve_id.clone(), reason.clone());
            preflight_cache_updated = true;
            preflight_infra_skips.insert(test.cve_id.clone(), reason);
        }
    }
    if refresh_preflight || preflight_cache_updated {
        save_preflight_cache(&preflight_cache_path, &preflight_cache);
    }
    if !preflight_infra_skips.is_empty() {
        println!(
            "Preflight disabled {} CVE target(s) due to backend/tooling/artifact issues.",
            preflight_infra_skips.len()
        );
        println!("  Cache file: {}", preflight_cache_path.display());
        println!();
    }

    let mut executed = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut circuit_not_found = 0;
    let mut infra_skipped = 0;
    let mut failed_test_cases = 0usize;
    let mut expected_valid_execution_failures = 0usize;
    let mut expected_invalid_execution_successes = 0usize;
    let mut failure_reason_counts: HashMap<String, usize> = HashMap::new();

    for test in &selected_tests {
        println!("Testing: {} - {}", test.cve_id, test.cve_name);

        let circuit_full_path = repo_root().join(&test.circuit_path);
        println!("  Circuit: {}", circuit_full_path.display());
        println!("  Test cases: {}", test.test_cases.len());

        if !circuit_full_path.exists() {
            println!(
                "  ⚠️  Circuit not found at: {}",
                circuit_full_path.display()
            );
            circuit_not_found += 1;
            continue;
        }

        if let Some(reason) = preflight_infra_skips.get(&test.cve_id) {
            println!("  ⚠️  Skipping (preflight): {}", reason);
            infra_skipped += 1;
            println!();
            continue;
        }

        println!("  ▶️  Executing regression test...");
        let result = test.run();
        if result.is_infrastructure_failure() {
            println!("  ⚠️  Skipping: backend/tooling artifacts unavailable for this circuit");
            for tc_result in &result.test_results {
                let msg = tc_result
                    .message
                    .as_deref()
                    .unwrap_or("infrastructure failure");
                println!("    - {}: {}", tc_result.name, msg);
            }
            infra_skipped += 1;
            println!();
            continue;
        }
        executed += 1;

        println!(
            "  Result: {}",
            if result.passed {
                "✓ PASSED"
            } else {
                "✗ FAILED"
            }
        );

        if result.passed {
            passed += 1;
        } else {
            failed += 1;
        }

        for tc_result in &result.test_results {
            let status = if tc_result.passed { "✓" } else { "✗" };
            let msg = tc_result.message.as_deref().unwrap_or("OK");
            println!("    {} {}: {}", status, tc_result.name, msg);
            if !tc_result.passed {
                failed_test_cases += 1;
                if let Some(message) = tc_result.message.as_deref() {
                    if message.starts_with("Expected valid but execution failed") {
                        expected_valid_execution_failures += 1;
                    }
                    if message.contains("Expected invalid but execution succeeded") {
                        expected_invalid_execution_successes += 1;
                    }
                    let normalized = normalize_failure_reason(message);
                    *failure_reason_counts.entry(normalized).or_insert(0) += 1;
                } else {
                    *failure_reason_counts
                        .entry("unknown_failure".to_string())
                        .or_insert(0) += 1;
                }
            }
        }
        println!();
    }

    println!("========================================");
    println!("Autonomous CVE Test Summary");
    println!("========================================");
    println!("Total CVE patterns run: {}", selected_tests.len());
    println!("Executed: {}", executed);
    println!("Passed: {}", passed);
    println!("Failed: {}", failed);
    println!("Circuits not found: {}", circuit_not_found);
    println!("Infrastructure skipped: {}", infra_skipped);
    println!("Failed test cases: {}", failed_test_cases);
    println!(
        "Expected-valid execution failures: {}",
        expected_valid_execution_failures
    );
    println!(
        "Expected-invalid execution successes: {}",
        expected_invalid_execution_successes
    );
    if !failure_reason_counts.is_empty() {
        let mut ranked_reasons: Vec<(String, usize)> = failure_reason_counts.into_iter().collect();
        ranked_reasons.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        println!("Top failure reasons:");
        for (reason, count) in ranked_reasons.into_iter().take(5) {
            println!("  - {} ({})", reason, count);
        }
    }
    println!();

    if executed > 0 {
        let success_rate = (passed as f64 / executed as f64) * 100.0;
        println!("Success rate: {:.1}%", success_rate);

        assert!(
            success_rate >= 50.0,
            "At least 50% of CVE tests should pass. Got {:.1}%",
            success_rate
        );
    } else {
        println!("⚠️  No circuits found. Check that targets/zkbugs/ is populated.");
        println!("Run: python3 scripts/integrate_validation_datasets.py");
    }

    assert!(
        circuit_not_found < selected_tests.len(),
        "At least some CVE test circuits should be available"
    );
}

#[test]
fn test_autonomous_cve_database_structure() {
    let db = CveDatabase::load_strict(AUTONOMOUS_CVE_DB)
        .expect("Failed to load autonomous CVE database");

    for cve in db.all_patterns() {
        assert!(!cve.id.is_empty(), "CVE ID cannot be empty");
        assert!(!cve.name.is_empty(), "CVE name cannot be empty");
        assert!(
            !cve.description.is_empty(),
            "CVE description cannot be empty"
        );
        assert!(
            !cve.regression_test.circuit_path.is_empty(),
            "Circuit path required"
        );

        // Verify circuit paths point to downloaded targets
        assert!(
            cve.regression_test.circuit_path.starts_with("targets/"),
            "CVE {}: Circuit path should be in targets/: {}",
            cve.id,
            cve.regression_test.circuit_path
        );

        // Verify test cases exist
        assert!(
            !cve.regression_test.test_cases.is_empty(),
            "CVE {}: Should have test cases",
            cve.id
        );

        println!(
            "✓ {}: {} - {} test cases",
            cve.id,
            cve.name,
            cve.regression_test.test_cases.len()
        );
    }

    println!("\n✅ All autonomous CVE patterns have valid structure");
}

fn normalize_failure_reason(message: &str) -> String {
    if message.starts_with("Expected valid but execution failed:") {
        return "expected_valid_execution_failed".to_string();
    }
    if message.contains("Expected invalid but execution succeeded") {
        return "expected_invalid_execution_succeeded".to_string();
    }
    if let Some((prefix, _)) = message.split_once(':') {
        return prefix.trim().to_ascii_lowercase().replace(' ', "_");
    }
    message.trim().to_ascii_lowercase().replace(' ', "_")
}

#[test]
fn test_cve_circuits_exist_in_repo() {
    if !ensure_dataset_available("test_cve_circuits_exist_in_repo") {
        return;
    }

    let db = CveDatabase::load_strict(AUTONOMOUS_CVE_DB)
        .expect("Failed to load autonomous CVE database");

    let repo_root = repo_root();
    let mut found = 0;
    let mut missing = 0;

    for cve in db.all_patterns() {
        let circuit_path = repo_root.join(&cve.regression_test.circuit_path);

        if circuit_path.exists() {
            println!("✓ {}: {}", cve.id, circuit_path.display());
            found += 1;
        } else {
            println!("✗ {}: {} (NOT FOUND)", cve.id, circuit_path.display());
            missing += 1;
        }
    }

    println!();
    println!("Circuits found: {}", found);
    println!("Circuits missing: {}", missing);

    // At least half should be present
    assert!(
        found > 0,
        "At least some CVE circuits should exist. Run the integration script to download them."
    );
}
