//! CVE Regression Test Runner
//!
//! This test verifies that CVE regression tests actually execute circuits
//! and detect vulnerabilities, not just return passed=true.

use std::env;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};

use tempfile::tempdir;
use zk_fuzzer::cve::{CveDatabase, RegressionTest};

const CVE_DATABASE_PATH: &str = "templates/known_vulnerabilities.yaml";

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct PathRestore(Option<String>);

impl Drop for PathRestore {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            env::set_var("PATH", path);
        } else {
            env::remove_var("PATH");
        }
    }
}

fn find_command_on_path(command: &str) -> std::path::PathBuf {
    env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(command))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| {
            panic!(
                "`{}` must be available on PATH for CVE regression tests",
                command
            )
        })
}

fn isolate_path_to_node_only() -> tempfile::TempDir {
    let node_path = find_command_on_path("node");
    let sandbox = tempdir().expect("node PATH sandbox");
    let node_bin_dir = sandbox.path().join("bin");
    fs::create_dir_all(&node_bin_dir).expect("create isolated node PATH");

    #[cfg(unix)]
    std::os::unix::fs::symlink(&node_path, node_bin_dir.join("node"))
        .expect("symlink node into isolated PATH");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&node_path, node_bin_dir.join("node.exe"))
        .expect("symlink node into isolated PATH");

    env::set_var("PATH", &node_bin_dir);
    sandbox
}

fn assert_bundled_circom_fixture_artifacts(circuit_path: &str) {
    let circuit = Path::new(circuit_path);
    let stem = circuit
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_else(|| {
            panic!(
                "fixture circuit path must have a valid UTF-8 stem: {}",
                circuit.display()
            )
        });
    let build_dir = circuit
        .parent()
        .unwrap_or_else(|| {
            panic!(
                "fixture circuit path must have a parent directory: {}",
                circuit.display()
            )
        })
        .join("build");
    let wasm_dir = build_dir.join(format!("{}_js", stem));
    let required = [
        build_dir.join(format!("{}.r1cs", stem)),
        build_dir.join(format!("{}.sym", stem)),
        build_dir.join(format!("{}_constraints.json", stem)),
        build_dir.join(format!("{}_metadata.json", stem)),
        wasm_dir.join(format!("{}.wasm", stem)),
        wasm_dir.join("witness_calculator.js"),
    ];

    let missing: Vec<String> = required
        .iter()
        .filter(|path| !path.exists())
        .map(|path| path.display().to_string())
        .collect();

    assert!(
        missing.is_empty(),
        "Bundled CVE fixture artifacts are required for clean-clone regression execution. Missing: {}",
        missing.join(", ")
    );
}

/// Test that CVE regression tests actually run and produce results
#[test]
fn test_cve_regression_tests_execute() {
    let _guard = env_lock();
    let _path_restore = PathRestore(env::var("PATH").ok());
    let _node_path_only = isolate_path_to_node_only();
    let db =
        CveDatabase::load_strict(CVE_DATABASE_PATH).expect("Failed to load strict CVE database");

    let tests = db.generate_regression_tests();
    assert!(!tests.is_empty(), "Should have regression tests");

    println!("Found {} CVE regression tests", tests.len());

    let mut executed = 0;
    let mut _skipped = 0;
    let mut circuit_not_found = 0;

    for test in &tests {
        println!("\nTesting: {} - {}", test.cve_id, test.cve_name);
        println!("  Circuit: {}", test.circuit_path);
        println!("  Test cases: {}", test.test_cases.len());

        // Check if circuit exists
        let circuit_path = Path::new(&test.circuit_path);
        if !circuit_path.exists() {
            println!("  ⚠️  Circuit not found - SKIPPING");
            _skipped += 1;
            circuit_not_found += 1;
            continue;
        }
        assert_bundled_circom_fixture_artifacts(&test.circuit_path);

        // Run the regression test
        println!("  ▶️  Executing...");
        let result = test.run();

        println!("  Results:");
        println!("    Overall passed: {}", result.passed);
        println!("    Test cases run: {}", result.test_results.len());

        for tc_result in &result.test_results {
            let status = if tc_result.passed { "✓" } else { "✗" };
            let message = tc_result.message.as_deref().unwrap_or("OK");
            println!("    {} {}: {}", status, tc_result.name, message);
        }

        executed += 1;

        // CRITICAL: Verify that the test actually did something
        // A test that always passes without checking anything is useless
        assert!(
            !result.test_results.is_empty(),
            "CVE {}: Test should have test case results, not empty",
            test.cve_id
        );
        assert!(
            result.passed,
            "CVE {}: regression cases must match their explicit valid/invalid expectations",
            test.cve_id
        );
    }

    println!("\n========================================");
    println!("CVE Regression Test Summary");
    println!("========================================");
    println!("Total tests: {}", tests.len());
    println!("Executed: {}", executed);
    println!("Skipped (circuit not found): {}", circuit_not_found);

    assert_eq!(
        circuit_not_found, 0,
        "Known CVE regression fixtures must be bundled in-repo"
    );
    assert_eq!(
        executed,
        tests.len(),
        "Every known CVE regression target should execute without missing fixture paths"
    );
}

/// Test that verifies the CVE run() method doesn't return passed=true unconditionally
#[test]
fn test_cve_run_not_stubbed() {
    // Create a test with a non-existent circuit
    use zk_fuzzer::cve::GeneratedTestCase;

    // Create a test with a non-existent circuit but WITH a test case
    let test = RegressionTest {
        cve_id: "TEST-CVE-000".to_string(),
        cve_name: "Test CVE".to_string(),
        circuit_path: "/nonexistent/path/circuit.circom".to_string(),
        test_cases: vec![GeneratedTestCase {
            name: "test_case_1".to_string(),
            inputs: vec![],
            expected_result: "valid".to_string(),
            expected_valid: Some(true),
        }],
        assertion: "Test".to_string(),
    };

    let result = test.run();

    // Should fail because circuit doesn't exist
    assert!(
        !result.passed,
        "Test with non-existent circuit should fail, not pass"
    );

    // Should have test results explaining the failure
    assert!(
        !result.test_results.is_empty(),
        "Should have test results explaining failure"
    );

    // Check the failure message
    let first_result = &result.test_results[0];
    assert!(
        first_result.message.as_ref().unwrap().contains("not found"),
        "Failure message should indicate circuit not found: {:?}",
        first_result.message
    );
}

/// Test that CVE patterns can create actual findings
#[test]
fn test_cve_finding_creation() {
    let db =
        CveDatabase::load_strict(CVE_DATABASE_PATH).expect("Failed to load strict CVE database");

    // Test finding creation for each CVE
    for cve in db.all_patterns() {
        let poc = zk_fuzzer::fuzzer::ProofOfConcept {
            witness_a: vec![],
            witness_b: None,
            public_inputs: vec![],
            proof: None,
        };

        let finding = cve.create_finding(poc, None);

        // Verify finding has proper metadata
        assert!(
            finding.description.contains(&cve.id),
            "Finding should reference CVE ID: {}",
            cve.id
        );

        assert!(
            finding.description.contains(&cve.name),
            "Finding should reference CVE name"
        );

        assert_eq!(
            finding.severity,
            cve.severity_enum(),
            "Finding severity should match CVE severity"
        );

        assert_eq!(
            finding.attack_type,
            cve.attack_type(),
            "Finding attack type should match CVE attack type"
        );
    }

    println!("✅ All CVE patterns can create proper findings");
}
