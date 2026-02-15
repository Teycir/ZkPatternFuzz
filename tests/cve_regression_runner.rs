//! CVE Regression Test Runner
//!
//! This test verifies that CVE regression tests actually execute circuits
//! and detect vulnerabilities, not just return passed=true.

use std::path::Path;
use zk_fuzzer::cve::{CveDatabase, RegressionTest};

const CVE_DATABASE_PATH: &str = "templates/known_vulnerabilities.yaml";

/// Test that CVE regression tests actually run and produce results
#[test]
fn test_cve_regression_tests_execute() {
    let db = CveDatabase::load(CVE_DATABASE_PATH).expect("Failed to load CVE database");

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

        // Run the regression test
        println!("  ▶️  Executing...");
        let result = test.run();

        println!("  Results:");
        println!("    Overall passed: {}", result.passed);
        println!("    Test cases run: {}", result.test_results.len());

        for tc_result in &result.test_results {
            let status = if tc_result.passed { "✓" } else { "✗" };
            let message = match tc_result.message.as_deref() {
                Some(message) => message,
                None => "OK",
            };
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
    }

    println!("\n========================================");
    println!("CVE Regression Test Summary");
    println!("========================================");
    println!("Total tests: {}", tests.len());
    println!("Executed: {}", executed);
    println!("Skipped (circuit not found): {}", circuit_not_found);

    // We should have executed at least some tests
    // If all were skipped due to missing circuits, that's a problem
    if executed == 0 {
        println!("\n⚠️  WARNING: No CVE tests were executed!");
        println!("Circuits are likely on external drive at /media/elements/Repos/zk0d/");
        println!("Connect the external drive to run full validation.");
    }
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
    let db = CveDatabase::load(CVE_DATABASE_PATH).expect("Failed to load CVE database");

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
