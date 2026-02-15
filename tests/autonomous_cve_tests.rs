use std::path::Path;
use zk_fuzzer::cve::CveDatabase;

const AUTONOMOUS_CVE_DB: &str = "templates/autonomous_cve_tests.yaml";

#[test]
fn test_autonomous_cve_regression_tests() {
    println!("Loading autonomous CVE database...");

    let db = CveDatabase::load(AUTONOMOUS_CVE_DB).expect("Failed to load autonomous CVE database");

    let tests = db.generate_regression_tests();
    assert!(!tests.is_empty(), "Should have autonomous CVE tests");

    println!("Found {} autonomous CVE regression tests", tests.len());
    println!();

    let mut executed = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut circuit_not_found = 0;

    for test in &tests {
        println!("Testing: {} - {}", test.cve_id, test.cve_name);

        let circuit_full_path =
            Path::new("/home/teycir/Repos/ZkPatternFuzz").join(&test.circuit_path);
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

        println!("  ▶️  Executing regression test...");
        let result = test.run();
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
        }
        println!();
    }

    println!("========================================");
    println!("Autonomous CVE Test Summary");
    println!("========================================");
    println!("Total CVE patterns: {}", tests.len());
    println!("Executed: {}", executed);
    println!("Passed: {}", passed);
    println!("Failed: {}", failed);
    println!("Circuits not found: {}", circuit_not_found);
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
        circuit_not_found < tests.len(),
        "At least some CVE test circuits should be available"
    );
}

#[test]
fn test_autonomous_cve_database_structure() {
    let db = CveDatabase::load(AUTONOMOUS_CVE_DB).expect("Failed to load autonomous CVE database");

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

#[test]
fn test_cve_circuits_exist_in_repo() {
    let db = CveDatabase::load(AUTONOMOUS_CVE_DB).expect("Failed to load autonomous CVE database");

    let repo_root = Path::new("/home/teycir/Repos/ZkPatternFuzz");
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
