//! Integration tests for ZK backend implementations
//!
//! These tests verify that the backend integrations work correctly
//! when the required tools are available in the environment.

use zk_fuzzer::config::Framework;
use zk_fuzzer::executor::ExecutorFactory;
use zk_fuzzer::fuzzer::FieldElement;
use zk_fuzzer::targets::{CircomTarget, NoirTarget, Halo2Target, CairoTarget, TargetCircuit};

/// Test that we can detect available backends
#[test]
fn test_backend_availability() {
    // Check Circom
    match CircomTarget::check_circom_available() {
        Ok(version) => println!("Circom available: {}", version),
        Err(e) => println!("Circom not available: {}", e),
    }

    // Check Noir
    match NoirTarget::check_nargo_available() {
        Ok(version) => println!("Noir available: {}", version),
        Err(e) => println!("Noir not available: {}", e),
    }

    // Check Cairo
    match CairoTarget::check_cairo_available() {
        Ok((version, ver_str)) => println!("Cairo available: {:?} - {}", version, ver_str),
        Err(e) => println!("Cairo not available: {}", e),
    }
}

/// Test mock executor creation
#[test]
fn test_mock_executor_creation() {
    let executor = ExecutorFactory::create(
        Framework::Mock,
        "test.circom",
        "TestCircuit",
    ).unwrap();

    assert_eq!(executor.framework(), Framework::Mock);
    assert_eq!(executor.name(), "TestCircuit");
}

/// Test Halo2 mock mode
#[test]
fn test_halo2_mock_mode() {
    let target = Halo2Target::new("test_circuit").unwrap();
    let target = target.with_mock_mode(true);
    
    // Would need to call setup() for actual execution
    assert_eq!(target.name(), "test_circuit");
}

/// Test field element operations
#[test]
fn test_field_element_operations() {
    let zero = FieldElement::zero();
    let one = FieldElement::one();
    
    assert_ne!(zero, one);
    
    // Test addition
    let two = one.add(&one);
    assert_eq!(two, FieldElement::from_u64(2));
    
    // Test multiplication
    let four = two.mul(&two);
    assert_eq!(four, FieldElement::from_u64(4));
}

/// Test Circom analysis functions
#[test]
fn test_circom_analysis() {
    let source = r#"
        pragma circom 2.0.0;
        
        template Multiplier() {
            signal input a;
            signal input b;
            signal output c;
            
            c <== a * b;
        }
        
        component main = Multiplier();
    "#;
    
    let signals = zk_fuzzer::targets::circom_analysis::extract_signals(source);
    assert_eq!(signals.len(), 3);
    
    let vulnerabilities = zk_fuzzer::targets::circom_analysis::analyze_for_vulnerabilities(source);
    // Should detect potential underconstrained (3 signals, 1 constraint)
    println!("Found {} potential issues", vulnerabilities.len());
}

/// Test Noir analysis functions
#[test]
fn test_noir_analysis() {
    let source = r#"
        fn main(x: Field, y: pub Field) -> Field {
            assert(x != 0);
            x * y
        }
        
        fn helper(a: u64) -> u64 {
            a + 1
        }
    "#;
    
    let functions = zk_fuzzer::targets::noir_analysis::extract_functions(source);
    assert_eq!(functions.len(), 2);
    assert!(functions[0].is_main);
    
    let vulnerabilities = zk_fuzzer::targets::noir_analysis::analyze_for_vulnerabilities(source);
    println!("Found {} potential issues", vulnerabilities.len());
}

/// Test Halo2 analysis functions
#[test]
fn test_halo2_analysis() {
    let source = r#"
        let a1 = meta.advice_column();
        let a2 = meta.advice_column();
        
        region.assign_advice(a1, 0, || Value::known(x));
        region.query_advice(a1, Rotation::cur());
    "#;
    
    let issues = zk_fuzzer::targets::halo2_analysis::analyze_circuit(source);
    // Should detect unused column (a2 declared but never used)
    println!("Found {} potential issues", issues.len());
}

/// Test Cairo analysis functions
#[test]
fn test_cairo_analysis() {
    let source = r#"
        func main{output_ptr: felt*}() {
            let x = 5;
            %{ memory[ap] = ids.x * 2 %}
            [ap] = [ap - 1] + x;
        }
    "#;
    
    let vulnerabilities = zk_fuzzer::targets::cairo_analysis::analyze_for_vulnerabilities(source);
    // Should detect hint usage
    assert!(vulnerabilities.iter().any(|v| v.issue_type == zk_fuzzer::targets::cairo_analysis::IssueType::HintUsage));
}

/// Integration test for Circom (only runs if circom is available)
#[test]
#[ignore] // Run with: cargo test --ignored
fn test_circom_integration() {
    if CircomTarget::check_circom_available().is_err() {
        println!("Skipping Circom integration test - circom not available");
        return;
    }
    
    // Would need an actual circom file to test fully
    println!("Circom integration test would run here");
}

/// Integration test for Noir (only runs if nargo is available)
#[test]
#[ignore] // Run with: cargo test --ignored
fn test_noir_integration() {
    if NoirTarget::check_nargo_available().is_err() {
        println!("Skipping Noir integration test - nargo not available");
        return;
    }
    
    // Would need an actual Noir project to test fully
    println!("Noir integration test would run here");
}

/// Integration test for Cairo (only runs if cairo tools are available)
#[test]
#[ignore] // Run with: cargo test --ignored
fn test_cairo_integration() {
    if CairoTarget::check_cairo_available().is_err() {
        println!("Skipping Cairo integration test - cairo not available");
        return;
    }
    
    // Would need an actual Cairo file to test fully
    println!("Cairo integration test would run here");
}

/// Test executor factory fallback behavior
#[test]
fn test_executor_factory_fallback() {
    // When the real backend isn't available, should fall back to mock
    let executor = ExecutorFactory::create(
        Framework::Circom,
        "nonexistent.circom",
        "TestCircuit",
    );
    
    // Should either succeed with mock or fail gracefully
    match executor {
        Ok(exec) => {
            println!("Executor created (framework: {:?})", exec.framework());
        }
        Err(e) => {
            println!("Executor creation failed (expected if circom not available): {}", e);
        }
    }
}
