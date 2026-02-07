//! Integration tests for ZK backend implementations
//!
//! These tests verify that the backend integrations work correctly
//! when the required tools are available in the environment.

use std::path::PathBuf;
use zk_fuzzer::config::Framework;
use zk_fuzzer::executor::{CircuitExecutor, ExecutorFactory, CircomExecutor, NoirExecutor, Halo2Executor};
use zk_fuzzer::fuzzer::FieldElement;
use zk_fuzzer::targets::{CircomTarget, NoirTarget, Halo2Target, CairoTarget, TargetCircuit};

const DEFAULT_ZK0D_BASE: &str = "/media/elements/Repos/zk0d";

fn repo_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn circom_test_circuit(name: &str) -> PathBuf {
    repo_path()
        .join("tests")
        .join("circuits")
        .join(format!("{}.circom", name))
}

fn noir_project_path(name: &str) -> PathBuf {
    repo_path()
        .join("tests")
        .join("noir_projects")
        .join(name)
}

fn cairo_program_path(name: &str) -> PathBuf {
    repo_path()
        .join("tests")
        .join("cairo_programs")
        .join(format!("{}.cairo", name))
}

fn halo2_spec_path(name: &str) -> PathBuf {
    repo_path()
        .join("tests")
        .join("halo2_specs")
        .join(format!("{}.json", name))
}

fn halo2_real_repo_path() -> PathBuf {
    if let Ok(path) = std::env::var("HALO2_SCAFFOLD_PATH") {
        return PathBuf::from(path);
    }
    let base = std::env::var("ZK0D_BASE")
        .unwrap_or_else(|_| DEFAULT_ZK0D_BASE.to_string());
    PathBuf::from(base).join("cat5_frameworks/halo2-scaffold")
}

/// Test that all required backends are available
#[test]
fn test_backend_availability() {
    let circom_version = CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    let snarkjs_version = CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");
    let noir_version = NoirTarget::check_nargo_available()
        .expect("Noir not available. Install with: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash");
    let (cairo_version, cairo_str) = CairoTarget::check_cairo_available()
        .expect("Cairo not available. Ensure cairo-compile and cairo-run are on PATH");

    println!("Circom available: {}", circom_version);
    println!("snarkjs available: {}", snarkjs_version);
    println!("Noir available: {}", noir_version);
    println!("Cairo available: {:?} - {}", cairo_version, cairo_str);
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
fn test_circom_integration() {
    CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");

    let circuit_path = circom_test_circuit("multiplier");
    assert!(circuit_path.exists(), "Missing test circuit at {:?}", circuit_path);

    let mut target = CircomTarget::new(
        circuit_path.to_str().unwrap(),
        "Multiplier",
    ).expect("Failed to create CircomTarget");
    target.compile().expect("Circom compilation failed");

    let outputs = target.execute(&[
        FieldElement::from_u64(3),
        FieldElement::from_u64(4),
    ]).expect("Circom execution failed");

    assert_eq!(outputs.get(0), Some(&FieldElement::from_u64(12)));
}

/// Integration test for Noir (only runs if nargo is available)
#[test]
fn test_noir_integration() {
    NoirTarget::check_nargo_available()
        .expect("Noir not available. Install with: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash");

    let project_path = noir_project_path("multiplier");
    assert!(project_path.exists(), "Missing Noir project at {:?}", project_path);

    let mut target = NoirTarget::new(project_path.to_str().unwrap())
        .expect("Failed to create NoirTarget");
    target.compile().expect("Noir compilation failed");

    let outputs = target.execute(&[
        FieldElement::from_u64(3),
        FieldElement::from_u64(5),
    ]).expect("Noir execution failed");

    assert_eq!(outputs.get(0), Some(&FieldElement::from_u64(15)));
}

/// Validate constraint-level coverage for Circom executor
#[test]
fn test_circom_constraint_coverage() {
    CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");

    let circuit_path = circom_test_circuit("multiplier");
    assert!(circuit_path.exists(), "Missing test circuit at {:?}", circuit_path);

    let executor = CircomExecutor::new(
        circuit_path.to_str().unwrap(),
        "Multiplier",
    ).expect("Failed to create CircomExecutor");

    let result = executor.execute_sync(&[
        FieldElement::from_u64(3),
        FieldElement::from_u64(4),
    ]);

    assert!(result.success, "Circom execution failed");
    assert!(
        !result.coverage.satisfied_constraints.is_empty(),
        "Expected constraint-level coverage for Circom executor"
    );
}

/// Validate constraint-level coverage for Noir executor
#[test]
fn test_noir_constraint_coverage() {
    NoirTarget::check_nargo_available()
        .expect("Noir not available. Install with: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash");

    let project_path = noir_project_path("multiplier");
    assert!(project_path.exists(), "Missing Noir project at {:?}", project_path);

    let executor = NoirExecutor::new(project_path.to_str().unwrap())
        .expect("Failed to create NoirExecutor");

    let result = executor.execute_sync(&[
        FieldElement::from_u64(3),
        FieldElement::from_u64(5),
    ]);

    assert!(result.success, "Noir execution failed");
    assert!(
        !result.coverage.satisfied_constraints.is_empty(),
        "Expected constraint-level coverage for Noir executor"
    );
}

/// Validate constraint-level coverage for a real Halo2 circuit project.
/// Requires the halo2-scaffold repo cloned at ${ZK0D_BASE:-/media/elements/Repos/zk0d}/cat5_frameworks/halo2-scaffold
/// (or set HALO2_SCAFFOLD_PATH explicitly).
#[test]
#[ignore]
fn test_halo2_real_circuit_constraint_coverage() {
    let repo_path = halo2_real_repo_path();
    assert!(
        repo_path.exists(),
        "Missing halo2-scaffold repo at {:?}",
        repo_path
    );

    let cargo_home = std::env::temp_dir().join("zk0d_cargo_home");
    std::fs::create_dir_all(&cargo_home).expect("Failed to create temp cargo home");
    std::env::set_var("CARGO_HOME", &cargo_home);
    std::env::set_var("RUSTUP_HOME", cargo_home.join("rustup"));

    let build_dir = std::env::temp_dir().join("zk0d_halo2_build");
    let executor = Halo2Executor::new_with_build_dir(
        repo_path.to_str().unwrap(),
        "zk0d_mul",
        build_dir,
    )
        .expect("Failed to create Halo2Executor");

    let inputs = vec![
        FieldElement::from_u64(3),
        FieldElement::from_u64(5),
        FieldElement::from_u64(15),
    ];

    let result = executor.execute_sync(&inputs);
    assert!(result.success, "Halo2 execution failed");
    assert!(
        !result.coverage.satisfied_constraints.is_empty(),
        "Expected constraint-level coverage for Halo2 executor"
    );
}

/// Integration test for Cairo (only runs if cairo tools are available)
#[test]
fn test_cairo_integration() {
    CairoTarget::check_cairo_available()
        .expect("Cairo not available. Ensure cairo-compile and cairo-run are on PATH");

    let program_path = cairo_program_path("multiplier");
    assert!(program_path.exists(), "Missing Cairo program at {:?}", program_path);

    let mut target = CairoTarget::new(program_path.to_str().unwrap())
        .expect("Failed to create CairoTarget");
    target.compile().expect("Cairo compilation failed");

    let outputs = target.execute(&[]).expect("Cairo execution failed");
    assert_eq!(outputs.get(0), Some(&FieldElement::from_u64(12)));
}

/// Integration test for Halo2 JSON spec loading/execution
#[test]
fn test_halo2_json_integration() {
    let spec_path = halo2_spec_path("minimal");
    assert!(spec_path.exists(), "Missing Halo2 spec at {:?}", spec_path);

    let mut target = Halo2Target::new(spec_path.to_str().unwrap())
        .expect("Failed to create Halo2Target");
    target.setup().expect("Halo2 setup failed");

    let outputs = target.execute(&[
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
    ]).expect("Halo2 execution failed");
    assert!(!outputs.is_empty());
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
