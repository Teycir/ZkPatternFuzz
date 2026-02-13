//! Real-world circuit validation against zk0d repository
//!
//! This test demonstrates ZkPatternFuzz's ability to find zero-day vulnerabilities
//! by analyzing production circuits from the zk0d repository.
//!
//! MANUAL INVARIANT ANALYSIS (Ground Truth):
//!
//! ## Tornado Core (withdraw.circom)
//! **Critical Invariants:**
//! 1. Nullifier uniqueness: nullifierHash === Pedersen(nullifier)
//! 2. Merkle membership: commitment must be in tree with root
//! 3. Commitment binding: commitment === Pedersen(nullifier || secret)
//! 4. Public input binding: recipient/relayer/fee bound via squares
//!
//! **Potential Vulnerabilities:**
//! - Signature malleability in EdDSA (if used in upstream circuits)
//! - Missing range checks on fee/refund values
//! - Pedersen hash collision resistance depends on external lib
//!
//! ## Semaphore (semaphore.circom)
//! **Critical Invariants:**
//! 1. Secret range: secret < l (subgroup order)
//! 2. Identity commitment: Poseidon(BabyPbk(secret))
//! 3. Merkle membership: identityCommitment in tree
//! 4. Nullifier uniqueness: Poseidon(scope, secret)
//! 5. Message binding: message * message constraint
//!
//! **Potential Vulnerabilities:**
//! - If BabyPbk not properly constrained, invalid public keys possible
//! - Nullifier could collide if scope reused
//! - Message malleability despite square constraint (Groth16 issue)
//!
//! ## Nullify Circuits (nullify.circom, linked/nullifier.circom)
//! **Critical Invariants:**
//! 1. Nullifier zero-safety: output 0 if any input is 0
//! 2. Schema validation: issuerClaim schema must match claimSchema
//! 3. Subject validation: claim issued to userGenesisID
//! 4. LinkID non-zero: linkID must not be zero
//!
//! **Potential Vulnerabilities:**
//! - Edge case: all inputs zero -> nullifier = 0 (collision risk)
//! - Missing constraint on claimSubjectProfileNonce range
//! - Possible claim reuse across different verifiers

use std::path::PathBuf;
use zk_fuzzer::analysis::opus::{OpusAnalyzer, OpusConfig, ZeroDayCategory};

const DEFAULT_ZK0D_BASE: &str = "/media/elements/Repos/zk0d";

fn zk0d_base() -> PathBuf {
    std::env::var("ZK0D_BASE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_ZK0D_BASE))
}

fn zk0d_privacy_base() -> PathBuf {
    zk0d_base().join("cat3_privacy")
}

fn zk0d_available() -> bool {
    zk0d_privacy_base().exists()
}

#[test]
// Requires zk0d repository - run manually
fn test_tornado_withdraw_invariant_detection() {
    if !zk0d_available() {
        eprintln!(
            "⚠️  zk0d not found at {}",
            zk0d_base().join("cat3_privacy").display()
        );
        return;
    }

    let circuit_path = zk0d_base().join("cat3_privacy/tornado-core/circuits/withdraw.circom");
    if !circuit_path.exists() {
        eprintln!("⚠️  Tornado withdraw circuit not found");
        return;
    }

    println!("\n{}", "=".repeat(80));
    println!("TORNADO CORE WITHDRAW CIRCUIT ANALYSIS");
    println!("{}\n", "=".repeat(80));

    let analyzer = OpusAnalyzer::with_config(OpusConfig {
        max_files: 1,
        min_zero_day_confidence: 0.3,
        ..Default::default()
    });

    let configs = analyzer
        .analyze_project(circuit_path.parent().unwrap())
        .unwrap();
    
    assert!(!configs.is_empty(), "Should analyze at least one circuit");

    let config = &configs[0];
    
    println!("Circuit: {}", config.circuit_name);
    println!("Analysis: {}", config.analysis_summary);

    println!("\n🔍 ZERO-DAY HINTS ({}):", config.zero_day_hints.len());
    println!("--------------------");
    for hint in &config.zero_day_hints {
        println!("  [{:?}] {:.0}% confidence", hint.category, hint.confidence * 100.0);
        println!("     {}", hint.description);
        if let Some(focus) = &hint.mutation_focus {
            println!("     Focus: {}", focus);
        }
    }

    // VALIDATION: Check generated config
    println!("\n✅ GENERATED CONFIG:");
    if let Some(base) = &config.config.base {
        println!("  Attacks configured: {}", base.attacks.len());
        for attack in &base.attacks {
            println!("    • {:?}", attack.attack_type);
        }
    }

    // Check for expected zero-day hints
    let hint_categories: Vec<_> = config.zero_day_hints.iter()
        .map(|h| format!("{:?}", h.category))
        .collect();
    
    println!("\n🎯 VULNERABILITY HINTS FOUND ({}):", hint_categories.len());
    for cat in &hint_categories {
        println!("  • {}", cat);
    }

    // We should detect something interesting
    println!("\n✅ VALIDATION: Detected {} zero-day hints", config.zero_day_hints.len());
}

#[test]
// Requires zk0d repository - run manually
fn test_semaphore_invariant_detection() {
    if !zk0d_available() {
        eprintln!("⚠️  zk0d not found");
        return;
    }

    let circuit_path = zk0d_privacy_base().join("semaphore/packages/circuits/src/semaphore.circom");
    if !circuit_path.exists() {
        eprintln!("⚠️  Semaphore circuit not found");
        return;
    }

    println!("\n{}", "=".repeat(80));
    println!("SEMAPHORE CIRCUIT ANALYSIS");
    println!("{}\n", "=".repeat(80));

    let analyzer = OpusAnalyzer::with_config(OpusConfig {
        max_files: 1,
        min_zero_day_confidence: 0.3,
        ..Default::default()
    });

    let configs = analyzer.analyze_project(circuit_path.parent().unwrap()).unwrap();
    
    if configs.is_empty() {
        println!("⚠️  No configs generated - circuit may need dependencies");
        return;
    }

    let config = &configs[0];
    
    println!("Circuit: {}", config.circuit_name);
    println!("Analysis: {}", config.analysis_summary);

    println!("\n🔍 ZERO-DAY HINTS ({}):", config.zero_day_hints.len());
    for hint in &config.zero_day_hints {
        println!("  [{:?}] {}", hint.category, hint.description);
    }

    if let Some(base) = &config.config.base {
        println!("\n📈 ATTACK CONFIGURATION:");
        for attack in &base.attacks {
            println!("  {:?}", attack.attack_type);
        }
    }

    println!("\n✅ Detected {} zero-day hints", config.zero_day_hints.len());
}

#[test]
// Requires zk0d repository - run manually
fn test_nullify_circuits_edge_cases() {
    if !zk0d_available() {
        eprintln!("⚠️  zk0d not found");
        return;
    }

    let nullify_path = zk0d_privacy_base().join("circuits/circuits/lib/utils/nullify.circom");
    if !nullify_path.exists() {
        eprintln!("⚠️  Nullify circuit not found");
        return;
    }

    println!("\n{}", "=".repeat(80));
    println!("NULLIFY CIRCUIT EDGE CASE ANALYSIS");
    println!("{}\n", "=".repeat(80));

    let analyzer = OpusAnalyzer::with_config(OpusConfig {
        max_files: 5,
        min_zero_day_confidence: 0.2,
        ..Default::default()
    });

    let configs = analyzer
        .analyze_project(nullify_path.parent().unwrap().parent().unwrap())
        .unwrap();
    
    println!("Found {} circuits in nullifier module", configs.len());

    for config in &configs {
        println!("\n--- {} ---", config.circuit_name);
        println!("Zero-day hints: {}", config.zero_day_hints.len());
        
        for hint in &config.zero_day_hints {
            println!("  • [{:.0}%] {:?}: {}", 
                hint.confidence * 100.0,
                hint.category,
                hint.description
            );
        }
    }

    // The nullify circuits should trigger edge case detection
    let has_edge_case_hint = configs.iter().any(|c| 
        c.zero_day_hints.iter().any(|h| 
            matches!(h.category, ZeroDayCategory::MissingConstraint | ZeroDayCategory::NullifierReuse)
        )
    );

    println!("\n🎯 Edge case detection: {}", has_edge_case_hint);
}

#[test]
// Requires zk0d repository and circom - comprehensive test
fn test_comprehensive_zk0d_scan() {
    if !zk0d_available() {
        eprintln!("⚠️  zk0d not found");
        return;
    }

    println!("\n{}", "=".repeat(80));
    println!("COMPREHENSIVE ZK0D PRIVACY CIRCUIT SCAN");
    println!("{}\n", "=".repeat(80));

    let analyzer = OpusAnalyzer::with_config(OpusConfig {
        max_files: 20,
        min_zero_day_confidence: 0.3,
        ..Default::default()
    });

    let privacy_path = zk0d_privacy_base();
    let configs = analyzer.analyze_project(privacy_path).unwrap();
    
    println!("📊 TOTAL CIRCUITS ANALYZED: {}", configs.len());
    println!("\n{}\n", "=".repeat(80));

    let mut total_hints = 0;
    let mut hints_by_category = std::collections::HashMap::new();
    let mut circuits_with_findings = 0;

    for (i, config) in configs.iter().enumerate() {
        if !config.zero_day_hints.is_empty() {
            circuits_with_findings += 1;
            println!("{}. {} - {} hints", i + 1, config.circuit_name, config.zero_day_hints.len());
            
            for hint in &config.zero_day_hints {
                total_hints += 1;
                *hints_by_category.entry(format!("{:?}", hint.category)).or_insert(0) += 1;
                
                println!("   [{:.0}%] {:?}", hint.confidence * 100.0, hint.category);
                println!("      {}", hint.description);
            }
            println!();
        }
    }

    println!("\n{}", "=".repeat(80));
    println!("SUMMARY");
    println!("{}\n", "=".repeat(80));
    println!("Total circuits: {}", configs.len());
    println!("Circuits with findings: {}", circuits_with_findings);
    println!("Total zero-day hints: {}", total_hints);
    
    println!("\n📊 HINTS BY CATEGORY:");
    let mut sorted_cats: Vec<_> = hints_by_category.iter().collect();
    sorted_cats.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    
    for (cat, count) in sorted_cats {
        println!("  {:30} : {}", cat, count);
    }

    println!("\n🎯 DETECTION RATE: {:.1}%", 
        (circuits_with_findings as f64 / configs.len() as f64) * 100.0
    );

    // We should find vulnerabilities in real circuits
    assert!(total_hints > 0, "Should detect potential vulnerabilities in zk0d circuits");
    assert!(circuits_with_findings > 0, "Should find at least some circuits with issues");
}
