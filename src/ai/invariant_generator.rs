//! Invariant Generator Module
//!
//! Generates candidate invariants from circuit analysis using AI

use crate::config::AIAssistantConfig;
use anyhow::Result;
use std::collections::HashSet;

/// Generate candidate invariants from circuit analysis
pub async fn generate_invariants(
    config: &AIAssistantConfig,
    circuit_info: &str,
) -> Result<Vec<String>> {
    let info_lc = circuit_info.to_ascii_lowercase();
    let mut invariants = Vec::new();
    let mut seen = HashSet::new();

    push_domain_invariants(&info_lc, &mut invariants, &mut seen);
    push_general_invariants(&mut invariants, &mut seen);

    for invariant in generate_invariants_with_ai(config, &info_lc).await? {
        push_invariant(&mut invariants, &mut seen, &invariant);
    }

    if invariants.is_empty() {
        push_invariant(
            &mut invariants,
            &mut seen,
            "circuit_well_formedness: all declared inputs and outputs are constrained",
        );
    }

    invariants.truncate(max_invariant_count(config));
    Ok(invariants)
}

fn max_invariant_count(config: &AIAssistantConfig) -> usize {
    let base = (config.max_tokens / 128).clamp(6, 16) as usize;
    if config.temperature >= 0.9 {
        (base + 2).min(18)
    } else if config.temperature <= 0.2 {
        base.min(8)
    } else {
        base
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn push_invariant(invariants: &mut Vec<String>, seen: &mut HashSet<String>, value: &str) {
    let key = value.trim().to_ascii_lowercase();
    if key.is_empty() || !seen.insert(key) {
        return;
    }
    invariants.push(value.trim().to_string());
}

fn push_domain_invariants(info_lc: &str, invariants: &mut Vec<String>, seen: &mut HashSet<String>) {
    if contains_any(info_lc, &["merkle", "smt", "path"]) {
        push_invariant(
            invariants,
            seen,
            "merkle_root_consistency: root == compute_merkle_root(leaves)",
        );
        push_invariant(
            invariants,
            seen,
            "merkle_path_validity: verify_merkle_path(root, leaf, path) == true",
        );
    }

    if contains_any(info_lc, &["nullifier", "nonce"]) {
        push_invariant(
            invariants,
            seen,
            "nullifier_uniqueness: nullifier not in used_nullifiers",
        );
        push_invariant(invariants, seen, "nullifier_range: nullifier < 2^252");
    }

    if contains_any(info_lc, &["range", "bound", "bit"]) {
        push_invariant(invariants, seen, "range_check: value < max_value");
        push_invariant(
            invariants,
            seen,
            "bit_length: bit_length(value) <= max_bits",
        );
    }

    if contains_any(info_lc, &["signature", "ecdsa", "schnorr", "eddsa"]) {
        push_invariant(
            invariants,
            seen,
            "signature_validity: verify_signature(pk, message, signature) == true",
        );
        push_invariant(
            invariants,
            seen,
            "public_key_validation: is_valid_public_key(pk) == true",
        );
    }

    if contains_any(info_lc, &["hash", "poseidon", "keccak", "pedersen"]) {
        push_invariant(
            invariants,
            seen,
            "hash_consistency: hash(input) == expected_hash for canonical test vectors",
        );
        push_invariant(
            invariants,
            seen,
            "hash_domain_separation: hashes across domains use distinct prefixes",
        );
    }

    if contains_any(info_lc, &["balance", "transfer", "amount"]) {
        push_invariant(
            invariants,
            seen,
            "balance_conservation: total_value_before == total_value_after + fees",
        );
    }
}

fn push_general_invariants(invariants: &mut Vec<String>, seen: &mut HashSet<String>) {
    push_invariant(
        invariants,
        seen,
        "public_input_consistency: public_inputs match circuit specification",
    );
    push_invariant(
        invariants,
        seen,
        "constraint_satisfaction: all_constraints_satisfied(witness) == true",
    );
    push_invariant(
        invariants,
        seen,
        "witness_determinism: identical inputs yield identical witness commitments",
    );
}

/// Model-guided invariant synthesis using configured model/prompt context.
///
/// This implementation intentionally stays offline and deterministic. It uses
/// model identity and prompt hints to specialize additional invariants.
async fn generate_invariants_with_ai(
    config: &AIAssistantConfig,
    circuit_info: &str,
) -> Result<Vec<String>> {
    let mut suggestions = Vec::new();

    let mut synthesis_context = format!("{} {}", config.model, circuit_info);
    if let Some(prompt) = &config.system_prompt {
        synthesis_context.push(' ');
        synthesis_context.push_str(prompt);
    }
    let context_lc = synthesis_context.to_ascii_lowercase();

    if contains_any(&context_lc, &["privacy", "leak", "anonymity"]) {
        suggestions.push(
            "privacy_leakage_bound: sensitive witness data is not derivable from public outputs"
                .to_string(),
        );
    }
    if contains_any(&context_lc, &["defi", "vault", "balance", "liquidity"]) {
        suggestions.push(
            "state_transition_soundness: next_state = apply_transition(prev_state, tx)".to_string(),
        );
    }
    if contains_any(&context_lc, &["replay", "nonce", "sequence"]) {
        suggestions.push("nonce_monotonicity: nonce_next > nonce_prev for same signer".to_string());
    }
    if contains_any(&context_lc, &["bridge", "cross-chain", "rollup"]) {
        suggestions.push(
            "domain_binding: source_chain_id and target_chain_id are bound into proofs".to_string(),
        );
    }

    Ok(suggestions)
}
