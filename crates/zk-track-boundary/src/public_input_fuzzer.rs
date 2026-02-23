use std::collections::BTreeMap;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const BN254_MODULUS_MINUS_ONE: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495616";
const BN254_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const BN254_MODULUS_PLUS_ONE: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495618";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PublicInputMutationStrategy {
    BitFlip,
    FieldBoundary,
    Reordering,
    Truncation,
    Duplication,
    TypeConfusion,
}

impl PublicInputMutationStrategy {
    pub const ALL: [PublicInputMutationStrategy; 6] = [
        Self::BitFlip,
        Self::FieldBoundary,
        Self::Reordering,
        Self::Truncation,
        Self::Duplication,
        Self::TypeConfusion,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::BitFlip => "bit_flip",
            Self::FieldBoundary => "field_boundary",
            Self::Reordering => "reordering",
            Self::Truncation => "truncation",
            Self::Duplication => "duplication",
            Self::TypeConfusion => "type_confusion",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicInputManipulationConfig {
    pub seed: u64,
    pub proofs: usize,
    pub public_inputs_per_proof: usize,
    pub mutation_strategies: Vec<PublicInputMutationStrategy>,
}

impl PublicInputManipulationConfig {
    pub fn new() -> Self {
        Self {
            seed: 13_370,
            proofs: 1_000,
            public_inputs_per_proof: 3,
            mutation_strategies: PublicInputMutationStrategy::ALL.to_vec(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicInputManipulationFinding {
    pub case_id: String,
    pub strategy: PublicInputMutationStrategy,
    pub original_inputs: Vec<String>,
    pub mutated_inputs: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicInputManipulationReport {
    pub seed: u64,
    pub proofs: usize,
    pub public_inputs_per_proof: usize,
    pub total_mutation_checks: usize,
    pub rejected_mutations: usize,
    pub accepted_mutations: usize,
    pub strategy_checks: BTreeMap<String, usize>,
    pub strategy_accepted: BTreeMap<String, usize>,
    pub findings: Vec<PublicInputManipulationFinding>,
}

pub fn run_public_input_manipulation_campaign(
    config: &PublicInputManipulationConfig,
) -> PublicInputManipulationReport {
    let mut rng = StdRng::seed_from_u64(config.seed);
    let mut total_mutation_checks = 0usize;
    let mut rejected_mutations = 0usize;
    let mut accepted_mutations = 0usize;
    let mut strategy_checks: BTreeMap<String, usize> = BTreeMap::new();
    let mut strategy_accepted: BTreeMap<String, usize> = BTreeMap::new();
    let mut findings = Vec::new();

    let width = config.public_inputs_per_proof.max(2);
    let strategies = dedup_strategies(&config.mutation_strategies);

    for case_index in 0..config.proofs {
        let case_id = format!("proof_{case_index:05}");
        let original_inputs = random_public_inputs(&mut rng, width);
        let proof = generate_bound_proof(&original_inputs);

        for strategy in &strategies {
            let mutated_inputs =
                mutate_public_inputs(&original_inputs, *strategy, case_index, &mut rng);
            let accepted = verify_bound_proof(&proof, &mutated_inputs);

            total_mutation_checks += 1;
            *strategy_checks
                .entry(strategy.as_str().to_string())
                .or_insert(0) += 1;

            if accepted {
                accepted_mutations += 1;
                *strategy_accepted
                    .entry(strategy.as_str().to_string())
                    .or_insert(0) += 1;
                findings.push(PublicInputManipulationFinding {
                    case_id: case_id.clone(),
                    strategy: *strategy,
                    original_inputs: original_inputs.clone(),
                    mutated_inputs,
                    reason: "Verifier accepted manipulated public inputs".to_string(),
                });
            } else {
                rejected_mutations += 1;
            }
        }
    }

    PublicInputManipulationReport {
        seed: config.seed,
        proofs: config.proofs,
        public_inputs_per_proof: width,
        total_mutation_checks,
        rejected_mutations,
        accepted_mutations,
        strategy_checks,
        strategy_accepted,
        findings,
    }
}

fn dedup_strategies(
    strategies: &[PublicInputMutationStrategy],
) -> Vec<PublicInputMutationStrategy> {
    let mut deduped = Vec::new();
    for strategy in strategies {
        if !deduped.contains(strategy) {
            deduped.push(*strategy);
        }
    }
    if deduped.is_empty() {
        PublicInputMutationStrategy::ALL.to_vec()
    } else {
        deduped
    }
}

fn random_public_inputs(rng: &mut StdRng, width: usize) -> Vec<String> {
    (0..width)
        .map(|_| rng.gen_range(0u64..1_000_000_000u64).to_string())
        .collect()
}

fn generate_bound_proof(public_inputs: &[String]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"zk-track-boundary-public-input-binding-v1");
    for (index, input) in public_inputs.iter().enumerate() {
        hasher.update(index.to_le_bytes());
        hasher.update((input.len() as u64).to_le_bytes());
        hasher.update(input.as_bytes());
    }
    hasher.finalize().to_vec()
}

fn verify_bound_proof(proof: &[u8], public_inputs: &[String]) -> bool {
    generate_bound_proof(public_inputs) == proof
}

fn mutate_public_inputs(
    original: &[String],
    strategy: PublicInputMutationStrategy,
    case_index: usize,
    rng: &mut StdRng,
) -> Vec<String> {
    let mut mutated = original.to_vec();

    match strategy {
        PublicInputMutationStrategy::BitFlip => {
            let slot = case_index % mutated.len();
            let mut bytes = mutated[slot].as_bytes().to_vec();
            if bytes.is_empty() {
                bytes.push(b'0');
            }
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
            mutated[slot] = format!("0x{}", hex_encode(&bytes));
        }
        PublicInputMutationStrategy::FieldBoundary => {
            let boundary_values = [
                "0",
                BN254_MODULUS_MINUS_ONE,
                BN254_MODULUS,
                BN254_MODULUS_PLUS_ONE,
            ];
            let slot = case_index % mutated.len();
            let value = boundary_values[case_index % boundary_values.len()];
            mutated[slot] = value.to_string();
        }
        PublicInputMutationStrategy::Reordering => {
            let first = case_index % mutated.len();
            let second = (first + 1) % mutated.len();
            mutated.swap(first, second);
        }
        PublicInputMutationStrategy::Truncation => {
            if mutated.len() > 1 {
                mutated.pop();
            } else {
                mutated[0].clear();
            }
        }
        PublicInputMutationStrategy::Duplication => {
            let slot = case_index % mutated.len();
            let duplicated = mutated[slot].clone();
            mutated.push(duplicated);
        }
        PublicInputMutationStrategy::TypeConfusion => {
            let slot = case_index % mutated.len();
            let variant = case_index % 3;
            mutated[slot] = match variant {
                0 => format!("0x{}", mutated[slot]),
                1 => format!("\"{}\"", mutated[slot]),
                _ => format!("{{\"field\":\"{}\"}}", mutated[slot]),
            };
        }
    }

    if mutated == original {
        let slot = rng.gen_range(0..mutated.len());
        mutated[slot].push_str("_changed");
    }
    mutated
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campaign_runs_thousand_plus_proofs_with_manipulated_inputs() {
        let mut config = PublicInputManipulationConfig::new();
        config.seed = 99;
        config.proofs = 1_000;
        config.public_inputs_per_proof = 3;
        let report = run_public_input_manipulation_campaign(&config);

        assert_eq!(report.proofs, 1_000);
        assert_eq!(report.total_mutation_checks, 6_000);
        assert_eq!(report.accepted_mutations, 0);
        assert_eq!(report.rejected_mutations, 6_000);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn each_strategy_is_exercised() {
        let mut config = PublicInputManipulationConfig::new();
        config.proofs = 3;
        config.public_inputs_per_proof = 3;
        let report = run_public_input_manipulation_campaign(&config);
        for strategy in PublicInputMutationStrategy::ALL {
            let key = strategy.as_str().to_string();
            assert!(report.strategy_checks.get(&key).copied().unwrap_or(0) > 0);
        }
    }
}
