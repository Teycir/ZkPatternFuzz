use std::collections::BTreeMap;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zk_core::constants::{
    BN254_SCALAR_MODULUS_DECIMAL, BN254_SCALAR_MODULUS_MINUS_ONE_DECIMAL,
    BN254_SCALAR_MODULUS_PLUS_ONE_DECIMAL,
};

const MIN_GAS_REFERENCE: u64 = 250_000;
const MIN_GAS_WEAK_FAIL_OPEN: u64 = 90_000;
const CALLDATA_SELECTOR: [u8; 4] = [0x19, 0x28, 0x65, 0xab];
const CANONICAL_PROOF_LEN: usize = 96;
const MIN_PROOF_BINDING_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VerifierInputMutation {
    ProofByteMutation,
    PublicInputEdgeCase,
    MalformedCalldata,
    GasLimitStress,
    RevertConditionProbe,
}

impl VerifierInputMutation {
    pub const ALL: [VerifierInputMutation; 5] = [
        Self::ProofByteMutation,
        Self::PublicInputEdgeCase,
        Self::MalformedCalldata,
        Self::GasLimitStress,
        Self::RevertConditionProbe,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProofByteMutation => "proof_byte_mutation",
            Self::PublicInputEdgeCase => "public_input_edge_case",
            Self::MalformedCalldata => "malformed_calldata",
            Self::GasLimitStress => "gas_limit_stress",
            Self::RevertConditionProbe => "revert_condition_probe",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PairingManipulationCase {
    PairingEquationTamper,
    InvalidCurvePoint,
    WrongSubgroupPoint,
    MalformedPairingInput,
}

impl PairingManipulationCase {
    pub const ALL: [PairingManipulationCase; 4] = [
        Self::PairingEquationTamper,
        Self::InvalidCurvePoint,
        Self::WrongSubgroupPoint,
        Self::MalformedPairingInput,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PairingEquationTamper => "pairing_equation_tamper",
            Self::InvalidCurvePoint => "invalid_curve_point",
            Self::WrongSubgroupPoint => "wrong_subgroup_point",
            Self::MalformedPairingInput => "malformed_pairing_input",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SolidityEdgeCase {
    GasCalculationOverflow,
    PublicInputArrayBounds,
    MemoryAllocationEdge,
    CalldataMemoryConfusion,
    ReentrancyCallbackProbe,
}

impl SolidityEdgeCase {
    pub const ALL: [SolidityEdgeCase; 5] = [
        Self::GasCalculationOverflow,
        Self::PublicInputArrayBounds,
        Self::MemoryAllocationEdge,
        Self::CalldataMemoryConfusion,
        Self::ReentrancyCallbackProbe,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::GasCalculationOverflow => "gas_calculation_overflow",
            Self::PublicInputArrayBounds => "public_input_array_bounds",
            Self::MemoryAllocationEdge => "memory_allocation_edge",
            Self::CalldataMemoryConfusion => "calldata_memory_confusion",
            Self::ReentrancyCallbackProbe => "reentrancy_callback_probe",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SolidityVerifierProfile {
    StrictParity,
    WeakGasOptimization,
}

impl SolidityVerifierProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StrictParity => "strict_parity",
            Self::WeakGasOptimization => "weak_gas_optimization",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolidityVerifierFuzzConfig {
    pub seed: u64,
    pub proofs: usize,
    pub public_inputs_per_proof: usize,
    pub input_mutations: Vec<VerifierInputMutation>,
    pub pairing_cases: Vec<PairingManipulationCase>,
    pub edge_cases: Vec<SolidityEdgeCase>,
    pub optimized_profile: SolidityVerifierProfile,
}

impl SolidityVerifierFuzzConfig {
    pub fn new() -> Self {
        Self {
            seed: 20_260_223,
            proofs: 500,
            public_inputs_per_proof: 3,
            input_mutations: VerifierInputMutation::ALL.to_vec(),
            pairing_cases: PairingManipulationCase::ALL.to_vec(),
            edge_cases: SolidityEdgeCase::ALL.to_vec(),
            optimized_profile: SolidityVerifierProfile::StrictParity,
        }
    }
}

impl Default for SolidityVerifierFuzzConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolidityVerifierFinding {
    pub case_id: String,
    pub category: String,
    pub test_case: String,
    pub reason: String,
    pub reference_accepted: bool,
    pub optimized_accepted: bool,
    pub reference_reverted: bool,
    pub optimized_reverted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolidityVerifierFuzzReport {
    pub seed: u64,
    pub proofs: usize,
    pub public_inputs_per_proof: usize,
    pub optimized_profile: SolidityVerifierProfile,
    pub total_checks: usize,
    pub differential_checks: usize,
    pub input_fuzz_checks: usize,
    pub pairing_checks: usize,
    pub edge_case_checks: usize,
    pub differential_divergences: usize,
    pub optimized_accepts_reference_rejects: usize,
    pub reference_accepts_optimized_rejects: usize,
    pub checks_by_input_mutation: BTreeMap<String, usize>,
    pub divergences_by_input_mutation: BTreeMap<String, usize>,
    pub checks_by_pairing_case: BTreeMap<String, usize>,
    pub divergences_by_pairing_case: BTreeMap<String, usize>,
    pub checks_by_edge_case: BTreeMap<String, usize>,
    pub divergences_by_edge_case: BTreeMap<String, usize>,
    pub findings: Vec<SolidityVerifierFinding>,
}

pub fn run_solidity_verifier_fuzz_campaign(
    config: &SolidityVerifierFuzzConfig,
) -> SolidityVerifierFuzzReport {
    let mut rng = StdRng::seed_from_u64(config.seed);
    let proofs = config.proofs.max(1);
    let width = config.public_inputs_per_proof.max(1);
    let input_mutations = dedup_input_mutations(&config.input_mutations);
    let pairing_cases = dedup_pairing_cases(&config.pairing_cases);
    let edge_cases = dedup_edge_cases(&config.edge_cases);

    let mut report = SolidityVerifierFuzzReport {
        seed: config.seed,
        proofs,
        public_inputs_per_proof: width,
        optimized_profile: config.optimized_profile,
        total_checks: 0,
        differential_checks: 0,
        input_fuzz_checks: 0,
        pairing_checks: 0,
        edge_case_checks: 0,
        differential_divergences: 0,
        optimized_accepts_reference_rejects: 0,
        reference_accepts_optimized_rejects: 0,
        checks_by_input_mutation: BTreeMap::new(),
        divergences_by_input_mutation: BTreeMap::new(),
        checks_by_pairing_case: BTreeMap::new(),
        divergences_by_pairing_case: BTreeMap::new(),
        checks_by_edge_case: BTreeMap::new(),
        divergences_by_edge_case: BTreeMap::new(),
        findings: Vec::new(),
    };

    for case_index in 0..proofs {
        let case_id = format!("proof_{case_index:05}");
        let base_case = generate_valid_case(&mut rng, case_index, width);

        compare_case(
            &mut report,
            &case_id,
            "gas_optimized_verifier_testing",
            "baseline_valid_proof",
            &base_case,
            config.optimized_profile,
            None,
        );

        for mutation in &input_mutations {
            let mutated = mutate_input_case(base_case.clone(), *mutation, case_index, &mut rng);
            *report
                .checks_by_input_mutation
                .entry(mutation.as_str().to_string())
                .or_insert(0) += 1;
            report.input_fuzz_checks += 1;
            compare_case(
                &mut report,
                &case_id,
                "verifier_input_fuzzing",
                mutation.as_str(),
                &mutated,
                config.optimized_profile,
                Some(mutation.as_str()),
            );
        }

        for pairing_case in &pairing_cases {
            let mutated = mutate_pairing_case(base_case.clone(), *pairing_case, case_index);
            *report
                .checks_by_pairing_case
                .entry(pairing_case.as_str().to_string())
                .or_insert(0) += 1;
            report.pairing_checks += 1;
            compare_case(
                &mut report,
                &case_id,
                "pairing_check_manipulation",
                pairing_case.as_str(),
                &mutated,
                config.optimized_profile,
                Some(pairing_case.as_str()),
            );
        }

        for edge_case in &edge_cases {
            let mutated = mutate_solidity_edge_case(base_case.clone(), *edge_case, case_index);
            *report
                .checks_by_edge_case
                .entry(edge_case.as_str().to_string())
                .or_insert(0) += 1;
            report.edge_case_checks += 1;
            compare_case(
                &mut report,
                &case_id,
                "solidity_specific_edge_cases",
                edge_case.as_str(),
                &mutated,
                config.optimized_profile,
                Some(edge_case.as_str()),
            );
        }
    }

    report
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerificationCase {
    proof: Vec<u8>,
    public_inputs: Vec<String>,
    calldata: Vec<u8>,
    gas_limit: u64,
    pairing: PairingState,
    solidity: SolidityState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PairingState {
    equation_valid: bool,
    curve_points_valid: bool,
    subgroup_valid: bool,
    malformed_input: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SolidityState {
    gas_overflow_flag: bool,
    public_input_bounds_ok: bool,
    memory_allocation_ok: bool,
    calldata_memory_consistent: bool,
    reentrancy_detected: bool,
    force_revert: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerificationOutcome {
    accepted: bool,
    reverted: bool,
}

fn compare_case(
    report: &mut SolidityVerifierFuzzReport,
    case_id: &str,
    category: &str,
    test_case: &str,
    case: &VerificationCase,
    optimized_profile: SolidityVerifierProfile,
    case_key: Option<&str>,
) {
    let reference = verify_case(SolidityVerifierProfile::StrictParity, case);
    let optimized = verify_case(optimized_profile, case);

    report.total_checks += 1;
    report.differential_checks += 1;

    if let Some(reason) = divergence_reason(reference, optimized) {
        report.differential_divergences += 1;
        if !reference.accepted && optimized.accepted {
            report.optimized_accepts_reference_rejects += 1;
        }
        if reference.accepted && !optimized.accepted {
            report.reference_accepts_optimized_rejects += 1;
        }
        if let Some(key) = case_key {
            if category == "verifier_input_fuzzing" {
                *report
                    .divergences_by_input_mutation
                    .entry(key.to_string())
                    .or_insert(0) += 1;
            } else if category == "pairing_check_manipulation" {
                *report
                    .divergences_by_pairing_case
                    .entry(key.to_string())
                    .or_insert(0) += 1;
            } else if category == "solidity_specific_edge_cases" {
                *report
                    .divergences_by_edge_case
                    .entry(key.to_string())
                    .or_insert(0) += 1;
            }
        }
        report.findings.push(SolidityVerifierFinding {
            case_id: format!("{case_id}_{category}_{test_case}"),
            category: category.to_string(),
            test_case: test_case.to_string(),
            reason: reason.to_string(),
            reference_accepted: reference.accepted,
            optimized_accepted: optimized.accepted,
            reference_reverted: reference.reverted,
            optimized_reverted: optimized.reverted,
        });
    }
}

fn divergence_reason(
    reference: VerificationOutcome,
    optimized: VerificationOutcome,
) -> Option<&'static str> {
    if reference == optimized {
        return None;
    }
    if !reference.accepted && optimized.accepted {
        return Some("optimized verifier accepted input rejected by reference");
    }
    if reference.accepted && !optimized.accepted {
        return Some("optimized verifier rejected input accepted by reference");
    }
    Some("revert-path mismatch between reference and optimized verifier")
}

fn verify_case(profile: SolidityVerifierProfile, case: &VerificationCase) -> VerificationOutcome {
    if case.gas_limit < MIN_GAS_WEAK_FAIL_OPEN {
        return VerificationOutcome {
            accepted: false,
            reverted: false,
        };
    }

    if case.solidity.force_revert && profile == SolidityVerifierProfile::StrictParity {
        return VerificationOutcome {
            accepted: false,
            reverted: true,
        };
    }

    let calldata_ok = match profile {
        SolidityVerifierProfile::StrictParity => {
            case.calldata == encode_calldata(&case.proof, &case.public_inputs)
        }
        SolidityVerifierProfile::WeakGasOptimization => {
            case.calldata.len() >= CALLDATA_SELECTOR.len()
                && case.calldata.starts_with(&CALLDATA_SELECTOR)
        }
    };
    if !calldata_ok {
        return VerificationOutcome {
            accepted: false,
            reverted: profile == SolidityVerifierProfile::StrictParity,
        };
    }

    if case.gas_limit < MIN_GAS_REFERENCE && profile == SolidityVerifierProfile::StrictParity {
        return VerificationOutcome {
            accepted: false,
            reverted: false,
        };
    }

    if case.gas_limit < MIN_GAS_REFERENCE
        && profile == SolidityVerifierProfile::WeakGasOptimization
        && weak_binding_holds(case)
        && case.pairing.equation_valid
        && case.pairing.curve_points_valid
    {
        return VerificationOutcome {
            accepted: true,
            reverted: false,
        };
    }

    if !case.pairing.equation_valid || !case.pairing.curve_points_valid {
        return VerificationOutcome {
            accepted: false,
            reverted: false,
        };
    }

    if profile == SolidityVerifierProfile::StrictParity
        && (!case.pairing.subgroup_valid || case.pairing.malformed_input)
    {
        return VerificationOutcome {
            accepted: false,
            reverted: false,
        };
    }

    if profile == SolidityVerifierProfile::StrictParity
        && (!case.solidity.public_input_bounds_ok
            || !case.solidity.memory_allocation_ok
            || !case.solidity.calldata_memory_consistent
            || case.solidity.gas_overflow_flag
            || case.solidity.reentrancy_detected)
    {
        return VerificationOutcome {
            accepted: false,
            reverted: true,
        };
    }

    if profile == SolidityVerifierProfile::WeakGasOptimization
        && case.public_inputs.is_empty()
        && !case.solidity.public_input_bounds_ok
    {
        return VerificationOutcome {
            accepted: false,
            reverted: false,
        };
    }

    let accepted = match profile {
        SolidityVerifierProfile::StrictParity => {
            case.proof == generate_bound_proof(&case.public_inputs)
        }
        SolidityVerifierProfile::WeakGasOptimization => weak_binding_holds(case),
    };

    VerificationOutcome {
        accepted,
        reverted: false,
    }
}

fn weak_binding_holds(case: &VerificationCase) -> bool {
    if case.proof.len() < MIN_PROOF_BINDING_BYTES {
        return false;
    }
    let expected = generate_bound_proof(&case.public_inputs);
    case.proof
        .iter()
        .zip(expected.iter())
        .take(MIN_PROOF_BINDING_BYTES)
        .all(|(left, right)| left == right)
}

fn generate_valid_case(rng: &mut StdRng, case_index: usize, width: usize) -> VerificationCase {
    let public_inputs = random_public_inputs(rng, width);
    let proof = generate_bound_proof(&public_inputs);
    let calldata = encode_calldata(&proof, &public_inputs);
    VerificationCase {
        proof,
        public_inputs,
        calldata,
        gas_limit: MIN_GAS_REFERENCE
            .saturating_add(5_000)
            .saturating_add(case_index as u64),
        pairing: PairingState {
            equation_valid: true,
            curve_points_valid: true,
            subgroup_valid: true,
            malformed_input: false,
        },
        solidity: SolidityState {
            gas_overflow_flag: false,
            public_input_bounds_ok: true,
            memory_allocation_ok: true,
            calldata_memory_consistent: true,
            reentrancy_detected: false,
            force_revert: false,
        },
    }
}

fn mutate_input_case(
    mut case: VerificationCase,
    mutation: VerifierInputMutation,
    case_index: usize,
    rng: &mut StdRng,
) -> VerificationCase {
    match mutation {
        VerifierInputMutation::ProofByteMutation => {
            let slot = if case.proof.len() > MIN_PROOF_BINDING_BYTES {
                MIN_PROOF_BINDING_BYTES
                    + (case_index % (case.proof.len() - MIN_PROOF_BINDING_BYTES))
            } else {
                case_index % case.proof.len()
            };
            case.proof[slot] ^= 0x01;
            case.calldata = encode_calldata(&case.proof, &case.public_inputs);
        }
        VerifierInputMutation::PublicInputEdgeCase => {
            let boundary_values = [
                "0",
                "1",
                BN254_SCALAR_MODULUS_MINUS_ONE_DECIMAL,
                BN254_SCALAR_MODULUS_DECIMAL,
                BN254_SCALAR_MODULUS_PLUS_ONE_DECIMAL,
            ];
            let slot = case_index % case.public_inputs.len();
            let value = boundary_values[case_index % boundary_values.len()];
            case.public_inputs[slot] = value.to_string();
            case.calldata = encode_calldata(&case.proof, &case.public_inputs);
            case.solidity.public_input_bounds_ok = false;
        }
        VerifierInputMutation::MalformedCalldata => {
            let mut malformed = CALLDATA_SELECTOR.to_vec();
            malformed.extend_from_slice(b"\x00\xffmalformed_abi_payload");
            case.calldata = malformed;
            case.solidity.calldata_memory_consistent = false;
        }
        VerifierInputMutation::GasLimitStress => {
            case.gas_limit = MIN_GAS_WEAK_FAIL_OPEN
                .saturating_add(5_000)
                .saturating_add((case_index as u64) % 10_000);
        }
        VerifierInputMutation::RevertConditionProbe => {
            case.solidity.force_revert = true;
            case.solidity.reentrancy_detected = true;
        }
    }

    if rng.gen_bool(0.05) {
        case.gas_limit = case.gas_limit.saturating_sub(1_000);
    }

    case
}

fn mutate_pairing_case(
    mut case: VerificationCase,
    pairing_case: PairingManipulationCase,
    case_index: usize,
) -> VerificationCase {
    match pairing_case {
        PairingManipulationCase::PairingEquationTamper => {
            case.pairing.equation_valid = false;
        }
        PairingManipulationCase::InvalidCurvePoint => {
            case.pairing.curve_points_valid = false;
        }
        PairingManipulationCase::WrongSubgroupPoint => {
            case.pairing.subgroup_valid = false;
        }
        PairingManipulationCase::MalformedPairingInput => {
            case.pairing.malformed_input = true;
            if case_index.is_multiple_of(2) {
                let mut malformed = CALLDATA_SELECTOR.to_vec();
                malformed.extend_from_slice(b"\x01\x02pairing");
                case.calldata = malformed;
                case.solidity.calldata_memory_consistent = false;
            }
        }
    }
    case
}

fn mutate_solidity_edge_case(
    mut case: VerificationCase,
    edge_case: SolidityEdgeCase,
    case_index: usize,
) -> VerificationCase {
    match edge_case {
        SolidityEdgeCase::GasCalculationOverflow => {
            case.solidity.gas_overflow_flag = true;
            case.gas_limit = u64::MAX.saturating_sub(case_index as u64);
        }
        SolidityEdgeCase::PublicInputArrayBounds => {
            case.solidity.public_input_bounds_ok = false;
            if case.public_inputs.len() > 1 {
                case.public_inputs.pop();
            } else {
                case.public_inputs.clear();
            }
            case.calldata = encode_calldata(&case.proof, &case.public_inputs);
        }
        SolidityEdgeCase::MemoryAllocationEdge => {
            case.solidity.memory_allocation_ok = false;
            case.calldata.extend(std::iter::repeat_n(0xff, 64));
        }
        SolidityEdgeCase::CalldataMemoryConfusion => {
            case.solidity.calldata_memory_consistent = false;
            case.calldata.reverse();
            case.calldata.splice(0..0, CALLDATA_SELECTOR);
        }
        SolidityEdgeCase::ReentrancyCallbackProbe => {
            case.solidity.reentrancy_detected = true;
            case.solidity.force_revert = true;
        }
    }
    case
}

fn dedup_input_mutations(mutations: &[VerifierInputMutation]) -> Vec<VerifierInputMutation> {
    let mut deduped = Vec::new();
    for mutation in mutations {
        if !deduped.contains(mutation) {
            deduped.push(*mutation);
        }
    }
    if deduped.is_empty() {
        VerifierInputMutation::ALL.to_vec()
    } else {
        deduped
    }
}

fn dedup_pairing_cases(cases: &[PairingManipulationCase]) -> Vec<PairingManipulationCase> {
    let mut deduped = Vec::new();
    for pairing_case in cases {
        if !deduped.contains(pairing_case) {
            deduped.push(*pairing_case);
        }
    }
    if deduped.is_empty() {
        PairingManipulationCase::ALL.to_vec()
    } else {
        deduped
    }
}

fn dedup_edge_cases(cases: &[SolidityEdgeCase]) -> Vec<SolidityEdgeCase> {
    let mut deduped = Vec::new();
    for edge_case in cases {
        if !deduped.contains(edge_case) {
            deduped.push(*edge_case);
        }
    }
    if deduped.is_empty() {
        SolidityEdgeCase::ALL.to_vec()
    } else {
        deduped
    }
}

fn random_public_inputs(rng: &mut StdRng, width: usize) -> Vec<String> {
    let mut inputs = Vec::with_capacity(width);
    for slot in 0..width {
        let value = match slot {
            0 => rng.gen_range(1u64..1_000_000_000u64).to_string(),
            1 => rng.gen_range(1u64..10_000u64).to_string(),
            _ => format!("0x{}", random_hex_32(rng)),
        };
        inputs.push(value);
    }
    inputs
}

fn generate_bound_proof(public_inputs: &[String]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CANONICAL_PROOF_LEN);
    for round in 0u8..3u8 {
        let mut hasher = Sha256::new();
        hasher.update(b"zk-track-boundary-solidity-verifier-v1");
        hasher.update([round]);
        for (index, input) in public_inputs.iter().enumerate() {
            hasher.update((index as u64).to_le_bytes());
            hasher.update((input.len() as u64).to_le_bytes());
            hasher.update(input.as_bytes());
        }
        out.extend_from_slice(&hasher.finalize());
    }
    out
}

fn encode_calldata(proof: &[u8], public_inputs: &[String]) -> Vec<u8> {
    let mut calldata = Vec::new();
    calldata.extend_from_slice(&CALLDATA_SELECTOR);
    calldata.extend_from_slice(&(proof.len() as u16).to_le_bytes());
    calldata.extend_from_slice(proof);
    calldata.push(public_inputs.len().min(u8::MAX as usize) as u8);
    for input in public_inputs {
        let bytes = input.as_bytes();
        calldata.push(bytes.len().min(u8::MAX as usize) as u8);
        calldata.extend_from_slice(bytes);
    }
    calldata
}

fn random_hex_32(rng: &mut StdRng) -> String {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    hex_encode(&bytes)
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
    fn strict_profile_matches_reference_on_five_hundred_plus_proofs() {
        let mut config = SolidityVerifierFuzzConfig::new();
        config.seed = 42;
        config.proofs = 500;
        config.optimized_profile = SolidityVerifierProfile::StrictParity;

        let report = run_solidity_verifier_fuzz_campaign(&config);

        assert!(report.differential_checks >= 500);
        assert_eq!(report.differential_divergences, 0);
        assert_eq!(report.optimized_accepts_reference_rejects, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn weak_profile_detects_optimization_divergences() {
        let mut config = SolidityVerifierFuzzConfig::new();
        config.seed = 7;
        config.proofs = 80;
        config.optimized_profile = SolidityVerifierProfile::WeakGasOptimization;

        let report = run_solidity_verifier_fuzz_campaign(&config);

        assert!(report.differential_checks >= 80);
        assert!(report.differential_divergences > 0);
        assert!(report.optimized_accepts_reference_rejects > 0);
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn coverage_maps_include_all_cases() {
        let mut config = SolidityVerifierFuzzConfig::new();
        config.seed = 13;
        config.proofs = 20;

        let report = run_solidity_verifier_fuzz_campaign(&config);

        for mutation in VerifierInputMutation::ALL {
            assert!(
                report
                    .checks_by_input_mutation
                    .get(mutation.as_str())
                    .copied()
                    .unwrap_or(0)
                    > 0
            );
        }
        for pairing_case in PairingManipulationCase::ALL {
            assert!(
                report
                    .checks_by_pairing_case
                    .get(pairing_case.as_str())
                    .copied()
                    .unwrap_or(0)
                    > 0
            );
        }
        for edge_case in SolidityEdgeCase::ALL {
            assert!(
                report
                    .checks_by_edge_case
                    .get(edge_case.as_str())
                    .copied()
                    .unwrap_or(0)
                    > 0
            );
        }
    }
}
