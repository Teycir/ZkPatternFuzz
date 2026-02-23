use std::collections::BTreeMap;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const TRANSPORT_SELECTOR: [u8; 4] = [0x43, 0x50, 0x4f, 0x4d];
const CANONICAL_PROOF_LEN: usize = 96;
const PROOF_PREFIX_BINDING_BYTES: usize = 12;

const PROVER_VERSIONS: [&str; 3] = ["1.0.0", "1.1.0", "2.0.0"];
const VERIFIER_VERSIONS: [&str; 3] = ["1.0.0", "1.1.0", "2.0.0"];
const CIRCUIT_FLAGS: [&str; 3] = ["std", "fast_math", "unsafe_optim"];
const TRUSTED_SETUPS: [&str; 2] = ["ptau28", "ptau29"];
const CURVES: [&str; 2] = ["bn254", "bls12_381"];
const MATRIX_COMBINATIONS: usize = PROVER_VERSIONS.len()
    * VERIFIER_VERSIONS.len()
    * CIRCUIT_FLAGS.len()
    * TRUSTED_SETUPS.len()
    * CURVES.len();

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowFaultStage {
    CircuitStage,
    ProverStage,
    VerifierStage,
    TransportBoundary,
}

impl WorkflowFaultStage {
    pub const ALL: [WorkflowFaultStage; 4] = [
        Self::CircuitStage,
        Self::ProverStage,
        Self::VerifierStage,
        Self::TransportBoundary,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CircuitStage => "circuit_stage",
            Self::ProverStage => "prover_stage",
            Self::VerifierStage => "verifier_stage",
            Self::TransportBoundary => "transport_boundary",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ComponentMismatchCase {
    ProverVerifierVersionMismatch,
    CircuitVerifierFlagMismatch,
    TrustedSetupMismatch,
    CurveParameterMismatch,
}

impl ComponentMismatchCase {
    pub const ALL: [ComponentMismatchCase; 4] = [
        Self::ProverVerifierVersionMismatch,
        Self::CircuitVerifierFlagMismatch,
        Self::TrustedSetupMismatch,
        Self::CurveParameterMismatch,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProverVerifierVersionMismatch => "prover_verifier_version_mismatch",
            Self::CircuitVerifierFlagMismatch => "circuit_verifier_flag_mismatch",
            Self::TrustedSetupMismatch => "trusted_setup_mismatch",
            Self::CurveParameterMismatch => "curve_parameter_mismatch",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CrossComponentVerifierProfile {
    StrictCompatibility,
    WeakMismatchAcceptance,
}

impl CrossComponentVerifierProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StrictCompatibility => "strict_compatibility",
            Self::WeakMismatchAcceptance => "weak_mismatch_acceptance",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossComponentFuzzConfig {
    pub seed: u64,
    pub combinations: usize,
    pub public_inputs_per_case: usize,
    pub fault_stages: Vec<WorkflowFaultStage>,
    pub mismatch_cases: Vec<ComponentMismatchCase>,
    pub verifier_profile: CrossComponentVerifierProfile,
}

impl CrossComponentFuzzConfig {
    pub fn new() -> Self {
        Self {
            seed: 20_260_223,
            combinations: 60,
            public_inputs_per_case: 3,
            fault_stages: WorkflowFaultStage::ALL.to_vec(),
            mismatch_cases: ComponentMismatchCase::ALL.to_vec(),
            verifier_profile: CrossComponentVerifierProfile::StrictCompatibility,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossComponentFinding {
    pub case_id: String,
    pub category: String,
    pub test_case: String,
    pub reason: String,
    pub reference_accepted: bool,
    pub candidate_accepted: bool,
    pub reference_reverted: bool,
    pub candidate_reverted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossComponentFuzzReport {
    pub seed: u64,
    pub combinations: usize,
    pub configuration_combinations_tested: usize,
    pub public_inputs_per_case: usize,
    pub verifier_profile: CrossComponentVerifierProfile,
    pub total_checks: usize,
    pub end_to_end_checks: usize,
    pub boundary_checks: usize,
    pub fault_injection_checks: usize,
    pub mismatch_checks: usize,
    pub differential_divergences: usize,
    pub candidate_accepts_reference_rejects: usize,
    pub reference_accepts_candidate_rejects: usize,
    pub checks_by_fault_stage: BTreeMap<String, usize>,
    pub divergences_by_fault_stage: BTreeMap<String, usize>,
    pub checks_by_mismatch_case: BTreeMap<String, usize>,
    pub divergences_by_mismatch_case: BTreeMap<String, usize>,
    pub findings: Vec<CrossComponentFinding>,
}

pub fn run_cross_component_fuzz_campaign(
    config: &CrossComponentFuzzConfig,
) -> CrossComponentFuzzReport {
    let mut rng = StdRng::seed_from_u64(config.seed);
    let combinations = config.combinations.max(1);
    let width = config.public_inputs_per_case.max(1);
    let fault_stages = dedup_fault_stages(&config.fault_stages);
    let mismatch_cases = dedup_mismatch_cases(&config.mismatch_cases);
    let mut combinations_seen: BTreeMap<String, ()> = BTreeMap::new();

    let mut report = CrossComponentFuzzReport {
        seed: config.seed,
        combinations,
        configuration_combinations_tested: 0,
        public_inputs_per_case: width,
        verifier_profile: config.verifier_profile,
        total_checks: 0,
        end_to_end_checks: 0,
        boundary_checks: 0,
        fault_injection_checks: 0,
        mismatch_checks: 0,
        differential_divergences: 0,
        candidate_accepts_reference_rejects: 0,
        reference_accepts_candidate_rejects: 0,
        checks_by_fault_stage: BTreeMap::new(),
        divergences_by_fault_stage: BTreeMap::new(),
        checks_by_mismatch_case: BTreeMap::new(),
        divergences_by_mismatch_case: BTreeMap::new(),
        findings: Vec::new(),
    };

    for case_index in 0..combinations {
        let combination = component_combination_at(case_index);
        combinations_seen.insert(combination.key(), ());
        let case_id = format!("combo_{case_index:05}");
        let base_case = generate_valid_case(&mut rng, combination, width);

        compare_case(
            &mut report,
            &case_id,
            "end_to_end_workflow_testing",
            "full_pipeline",
            &base_case,
            config.verifier_profile,
            None,
            None,
        );
        report.end_to_end_checks += 1;

        for stage in &fault_stages {
            let faulted = inject_stage_fault(base_case.clone(), *stage, case_index);
            *report
                .checks_by_fault_stage
                .entry(stage.as_str().to_string())
                .or_insert(0) += 1;
            report.fault_injection_checks += 1;
            if *stage == WorkflowFaultStage::TransportBoundary {
                report.boundary_checks += 1;
            }
            compare_case(
                &mut report,
                &case_id,
                "end_to_end_workflow_testing",
                stage.as_str(),
                &faulted,
                config.verifier_profile,
                Some(stage.as_str()),
                None,
            );
        }

        for mismatch_case in &mismatch_cases {
            let mismatched =
                apply_component_mismatch(base_case.clone(), *mismatch_case, case_index);
            *report
                .checks_by_mismatch_case
                .entry(mismatch_case.as_str().to_string())
                .or_insert(0) += 1;
            report.mismatch_checks += 1;
            compare_case(
                &mut report,
                &case_id,
                "component_mismatch_detection",
                mismatch_case.as_str(),
                &mismatched,
                config.verifier_profile,
                None,
                Some(mismatch_case.as_str()),
            );
        }
    }

    report.configuration_combinations_tested = combinations_seen.len();
    report
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CrossComponentCase {
    combination: ComponentCombination,
    public_inputs: Vec<String>,
    proof: Vec<u8>,
    transport: TransportFrame,
    fault_state: FaultState,
    mismatch_state: MismatchState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ComponentCombination {
    prover_version: String,
    verifier_version: String,
    circuit_flag: String,
    verifier_expected_flag: String,
    trusted_setup: String,
    verifier_expected_setup: String,
    curve: String,
    verifier_expected_curve: String,
}

impl ComponentCombination {
    fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.prover_version,
            self.verifier_version,
            self.circuit_flag,
            self.trusted_setup,
            self.curve
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransportFrame {
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FaultState {
    circuit_fault: bool,
    prover_fault: bool,
    verifier_fault: bool,
    boundary_fault: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MismatchState {
    version_match: bool,
    flag_match: bool,
    trusted_setup_match: bool,
    curve_match: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerificationOutcome {
    accepted: bool,
    reverted: bool,
}

fn compare_case(
    report: &mut CrossComponentFuzzReport,
    case_id: &str,
    category: &str,
    test_case: &str,
    case: &CrossComponentCase,
    profile: CrossComponentVerifierProfile,
    fault_stage_key: Option<&str>,
    mismatch_key: Option<&str>,
) {
    let reference = verify_case(CrossComponentVerifierProfile::StrictCompatibility, case);
    let candidate = verify_case(profile, case);

    report.total_checks += 1;

    if let Some(reason) = divergence_reason(reference, candidate) {
        report.differential_divergences += 1;
        if !reference.accepted && candidate.accepted {
            report.candidate_accepts_reference_rejects += 1;
        }
        if reference.accepted && !candidate.accepted {
            report.reference_accepts_candidate_rejects += 1;
        }
        if let Some(key) = fault_stage_key {
            *report
                .divergences_by_fault_stage
                .entry(key.to_string())
                .or_insert(0) += 1;
        }
        if let Some(key) = mismatch_key {
            *report
                .divergences_by_mismatch_case
                .entry(key.to_string())
                .or_insert(0) += 1;
        }
        report.findings.push(CrossComponentFinding {
            case_id: format!("{case_id}_{category}_{test_case}"),
            category: category.to_string(),
            test_case: test_case.to_string(),
            reason: reason.to_string(),
            reference_accepted: reference.accepted,
            candidate_accepted: candidate.accepted,
            reference_reverted: reference.reverted,
            candidate_reverted: candidate.reverted,
        });
    }
}

fn divergence_reason(
    reference: VerificationOutcome,
    candidate: VerificationOutcome,
) -> Option<&'static str> {
    if reference == candidate {
        return None;
    }
    if !reference.accepted && candidate.accepted {
        return Some("candidate pipeline accepted case rejected by strict reference");
    }
    if reference.accepted && !candidate.accepted {
        return Some("candidate pipeline rejected case accepted by strict reference");
    }
    Some("candidate pipeline diverged on revert handling")
}

fn verify_case(
    profile: CrossComponentVerifierProfile,
    case: &CrossComponentCase,
) -> VerificationOutcome {
    if case.fault_state.circuit_fault {
        return VerificationOutcome {
            accepted: false,
            reverted: false,
        };
    }

    if case.fault_state.boundary_fault {
        if profile == CrossComponentVerifierProfile::StrictCompatibility {
            return VerificationOutcome {
                accepted: false,
                reverted: true,
            };
        }
        if !case.transport.payload.starts_with(&TRANSPORT_SELECTOR) {
            return VerificationOutcome {
                accepted: false,
                reverted: false,
            };
        }
    }

    let canonical_transport = encode_transport(
        &case.proof,
        &case.public_inputs,
        &case.combination.prover_version,
        &case.combination.circuit_flag,
        &case.combination.trusted_setup,
        &case.combination.curve,
    );
    if profile == CrossComponentVerifierProfile::StrictCompatibility
        && case.transport.payload != canonical_transport
    {
        return VerificationOutcome {
            accepted: false,
            reverted: true,
        };
    }

    if profile == CrossComponentVerifierProfile::StrictCompatibility {
        if case.fault_state.prover_fault || case.fault_state.verifier_fault {
            return VerificationOutcome {
                accepted: false,
                reverted: false,
            };
        }
        if !case.mismatch_state.version_match
            || !case.mismatch_state.flag_match
            || !case.mismatch_state.trusted_setup_match
            || !case.mismatch_state.curve_match
        {
            return VerificationOutcome {
                accepted: false,
                reverted: false,
            };
        }
        let expected_proof = generate_bound_proof(
            &case.public_inputs,
            &case.combination.prover_version,
            &case.combination.circuit_flag,
            &case.combination.trusted_setup,
            &case.combination.curve,
        );
        return VerificationOutcome {
            accepted: case.proof == expected_proof,
            reverted: false,
        };
    }

    if case.fault_state.verifier_fault {
        return VerificationOutcome {
            accepted: true,
            reverted: false,
        };
    }

    if case.proof.len() < PROOF_PREFIX_BINDING_BYTES
        || case.transport.payload.len() < TRANSPORT_SELECTOR.len()
    {
        return VerificationOutcome {
            accepted: false,
            reverted: false,
        };
    }

    let expected_prefix = generate_bound_proof(
        &case.public_inputs,
        &case.combination.prover_version,
        &case.combination.circuit_flag,
        &case.combination.trusted_setup,
        &case.combination.curve,
    );
    let prefix_matches = case
        .proof
        .iter()
        .zip(expected_prefix.iter())
        .take(PROOF_PREFIX_BINDING_BYTES)
        .all(|(left, right)| left == right);

    if !prefix_matches {
        return VerificationOutcome {
            accepted: false,
            reverted: false,
        };
    }

    if !case.mismatch_state.curve_match {
        return VerificationOutcome {
            accepted: false,
            reverted: false,
        };
    }

    VerificationOutcome {
        accepted: true,
        reverted: false,
    }
}

fn generate_valid_case(
    rng: &mut StdRng,
    combination: ComponentCombination,
    width: usize,
) -> CrossComponentCase {
    let public_inputs = random_public_inputs(rng, width);
    let proof = generate_bound_proof(
        &public_inputs,
        &combination.prover_version,
        &combination.circuit_flag,
        &combination.trusted_setup,
        &combination.curve,
    );
    let transport = TransportFrame {
        payload: encode_transport(
            &proof,
            &public_inputs,
            &combination.prover_version,
            &combination.circuit_flag,
            &combination.trusted_setup,
            &combination.curve,
        ),
    };

    CrossComponentCase {
        combination,
        public_inputs,
        proof,
        transport,
        fault_state: FaultState {
            circuit_fault: false,
            prover_fault: false,
            verifier_fault: false,
            boundary_fault: false,
        },
        mismatch_state: MismatchState {
            version_match: true,
            flag_match: true,
            trusted_setup_match: true,
            curve_match: true,
        },
    }
}

fn inject_stage_fault(
    mut case: CrossComponentCase,
    stage: WorkflowFaultStage,
    case_index: usize,
) -> CrossComponentCase {
    match stage {
        WorkflowFaultStage::CircuitStage => {
            case.fault_state.circuit_fault = true;
            if !case.public_inputs.is_empty() {
                case.public_inputs[0].push_str("_invalid_constraint");
            }
            case.transport.payload = encode_transport(
                &case.proof,
                &case.public_inputs,
                &case.combination.prover_version,
                &case.combination.circuit_flag,
                &case.combination.trusted_setup,
                &case.combination.curve,
            );
        }
        WorkflowFaultStage::ProverStage => {
            case.fault_state.prover_fault = true;
            if case.proof.len() > PROOF_PREFIX_BINDING_BYTES {
                let slot = PROOF_PREFIX_BINDING_BYTES
                    + (case_index % (case.proof.len() - PROOF_PREFIX_BINDING_BYTES));
                case.proof[slot] ^= 0x01;
            } else if !case.proof.is_empty() {
                case.proof[0] ^= 0x01;
            }
            case.transport.payload = encode_transport(
                &case.proof,
                &case.public_inputs,
                &case.combination.prover_version,
                &case.combination.circuit_flag,
                &case.combination.trusted_setup,
                &case.combination.curve,
            );
        }
        WorkflowFaultStage::VerifierStage => {
            case.fault_state.verifier_fault = true;
        }
        WorkflowFaultStage::TransportBoundary => {
            case.fault_state.boundary_fault = true;
            case.transport.payload =
                truncate_transport_payload(&case.transport.payload, case_index);
        }
    }
    case
}

fn apply_component_mismatch(
    mut case: CrossComponentCase,
    mismatch_case: ComponentMismatchCase,
    case_index: usize,
) -> CrossComponentCase {
    match mismatch_case {
        ComponentMismatchCase::ProverVerifierVersionMismatch => {
            case.mismatch_state.version_match = false;
            case.combination.verifier_version = if case.combination.prover_version.starts_with("2.")
            {
                "1.0.0".to_string()
            } else {
                "2.0.0".to_string()
            };
        }
        ComponentMismatchCase::CircuitVerifierFlagMismatch => {
            case.mismatch_state.flag_match = false;
            case.combination.verifier_expected_flag = if case.combination.circuit_flag == "std" {
                "unsafe_optim".to_string()
            } else {
                "std".to_string()
            };
        }
        ComponentMismatchCase::TrustedSetupMismatch => {
            case.mismatch_state.trusted_setup_match = false;
            case.combination.verifier_expected_setup = if case.combination.trusted_setup == "ptau28"
            {
                "ptau29".to_string()
            } else {
                "ptau28".to_string()
            };
        }
        ComponentMismatchCase::CurveParameterMismatch => {
            case.mismatch_state.curve_match = false;
            case.combination.verifier_expected_curve = if case.combination.curve == "bn254" {
                "bls12_381".to_string()
            } else {
                "bn254".to_string()
            };
        }
    }

    if case_index % 2 == 0 {
        case.transport.payload = encode_transport(
            &case.proof,
            &case.public_inputs,
            &case.combination.prover_version,
            &case.combination.circuit_flag,
            &case.combination.trusted_setup,
            &case.combination.curve,
        );
    }

    case
}

fn dedup_fault_stages(stages: &[WorkflowFaultStage]) -> Vec<WorkflowFaultStage> {
    let mut deduped = Vec::new();
    for stage in stages {
        if !deduped.contains(stage) {
            deduped.push(*stage);
        }
    }
    if deduped.is_empty() {
        WorkflowFaultStage::ALL.to_vec()
    } else {
        deduped
    }
}

fn dedup_mismatch_cases(cases: &[ComponentMismatchCase]) -> Vec<ComponentMismatchCase> {
    let mut deduped = Vec::new();
    for mismatch_case in cases {
        if !deduped.contains(mismatch_case) {
            deduped.push(*mismatch_case);
        }
    }
    if deduped.is_empty() {
        ComponentMismatchCase::ALL.to_vec()
    } else {
        deduped
    }
}

fn random_public_inputs(rng: &mut StdRng, width: usize) -> Vec<String> {
    let mut inputs = Vec::with_capacity(width);
    for slot in 0..width {
        let value = match slot {
            0 => rng.gen_range(1u64..1_000_000_000u64).to_string(),
            1 => rng.gen_range(1u64..100_000u64).to_string(),
            _ => format!("0x{}", random_hex_32(rng)),
        };
        inputs.push(value);
    }
    inputs
}

fn component_combination_at(index: usize) -> ComponentCombination {
    let idx = index % MATRIX_COMBINATIONS;
    let prover_idx = idx % PROVER_VERSIONS.len();
    let verifier_idx = (idx / PROVER_VERSIONS.len()) % VERIFIER_VERSIONS.len();
    let flag_idx = (idx / (PROVER_VERSIONS.len() * VERIFIER_VERSIONS.len())) % CIRCUIT_FLAGS.len();
    let setup_idx = (idx / (PROVER_VERSIONS.len() * VERIFIER_VERSIONS.len() * CIRCUIT_FLAGS.len()))
        % TRUSTED_SETUPS.len();
    let curve_idx = (idx
        / (PROVER_VERSIONS.len()
            * VERIFIER_VERSIONS.len()
            * CIRCUIT_FLAGS.len()
            * TRUSTED_SETUPS.len()))
        % CURVES.len();

    let prover_version = PROVER_VERSIONS[prover_idx].to_string();
    let verifier_version = VERIFIER_VERSIONS[verifier_idx].to_string();
    let circuit_flag = CIRCUIT_FLAGS[flag_idx].to_string();
    let trusted_setup = TRUSTED_SETUPS[setup_idx].to_string();
    let curve = CURVES[curve_idx].to_string();

    ComponentCombination {
        prover_version: prover_version.clone(),
        verifier_version: verifier_version.clone(),
        circuit_flag: circuit_flag.clone(),
        verifier_expected_flag: circuit_flag,
        trusted_setup: trusted_setup.clone(),
        verifier_expected_setup: trusted_setup,
        curve: curve.clone(),
        verifier_expected_curve: curve,
    }
}

fn generate_bound_proof(
    public_inputs: &[String],
    prover_version: &str,
    circuit_flag: &str,
    trusted_setup: &str,
    curve: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CANONICAL_PROOF_LEN);
    for round in 0u8..3u8 {
        let mut hasher = Sha256::new();
        hasher.update(b"zk-track-boundary-cross-component-v1");
        hasher.update([round]);
        hasher.update((prover_version.len() as u64).to_le_bytes());
        hasher.update(prover_version.as_bytes());
        hasher.update((circuit_flag.len() as u64).to_le_bytes());
        hasher.update(circuit_flag.as_bytes());
        hasher.update((trusted_setup.len() as u64).to_le_bytes());
        hasher.update(trusted_setup.as_bytes());
        hasher.update((curve.len() as u64).to_le_bytes());
        hasher.update(curve.as_bytes());
        for (index, input) in public_inputs.iter().enumerate() {
            hasher.update((index as u64).to_le_bytes());
            hasher.update((input.len() as u64).to_le_bytes());
            hasher.update(input.as_bytes());
        }
        out.extend_from_slice(&hasher.finalize());
    }
    out
}

fn encode_transport(
    proof: &[u8],
    public_inputs: &[String],
    prover_version: &str,
    circuit_flag: &str,
    trusted_setup: &str,
    curve: &str,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&TRANSPORT_SELECTOR);
    append_field(&mut payload, prover_version.as_bytes());
    append_field(&mut payload, circuit_flag.as_bytes());
    append_field(&mut payload, trusted_setup.as_bytes());
    append_field(&mut payload, curve.as_bytes());
    append_field(&mut payload, proof);
    payload.push(public_inputs.len().min(u8::MAX as usize) as u8);
    for input in public_inputs {
        append_field(&mut payload, input.as_bytes());
    }
    payload
}

fn append_field(payload: &mut Vec<u8>, bytes: &[u8]) {
    payload.extend_from_slice(&(bytes.len().min(u16::MAX as usize) as u16).to_le_bytes());
    payload.extend_from_slice(bytes);
}

fn truncate_transport_payload(payload: &[u8], case_index: usize) -> Vec<u8> {
    if payload.is_empty() {
        return Vec::new();
    }
    let truncate = 1 + (case_index % 24);
    payload[..payload.len().saturating_sub(truncate)].to_vec()
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
    fn strict_profile_runs_fifty_plus_configurations_with_zero_divergence() {
        let mut config = CrossComponentFuzzConfig::new();
        config.seed = 42;
        config.combinations = 60;
        config.verifier_profile = CrossComponentVerifierProfile::StrictCompatibility;

        let report = run_cross_component_fuzz_campaign(&config);

        assert!(report.configuration_combinations_tested >= 50);
        assert_eq!(report.differential_divergences, 0);
        assert_eq!(report.candidate_accepts_reference_rejects, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn weak_profile_detects_component_mismatch_acceptance_bug() {
        let mut config = CrossComponentFuzzConfig::new();
        config.seed = 7;
        config.combinations = 60;
        config.verifier_profile = CrossComponentVerifierProfile::WeakMismatchAcceptance;

        let report = run_cross_component_fuzz_campaign(&config);

        assert!(report.configuration_combinations_tested >= 50);
        assert!(report.candidate_accepts_reference_rejects > 0);
        assert!(report.differential_divergences > 0);
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn every_fault_stage_and_mismatch_case_is_exercised() {
        let mut config = CrossComponentFuzzConfig::new();
        config.seed = 123;
        config.combinations = 12;

        let report = run_cross_component_fuzz_campaign(&config);

        for stage in WorkflowFaultStage::ALL {
            assert!(
                report
                    .checks_by_fault_stage
                    .get(stage.as_str())
                    .copied()
                    .unwrap_or(0)
                    > 0
            );
        }
        for mismatch_case in ComponentMismatchCase::ALL {
            assert!(
                report
                    .checks_by_mismatch_case
                    .get(mismatch_case.as_str())
                    .copied()
                    .unwrap_or(0)
                    > 0
            );
        }
    }
}
