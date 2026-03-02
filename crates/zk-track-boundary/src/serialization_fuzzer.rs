use std::collections::BTreeMap;

use base64::Engine;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CANONICAL_PROOF_LEN: usize = 96;
const MIN_PREFIX_BINDING_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SerializationFormat {
    Binary,
    Hex,
    Base64,
}

impl SerializationFormat {
    pub const ALL: [SerializationFormat; 3] = [Self::Binary, Self::Hex, Self::Base64];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Hex => "hex",
            Self::Base64 => "base64",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProofSerializationEdgeCase {
    EmptyProof,
    TruncatedProof,
    OversizedProof,
    InvalidEncoding,
    EndiannessConfusion,
    PaddingConfusion,
}

impl ProofSerializationEdgeCase {
    pub const ALL: [ProofSerializationEdgeCase; 6] = [
        Self::EmptyProof,
        Self::TruncatedProof,
        Self::OversizedProof,
        Self::InvalidEncoding,
        Self::EndiannessConfusion,
        Self::PaddingConfusion,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmptyProof => "empty_proof",
            Self::TruncatedProof => "truncated_proof",
            Self::OversizedProof => "oversized_proof",
            Self::InvalidEncoding => "invalid_encoding",
            Self::EndiannessConfusion => "endianness_confusion",
            Self::PaddingConfusion => "padding_confusion",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PublicInputSerializationEdgeCase {
    ArrayLengthMismatch,
    TypeConfusion,
    EncodingVariant,
    DelimiterConfusion,
}

impl PublicInputSerializationEdgeCase {
    pub const ALL: [PublicInputSerializationEdgeCase; 4] = [
        Self::ArrayLengthMismatch,
        Self::TypeConfusion,
        Self::EncodingVariant,
        Self::DelimiterConfusion,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArrayLengthMismatch => "array_length_mismatch",
            Self::TypeConfusion => "type_confusion",
            Self::EncodingVariant => "encoding_variant",
            Self::DelimiterConfusion => "delimiter_confusion",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CrossLanguageSerializationCase {
    RustToSnarkjs,
    CircomToSolidityAbi,
    NoirToTypescriptJson,
    LanguageAToLanguageB,
}

impl CrossLanguageSerializationCase {
    pub const ALL: [CrossLanguageSerializationCase; 4] = [
        Self::RustToSnarkjs,
        Self::CircomToSolidityAbi,
        Self::NoirToTypescriptJson,
        Self::LanguageAToLanguageB,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RustToSnarkjs => "rust_to_snarkjs",
            Self::CircomToSolidityAbi => "circom_to_solidity_abi",
            Self::NoirToTypescriptJson => "noir_to_typescript_json",
            Self::LanguageAToLanguageB => "language_a_to_language_b",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SerializationVerifierProfile {
    StrictCanonical,
    LenientLegacy,
}

impl SerializationVerifierProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StrictCanonical => "strict_canonical",
            Self::LenientLegacy => "lenient_legacy",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerializationFuzzConfig {
    pub seed: u64,
    pub cases_per_format: usize,
    pub formats: Vec<SerializationFormat>,
    pub verifier_profile: SerializationVerifierProfile,
}

impl SerializationFuzzConfig {
    pub fn new() -> Self {
        Self {
            seed: 20_260_223,
            cases_per_format: 12,
            formats: SerializationFormat::ALL.to_vec(),
            verifier_profile: SerializationVerifierProfile::StrictCanonical,
        }
    }
}

impl Default for SerializationFuzzConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerializationFuzzFinding {
    pub case_id: String,
    pub format: SerializationFormat,
    pub category: String,
    pub edge_case: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerializationFuzzReport {
    pub seed: u64,
    pub cases_per_format: usize,
    pub verifier_profile: SerializationVerifierProfile,
    pub formats: Vec<SerializationFormat>,
    pub checks_by_format: BTreeMap<String, usize>,
    pub proof_case_checks: BTreeMap<String, usize>,
    pub public_input_case_checks: BTreeMap<String, usize>,
    pub cross_language_case_checks: BTreeMap<String, usize>,
    pub total_checks: usize,
    pub rejected_invalid_cases: usize,
    pub accepted_invalid_cases: usize,
    pub findings: Vec<SerializationFuzzFinding>,
}

pub fn run_serialization_fuzz_campaign(
    config: &SerializationFuzzConfig,
) -> SerializationFuzzReport {
    let mut rng = StdRng::seed_from_u64(config.seed);
    let mut checks_by_format: BTreeMap<String, usize> = BTreeMap::new();
    let mut proof_case_checks: BTreeMap<String, usize> = BTreeMap::new();
    let mut public_input_case_checks: BTreeMap<String, usize> = BTreeMap::new();
    let mut cross_language_case_checks: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_checks = 0usize;
    let mut rejected_invalid_cases = 0usize;
    let mut accepted_invalid_cases = 0usize;
    let mut findings = Vec::new();

    let formats = dedup_formats(&config.formats);
    let cases_per_format = config.cases_per_format.max(1);

    for format in &formats {
        let format_key = format.as_str().to_string();
        for case_index in 0..cases_per_format {
            let case = generate_case(&mut rng, case_index);
            let encoded_proof = encode_proof(&case.proof_bytes, *format);
            let encoded_inputs = encode_public_inputs(&case.public_inputs, *format);

            for proof_case in ProofSerializationEdgeCase::ALL {
                let mutated_proof =
                    mutate_proof_payload(*format, &encoded_proof, proof_case, case_index, &mut rng);
                let accepted = verify_mutated_payload(
                    config.verifier_profile,
                    *format,
                    &mutated_proof,
                    &encoded_inputs,
                    &case.proof_bytes,
                    &case.public_inputs,
                );
                let case_id = format!("{format_key}_proof_{case_index:05}_{}", proof_case.as_str());
                record_result(
                    accepted,
                    &mut total_checks,
                    &mut rejected_invalid_cases,
                    &mut accepted_invalid_cases,
                    &mut checks_by_format,
                    &mut proof_case_checks,
                    &mut findings,
                    &format_key,
                    *format,
                    case_id,
                    "proof_serialization".to_string(),
                    proof_case.as_str().to_string(),
                    "Verifier accepted malformed proof serialization".to_string(),
                );
            }

            for input_case in PublicInputSerializationEdgeCase::ALL {
                let mutated_inputs =
                    mutate_public_inputs_payload(*format, &encoded_inputs, input_case, case_index);
                let accepted = verify_mutated_payload(
                    config.verifier_profile,
                    *format,
                    &encoded_proof,
                    &mutated_inputs,
                    &case.proof_bytes,
                    &case.public_inputs,
                );
                let case_id = format!(
                    "{format_key}_inputs_{case_index:05}_{}",
                    input_case.as_str()
                );
                record_result(
                    accepted,
                    &mut total_checks,
                    &mut rejected_invalid_cases,
                    &mut accepted_invalid_cases,
                    &mut checks_by_format,
                    &mut public_input_case_checks,
                    &mut findings,
                    &format_key,
                    *format,
                    case_id,
                    "public_input_serialization".to_string(),
                    input_case.as_str().to_string(),
                    "Verifier accepted malformed public input serialization".to_string(),
                );
            }

            for language_case in CrossLanguageSerializationCase::ALL {
                let (mutated_proof, mutated_inputs) = mutate_cross_language_payload(
                    *format,
                    &encoded_proof,
                    &encoded_inputs,
                    language_case,
                    case_index,
                );
                let accepted = verify_mutated_payload(
                    config.verifier_profile,
                    *format,
                    &mutated_proof,
                    &mutated_inputs,
                    &case.proof_bytes,
                    &case.public_inputs,
                );
                let case_id = format!(
                    "{format_key}_cross_lang_{case_index:05}_{}",
                    language_case.as_str()
                );
                record_result(
                    accepted,
                    &mut total_checks,
                    &mut rejected_invalid_cases,
                    &mut accepted_invalid_cases,
                    &mut checks_by_format,
                    &mut cross_language_case_checks,
                    &mut findings,
                    &format_key,
                    *format,
                    case_id,
                    "cross_language_serialization".to_string(),
                    language_case.as_str().to_string(),
                    "Verifier accepted mismatched cross-language serialization".to_string(),
                );
            }
        }
    }

    SerializationFuzzReport {
        seed: config.seed,
        cases_per_format,
        verifier_profile: config.verifier_profile,
        formats,
        checks_by_format,
        proof_case_checks,
        public_input_case_checks,
        cross_language_case_checks,
        total_checks,
        rejected_invalid_cases,
        accepted_invalid_cases,
        findings,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SerializationCase {
    proof_bytes: Vec<u8>,
    public_inputs: Vec<String>,
}

fn dedup_formats(formats: &[SerializationFormat]) -> Vec<SerializationFormat> {
    let mut deduped = Vec::new();
    for format in formats {
        if !deduped.contains(format) {
            deduped.push(*format);
        }
    }
    if deduped.is_empty() {
        SerializationFormat::ALL.to_vec()
    } else {
        deduped
    }
}

fn generate_case(rng: &mut StdRng, case_index: usize) -> SerializationCase {
    let public_inputs = vec![
        rng.gen_range(1u64..1_000_000_000u64).to_string(),
        rng.gen_range(1u64..100_000u64).to_string(),
        random_hex_32(rng),
    ];
    let proof_bytes = generate_bound_proof(&public_inputs, case_index as u64);
    SerializationCase {
        proof_bytes,
        public_inputs,
    }
}

fn generate_bound_proof(public_inputs: &[String], nonce: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(CANONICAL_PROOF_LEN);
    for round in 0u8..3u8 {
        let mut hasher = Sha256::new();
        hasher.update(b"zk-track-boundary-serialization-v1");
        hasher.update(nonce.to_le_bytes());
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

fn encode_proof(proof_bytes: &[u8], format: SerializationFormat) -> Vec<u8> {
    match format {
        SerializationFormat::Binary => proof_bytes.to_vec(),
        SerializationFormat::Hex => hex_encode(proof_bytes).into_bytes(),
        SerializationFormat::Base64 => base64::engine::general_purpose::STANDARD
            .encode(proof_bytes)
            .into_bytes(),
    }
}

fn decode_proof(
    profile: SerializationVerifierProfile,
    encoded: &[u8],
    format: SerializationFormat,
) -> Option<Vec<u8>> {
    match profile {
        SerializationVerifierProfile::StrictCanonical => decode_proof_strict(encoded, format),
        SerializationVerifierProfile::LenientLegacy => decode_proof_lenient(encoded, format),
    }
}

fn decode_proof_strict(encoded: &[u8], format: SerializationFormat) -> Option<Vec<u8>> {
    let decoded = match format {
        SerializationFormat::Binary => encoded.to_vec(),
        SerializationFormat::Hex => hex_decode(encoded)?,
        SerializationFormat::Base64 => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?,
    };

    if decoded.len() != CANONICAL_PROOF_LEN {
        return None;
    }

    if decoded
        .chunks(32)
        .any(|chunk| chunk.iter().all(|byte| *byte == 0xff))
    {
        return None;
    }

    Some(decoded)
}

fn decode_proof_lenient(encoded: &[u8], format: SerializationFormat) -> Option<Vec<u8>> {
    let mut decoded = match format {
        SerializationFormat::Binary => encoded.to_vec(),
        SerializationFormat::Hex => tolerant_hex_decode(encoded),
        SerializationFormat::Base64 => tolerant_base64_decode(encoded),
    };

    if decoded.len() < CANONICAL_PROOF_LEN {
        decoded.resize(CANONICAL_PROOF_LEN, 0u8);
    }
    if decoded.len() > CANONICAL_PROOF_LEN {
        decoded.truncate(CANONICAL_PROOF_LEN);
    }
    Some(decoded)
}

fn encode_public_inputs(public_inputs: &[String], format: SerializationFormat) -> Vec<u8> {
    let json = serde_json::to_vec(public_inputs).unwrap_or_else(|_| b"[]".to_vec());
    match format {
        SerializationFormat::Binary => json,
        SerializationFormat::Hex => hex_encode(&json).into_bytes(),
        SerializationFormat::Base64 => base64::engine::general_purpose::STANDARD
            .encode(json)
            .into_bytes(),
    }
}

fn decode_public_inputs(
    profile: SerializationVerifierProfile,
    encoded: &[u8],
    format: SerializationFormat,
    expected_len: usize,
) -> Option<Vec<String>> {
    match profile {
        SerializationVerifierProfile::StrictCanonical => {
            let decoded_bytes = decode_payload_bytes_strict(encoded, format)?;
            let parsed: Vec<String> = serde_json::from_slice(&decoded_bytes).ok()?;
            if parsed.len() != expected_len {
                return None;
            }
            Some(parsed)
        }
        SerializationVerifierProfile::LenientLegacy => {
            let decoded_bytes = decode_payload_bytes_lenient(encoded, format)?;
            if let Ok(parsed) = serde_json::from_slice::<Vec<String>>(&decoded_bytes) {
                return Some(normalize_lenient_inputs(parsed, expected_len));
            }
            if let Ok(wrapper) = serde_json::from_slice::<LenientInputsWrapper>(&decoded_bytes) {
                return Some(normalize_lenient_inputs(wrapper.inputs, expected_len));
            }
            let text = String::from_utf8_lossy(&decoded_bytes);
            let tokens: Vec<String> = text
                .trim_matches(|ch| ch == '[' || ch == ']')
                .split([',', ' ', '\n', '|'])
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(|token| token.trim_matches('"').to_string())
                .collect();
            Some(normalize_lenient_inputs(tokens, expected_len))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LenientInputsWrapper {
    inputs: Vec<String>,
}

fn normalize_lenient_inputs(mut inputs: Vec<String>, expected_len: usize) -> Vec<String> {
    if expected_len == 0 {
        return Vec::new();
    }
    if inputs.is_empty() {
        inputs.push("0".to_string());
    }
    if inputs.len() < expected_len {
        let fill = inputs.first().cloned().unwrap_or_else(|| "0".to_string());
        while inputs.len() < expected_len {
            inputs.push(fill.clone());
        }
    }
    if inputs.len() > expected_len {
        inputs.truncate(expected_len);
    }
    inputs
}

fn decode_payload_bytes_strict(encoded: &[u8], format: SerializationFormat) -> Option<Vec<u8>> {
    match format {
        SerializationFormat::Binary => Some(encoded.to_vec()),
        SerializationFormat::Hex => hex_decode(encoded),
        SerializationFormat::Base64 => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok(),
    }
}

fn decode_payload_bytes_lenient(encoded: &[u8], format: SerializationFormat) -> Option<Vec<u8>> {
    match format {
        SerializationFormat::Binary => Some(encoded.to_vec()),
        SerializationFormat::Hex => Some(tolerant_hex_decode(encoded)),
        SerializationFormat::Base64 => Some(tolerant_base64_decode(encoded)),
    }
}

fn mutate_proof_payload(
    format: SerializationFormat,
    encoded: &[u8],
    edge_case: ProofSerializationEdgeCase,
    case_index: usize,
    rng: &mut StdRng,
) -> Vec<u8> {
    match edge_case {
        ProofSerializationEdgeCase::EmptyProof => Vec::new(),
        ProofSerializationEdgeCase::TruncatedProof => {
            let truncate = 1 + (case_index % 16);
            encoded[..encoded.len().saturating_sub(truncate)].to_vec()
        }
        ProofSerializationEdgeCase::OversizedProof => {
            let mut payload = encoded.to_vec();
            payload.extend_from_slice(b"deadbeef");
            payload
        }
        ProofSerializationEdgeCase::InvalidEncoding => match format {
            SerializationFormat::Binary => vec![0xff; CANONICAL_PROOF_LEN],
            SerializationFormat::Hex => b"zz_not_hex_zz".to_vec(),
            SerializationFormat::Base64 => b"@@@not_base64@@@".to_vec(),
        },
        ProofSerializationEdgeCase::EndiannessConfusion => {
            let mut decoded = decode_payload_bytes_lenient(encoded, format).unwrap_or_default();
            decoded.reverse();
            encode_proof(&decoded, format)
        }
        ProofSerializationEdgeCase::PaddingConfusion => {
            let mut payload = encoded.to_vec();
            if rng.gen_bool(0.5) {
                payload.extend_from_slice(b"0000");
            } else {
                payload.splice(0..0, b"0000".iter().copied());
            }
            payload
        }
    }
}

fn mutate_public_inputs_payload(
    format: SerializationFormat,
    encoded: &[u8],
    edge_case: PublicInputSerializationEdgeCase,
    case_index: usize,
) -> Vec<u8> {
    match edge_case {
        PublicInputSerializationEdgeCase::ArrayLengthMismatch => {
            if let Some(mut parsed) = decode_public_inputs(
                SerializationVerifierProfile::LenientLegacy,
                encoded,
                format,
                3,
            ) {
                if case_index.is_multiple_of(2) && parsed.len() > 1 {
                    parsed.pop();
                } else {
                    parsed.push("999999".to_string());
                }
                encode_public_inputs(&parsed, format)
            } else {
                b"[1,2]".to_vec()
            }
        }
        PublicInputSerializationEdgeCase::TypeConfusion => match format {
            SerializationFormat::Binary => br#"{"inputs":[1,true,{"nested":"value"}]}"#.to_vec(),
            SerializationFormat::Hex => {
                hex_encode(br#"{"inputs":[1,true,{"nested":"value"}]}"#).into_bytes()
            }
            SerializationFormat::Base64 => base64::engine::general_purpose::STANDARD
                .encode(br#"{"inputs":[1,true,{"nested":"value"}]}"#)
                .into_bytes(),
        },
        PublicInputSerializationEdgeCase::EncodingVariant => {
            let decoded = decode_payload_bytes_lenient(encoded, format).unwrap_or_default();
            match format {
                SerializationFormat::Binary => hex_encode(&decoded).into_bytes(),
                SerializationFormat::Hex => base64::engine::general_purpose::STANDARD
                    .encode(decoded)
                    .into_bytes(),
                SerializationFormat::Base64 => decoded,
            }
        }
        PublicInputSerializationEdgeCase::DelimiterConfusion => {
            if let Some(parsed) = decode_public_inputs(
                SerializationVerifierProfile::LenientLegacy,
                encoded,
                format,
                3,
            ) {
                let text = parsed.join(" ");
                match format {
                    SerializationFormat::Binary => text.into_bytes(),
                    SerializationFormat::Hex => hex_encode(text.as_bytes()).into_bytes(),
                    SerializationFormat::Base64 => base64::engine::general_purpose::STANDARD
                        .encode(text.as_bytes())
                        .into_bytes(),
                }
            } else {
                b"1 2 3".to_vec()
            }
        }
    }
}

fn mutate_cross_language_payload(
    format: SerializationFormat,
    encoded_proof: &[u8],
    encoded_inputs: &[u8],
    case: CrossLanguageSerializationCase,
    case_index: usize,
) -> (Vec<u8>, Vec<u8>) {
    match case {
        CrossLanguageSerializationCase::RustToSnarkjs => {
            let mut proof = encoded_proof.to_vec();
            proof.extend_from_slice(b"::js");
            (proof, encoded_inputs.to_vec())
        }
        CrossLanguageSerializationCase::CircomToSolidityAbi => {
            let mut proof = Vec::new();
            proof.extend_from_slice(b"0x");
            proof.extend_from_slice(encoded_proof);
            (proof, encoded_inputs.to_vec())
        }
        CrossLanguageSerializationCase::NoirToTypescriptJson => {
            let wrapped = format!("{{\"inputs\":{}}}", String::from_utf8_lossy(encoded_inputs));
            (encoded_proof.to_vec(), wrapped.into_bytes())
        }
        CrossLanguageSerializationCase::LanguageAToLanguageB => {
            let mut inputs = encoded_inputs.to_vec();
            if case_index.is_multiple_of(2) {
                inputs.extend_from_slice(b"|extra|field");
            } else {
                match format {
                    SerializationFormat::Binary => {
                        inputs = b"42,7,0xabc".to_vec();
                    }
                    SerializationFormat::Hex => {
                        inputs = b"not_hex_payload".to_vec();
                    }
                    SerializationFormat::Base64 => {
                        inputs = b"@@bad_base64@@".to_vec();
                    }
                }
            }
            (encoded_proof.to_vec(), inputs)
        }
    }
}

fn verify_mutated_payload(
    profile: SerializationVerifierProfile,
    format: SerializationFormat,
    encoded_proof: &[u8],
    encoded_inputs: &[u8],
    expected_proof: &[u8],
    expected_inputs: &[String],
) -> bool {
    let decoded_inputs =
        match decode_public_inputs(profile, encoded_inputs, format, expected_inputs.len()) {
            Some(inputs) => inputs,
            None => return false,
        };

    let decoded_proof = match decode_proof(profile, encoded_proof, format) {
        Some(proof) => proof,
        None => return false,
    };

    if expected_proof.len() != CANONICAL_PROOF_LEN {
        return false;
    }
    let expected_prefix = &expected_proof[..MIN_PREFIX_BINDING_BYTES];
    let proof_prefix = &decoded_proof[..MIN_PREFIX_BINDING_BYTES];

    match profile {
        SerializationVerifierProfile::StrictCanonical => {
            decoded_inputs == expected_inputs && decoded_proof == expected_proof
        }
        SerializationVerifierProfile::LenientLegacy => {
            decoded_inputs.first() == expected_inputs.first() && proof_prefix == expected_prefix
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn record_result(
    accepted: bool,
    total_checks: &mut usize,
    rejected_invalid_cases: &mut usize,
    accepted_invalid_cases: &mut usize,
    checks_by_format: &mut BTreeMap<String, usize>,
    checks_by_case: &mut BTreeMap<String, usize>,
    findings: &mut Vec<SerializationFuzzFinding>,
    format_key: &str,
    format: SerializationFormat,
    case_id: String,
    category: String,
    edge_case: String,
    reason: String,
) {
    *total_checks += 1;
    *checks_by_format.entry(format_key.to_string()).or_insert(0) += 1;
    *checks_by_case.entry(edge_case.clone()).or_insert(0) += 1;
    if accepted {
        *accepted_invalid_cases += 1;
        findings.push(SerializationFuzzFinding {
            case_id,
            format,
            category,
            edge_case,
            reason,
        });
    } else {
        *rejected_invalid_cases += 1;
    }
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

fn hex_decode(input: &[u8]) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut idx = 0usize;
    while idx < input.len() {
        let hi = hex_nibble(input[idx])?;
        let lo = hex_nibble(input[idx + 1])?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Some(out)
}

fn tolerant_hex_decode(input: &[u8]) -> Vec<u8> {
    let filtered: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| b.is_ascii_hexdigit())
        .collect();
    let usable = if filtered.len().is_multiple_of(2) {
        filtered
    } else {
        filtered[..filtered.len() - 1].to_vec()
    };
    hex_decode(&usable).unwrap_or_default()
}

fn tolerant_base64_decode(input: &[u8]) -> Vec<u8> {
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(input) {
        return decoded;
    }
    let filtered: Vec<u8> = input
        .iter()
        .copied()
        .filter(|byte| {
            byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/' || *byte == b'='
        })
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(filtered)
        .unwrap_or_default()
}

fn hex_nibble(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}

fn random_hex_32(rng: &mut StdRng) -> String {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    format!("0x{}", hex_encode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_profile_rejects_all_invalid_serialization_cases() {
        let mut config = SerializationFuzzConfig::new();
        config.cases_per_format = 3;
        config.verifier_profile = SerializationVerifierProfile::StrictCanonical;

        let report = run_serialization_fuzz_campaign(&config);

        assert!(report.total_checks > 0);
        assert_eq!(report.accepted_invalid_cases, 0);
        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.total_checks, report.rejected_invalid_cases);
    }

    #[test]
    fn lenient_profile_detects_serialization_acceptance_bugs() {
        let mut config = SerializationFuzzConfig::new();
        config.cases_per_format = 6;
        config.verifier_profile = SerializationVerifierProfile::LenientLegacy;

        let report = run_serialization_fuzz_campaign(&config);

        assert!(report.total_checks > 0);
        assert!(report.accepted_invalid_cases > 0);
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn reports_more_than_hundred_checks_per_format() {
        let mut config = SerializationFuzzConfig::new();
        config.cases_per_format = 8;
        config.verifier_profile = SerializationVerifierProfile::StrictCanonical;

        let report = run_serialization_fuzz_campaign(&config);

        for format in &report.formats {
            let checks = report
                .checks_by_format
                .get(format.as_str())
                .copied()
                .unwrap_or(0);
            assert!(checks >= 100);
        }
    }
}
