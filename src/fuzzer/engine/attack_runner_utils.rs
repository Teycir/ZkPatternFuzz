use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) fn get_circuit_info(&self) -> zk_core::CircuitInfo {
        zk_core::CircuitInfo {
            name: self.config.campaign.target.main_component.clone(),
            num_constraints: self.executor.num_constraints(),
            num_private_inputs: self.executor.num_private_inputs(),
            num_public_inputs: self.executor.num_public_inputs(),
            num_outputs: 1,
        }
    }

    pub(super) fn hash_output(&self, output: &[FieldElement]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for fe in output {
            hasher.update(fe.0);
        }
        hasher.finalize().to_vec()
    }

    /// Check if witnesses have different inputs (Mode 3 optimized: takes references)
    pub(super) fn witnesses_are_different_refs(&self, witnesses: &[&TestCase]) -> bool {
        if witnesses.len() < 2 {
            return false;
        }

        for (i, left) in witnesses.iter().enumerate() {
            for right in witnesses.iter().skip(i + 1) {
                if left.inputs != right.inputs {
                    return true;
                }
            }
        }
        false
    }

    pub(super) fn get_field_modulus(&self) -> [u8; 32] {
        // Use executor's field modulus instead of hardcoded BN254
        self.executor.field_modulus()
    }

    pub(super) fn detect_overflow_indicator(
        &self,
        test_case: &TestCase,
        output: &[FieldElement],
    ) -> bool {
        // Keep this heuristic narrow: only evaluate the "small input" probes to
        // avoid noise from circuits that naturally emit high-entropy field values.
        let small_input_probe = test_case
            .inputs
            .iter()
            .all(|input| Self::fits_in_bytes(input, 2));
        if !small_input_probe {
            return false;
        }

        let modulus = self.get_field_modulus();
        output
            .iter()
            .any(|fe| Self::is_within_distance_to_modulus(fe, &modulus, 2))
    }

    fn fits_in_bytes(value: &FieldElement, bytes: usize) -> bool {
        let leading = 32usize.saturating_sub(bytes);
        value.0.iter().take(leading).all(|&byte| byte == 0)
    }

    /// Check whether `value` is within `threshold_bytes` of the field modulus.
    /// Uses byte-accurate big-endian subtraction to remain field-agnostic.
    fn is_within_distance_to_modulus(
        value: &FieldElement,
        modulus: &[u8; 32],
        threshold_bytes: usize,
    ) -> bool {
        match Self::cmp_be(&value.0, modulus) {
            // Non-canonical output (> modulus) is already suspicious.
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => true,
            std::cmp::Ordering::Less => {
                let diff = Self::sub_be(modulus, &value.0);
                let leading = 32usize.saturating_sub(threshold_bytes);
                diff.iter().take(leading).all(|&byte| byte == 0)
            }
        }
    }

    fn cmp_be(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
        for (left, right) in a.iter().zip(b.iter()) {
            if left < right {
                return std::cmp::Ordering::Less;
            }
            if left > right {
                return std::cmp::Ordering::Greater;
            }
        }
        std::cmp::Ordering::Equal
    }

    /// Compute `a - b` for big-endian 256-bit integers with `a >= b`.
    fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0u16;

        for i in (0..32).rev() {
            let ai = a[i] as u16;
            let bi = b[i] as u16 + borrow;
            if ai >= bi {
                out[i] = (ai - bi) as u8;
                borrow = 0;
            } else {
                out[i] = (ai + 256 - bi) as u8;
                borrow = 1;
            }
        }

        out
    }
}
