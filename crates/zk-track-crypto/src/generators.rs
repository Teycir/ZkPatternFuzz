use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use zk_core::constants::bn254_modulus_biguint;

pub const TOY_CURVE_ORDER: u64 = 10_177;
pub const TOY_PAIRING_ORDER: u64 = 101;
pub const TOY_PAIRING_TARGET_MODULUS: u64 = 1_000_000_007;
pub const TOY_PAIRING_GENERATOR: u64 = 5;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CurvePointType {
    Identity,
    Generator,
    RandomValid,
    RandomValidAlt,
    LowOrderProxy,
    InvalidNotOnCurve,
    InfinityAltRepresentation,
}

impl CurvePointType {
    pub const ALL: [CurvePointType; 7] = [
        Self::Identity,
        Self::Generator,
        Self::RandomValid,
        Self::RandomValidAlt,
        Self::LowOrderProxy,
        Self::InvalidNotOnCurve,
        Self::InfinityAltRepresentation,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Generator => "generator",
            Self::RandomValid => "random_valid",
            Self::RandomValidAlt => "random_valid_alt",
            Self::LowOrderProxy => "low_order_proxy",
            Self::InvalidNotOnCurve => "invalid_not_on_curve",
            Self::InfinityAltRepresentation => "infinity_alt_representation",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PairingInputType {
    Identity,
    Generator,
    RandomValid,
    LowOrderProxy,
    Invalid,
}

impl PairingInputType {
    pub const ALL: [PairingInputType; 5] = [
        Self::Identity,
        Self::Generator,
        Self::RandomValid,
        Self::LowOrderProxy,
        Self::Invalid,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Generator => "generator",
            Self::RandomValid => "random_valid",
            Self::LowOrderProxy => "low_order_proxy",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurvePointSample {
    pub point_type: CurvePointType,
    pub value: Option<u64>,
    pub low_order_hint: bool,
    pub infinity_encoding: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairingInputSample {
    pub input_type: PairingInputType,
    pub value: Option<u64>,
    pub low_order_hint: bool,
}

pub fn field_modulus() -> &'static BigUint {
    bn254_modulus_biguint()
}

pub fn generate_field_edge_values(modulus: &BigUint) -> Vec<BigUint> {
    let one = BigUint::one();
    let two = BigUint::from(2u8);

    let p_minus_one = modulus - &one;
    let p_plus_one = modulus + &one;
    let p_half = modulus / &two;

    vec![
        BigUint::zero(),
        one.clone(),
        p_minus_one,
        modulus.clone(),
        p_plus_one,
        p_half.clone(),
        p_half + &one,
        two.clone(),
        modulus - &two,
        BigUint::from(3u8),
    ]
}

pub fn generate_field_values(seed: u64, random_count: usize) -> Vec<BigUint> {
    let modulus = field_modulus();
    let mut values = generate_field_edge_values(modulus);
    let mut rng = StdRng::seed_from_u64(seed);
    let range_cap = modulus * BigUint::from(2u8);

    for _ in 0..random_count {
        let mut bytes = [0u8; 40];
        rng.fill_bytes(&mut bytes);
        let value = BigUint::from_bytes_be(&bytes) % &range_cap;
        values.push(value);
    }

    values
}

pub fn generate_curve_point(
    point_type: CurvePointType,
    case_index: usize,
    rng: &mut StdRng,
) -> CurvePointSample {
    let mut random_scalar = || -> u64 {
        let mut scalar = rng.gen_range(1..TOY_CURVE_ORDER);
        if scalar == 0 {
            scalar = 1;
        }
        scalar
    };

    match point_type {
        CurvePointType::Identity => CurvePointSample {
            point_type,
            value: Some(0),
            low_order_hint: false,
            infinity_encoding: false,
        },
        CurvePointType::Generator => CurvePointSample {
            point_type,
            value: Some(1),
            low_order_hint: false,
            infinity_encoding: false,
        },
        CurvePointType::RandomValid => CurvePointSample {
            point_type,
            value: Some(random_scalar()),
            low_order_hint: false,
            infinity_encoding: false,
        },
        CurvePointType::RandomValidAlt => CurvePointSample {
            point_type,
            value: Some((random_scalar() + (case_index as u64 % 97)) % TOY_CURVE_ORDER),
            low_order_hint: false,
            infinity_encoding: false,
        },
        CurvePointType::LowOrderProxy => CurvePointSample {
            point_type,
            value: Some(0),
            low_order_hint: true,
            infinity_encoding: false,
        },
        CurvePointType::InvalidNotOnCurve => CurvePointSample {
            point_type,
            value: None,
            low_order_hint: false,
            infinity_encoding: false,
        },
        CurvePointType::InfinityAltRepresentation => CurvePointSample {
            point_type,
            value: Some(0),
            low_order_hint: false,
            infinity_encoding: true,
        },
    }
}

pub fn generate_pairing_input(
    input_type: PairingInputType,
    case_index: usize,
    rng: &mut StdRng,
) -> PairingInputSample {
    match input_type {
        PairingInputType::Identity => PairingInputSample {
            input_type,
            value: Some(0),
            low_order_hint: false,
        },
        PairingInputType::Generator => PairingInputSample {
            input_type,
            value: Some(1),
            low_order_hint: false,
        },
        PairingInputType::RandomValid => PairingInputSample {
            input_type,
            value: Some(rng.gen_range(1..TOY_PAIRING_ORDER)),
            low_order_hint: false,
        },
        PairingInputType::LowOrderProxy => PairingInputSample {
            input_type,
            value: Some((case_index as u64 * 2) % TOY_PAIRING_ORDER),
            low_order_hint: true,
        },
        PairingInputType::Invalid => PairingInputSample {
            input_type,
            value: None,
            low_order_hint: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_value_generator_returns_expected_core_values() {
        let modulus = field_modulus();
        let values = generate_field_edge_values(modulus);
        assert_eq!(values.len(), 10);
        assert!(values.contains(&BigUint::zero()));
        assert!(values.contains(modulus));
    }

    #[test]
    fn curve_point_catalog_has_expected_size() {
        assert_eq!(CurvePointType::ALL.len(), 7);
    }

    #[test]
    fn pairing_input_catalog_has_expected_size() {
        assert_eq!(PairingInputType::ALL.len(), 5);
    }
}
