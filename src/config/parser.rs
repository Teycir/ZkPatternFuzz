//! YAML configuration parser utilities

/// Parse attack-specific configuration values
pub fn parse_attack_config<T: serde::de::DeserializeOwned>(
    config: &serde_yaml::Value,
    key: &str,
    default: T,
) -> T {
    let parsed = config
        .get(key)
        .and_then(|v| match serde_yaml::from_value(v.clone()) {
            Ok(parsed) => Some(parsed),
            Err(err) => {
                tracing::warn!("Failed parsing attack config key '{}': {}", key, err);
                None
            }
        });
    match parsed {
        Some(value) => value,
        None => default,
    }
}

/// Parse a list of test values from attack config
pub fn parse_test_values(config: &serde_yaml::Value) -> Vec<String> {
    let values = config
        .get("test_values")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });
    values.unwrap_or_default()
}

/// Error type for value expansion failures
#[derive(Debug, Clone)]
pub struct ValueExpansionError {
    pub value: String,
    pub reason: String,
}

impl std::fmt::Display for ValueExpansionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Failed to expand value '{}': {}",
            self.value, self.reason
        )
    }
}

impl std::error::Error for ValueExpansionError {}

/// Expand special value placeholders with proper error handling
///
/// Returns a Result to properly propagate parsing errors instead of
/// silently returning default values which could hide configuration bugs.
///
/// # Supported Placeholders
/// - `0`, `zero`: Zero value
/// - `1`, `one`: One value
/// - `p-1`, `max_field`: Field modulus minus one
/// - `p`, `field_mod`: Field modulus
/// - `field_mod-1`, `field_mod+1`: Field modulus with offset
/// - `max_field-1`, `max_field+1`: Max field element with offset
/// - Negative decimals like `-1` (interpreted as `p-1`)
/// - `(p-1)/2`: Half of modulus minus one
/// - `0x...`: Hexadecimal value
/// - Decimal numbers: Parsed as u64
///
/// # Errors
/// Returns `ValueExpansionError` if:
/// - Hex string is invalid
/// - Decimal parsing fails for non-placeholder values
pub fn expand_value_placeholder(
    value: &str,
    field_modulus: &[u8; 32],
) -> Result<Vec<u8>, ValueExpansionError> {
    use num_bigint::BigUint;

    let normalized = value.to_lowercase().replace(' ', "");
    let modulus = BigUint::from_bytes_be(field_modulus);

    let parse_offset = |base: BigUint, offset: &str| -> Result<Vec<u8>, ValueExpansionError> {
        if offset.is_empty() {
            return Ok(base.to_bytes_be());
        }

        let (sign, digits) = offset.split_at(1);
        let delta = digits.parse::<u64>().map_err(|e| ValueExpansionError {
            value: value.to_string(),
            reason: format!("Invalid decimal: {}", e),
        })?;
        let delta = BigUint::from(delta);

        let result = match sign {
            "+" => base + delta,
            "-" => {
                if base < delta {
                    return Err(ValueExpansionError {
                        value: value.to_string(),
                        reason: "Underflow while applying offset".to_string(),
                    });
                }
                base - delta
            }
            _ => {
                return Err(ValueExpansionError {
                    value: value.to_string(),
                    reason: "Invalid offset format".to_string(),
                })
            }
        };

        Ok(result.to_bytes_be())
    };

    match normalized.as_str() {
        "0" | "zero" => Ok(vec![0u8; 32]),
        "1" | "one" => {
            let mut bytes = vec![0u8; 32];
            bytes[31] = 1;
            Ok(bytes)
        }
        "max_field" | "max" => {
            // max field element = p - 1
            if modulus == BigUint::from(0u8) {
                return Ok(vec![0u8; 32]);
            }
            Ok((modulus.clone() - BigUint::from(1u8)).to_bytes_be())
        }
        "p" | "field_mod" => Ok(field_modulus.to_vec()),
        "(p-1)/2" => {
            // Half of p-1
            let mut result = field_modulus.to_vec();
            // Subtract 1 and divide by 2
            let mut borrow = 1u16;
            for i in (0..32).rev() {
                let diff = result[i] as u16 + 256 - borrow;
                borrow = if diff < 256 { 1 } else { 0 };
                result[i] = (diff & 0xff) as u8;
            }
            // Divide by 2 (right shift)
            let mut carry = 0u8;
            for byte in result.iter_mut() {
                let new_carry = *byte & 1;
                *byte = (*byte >> 1) | (carry << 7);
                carry = new_carry;
            }
            Ok(result)
        }
        _ if normalized.starts_with("p+") || normalized.starts_with("p-") => {
            parse_offset(modulus.clone(), &normalized[1..])
        }
        _ if normalized.starts_with("field_mod+") || normalized.starts_with("field_mod-") => {
            let offset = &normalized["field_mod".len()..];
            parse_offset(modulus.clone(), offset)
        }
        _ if normalized.starts_with("max+") || normalized.starts_with("max-") => {
            if modulus == BigUint::from(0u8) {
                return Ok(vec![0u8; 32]);
            }
            let base = modulus - BigUint::from(1u8);
            parse_offset(base, &normalized[3..])
        }
        _ if normalized.starts_with("max_field+") || normalized.starts_with("max_field-") => {
            if modulus == BigUint::from(0u8) {
                return Ok(vec![0u8; 32]);
            }
            let base = modulus - BigUint::from(1u8);
            let offset = &normalized["max_field".len()..];
            parse_offset(base, offset)
        }
        _ if normalized.starts_with('-') => {
            let digits = &normalized[1..];
            if digits.is_empty() {
                return Err(ValueExpansionError {
                    value: value.to_string(),
                    reason: "Invalid negative value".to_string(),
                });
            }
            let delta = digits.parse::<u64>().map_err(|e| ValueExpansionError {
                value: value.to_string(),
                reason: format!("Invalid decimal: {}", e),
            })?;
            if delta == 0 {
                return Ok(vec![0u8; 32]);
            }
            if modulus == BigUint::from(0u8) {
                return Err(ValueExpansionError {
                    value: value.to_string(),
                    reason: "Cannot apply negative offset without modulus".to_string(),
                });
            }
            let delta = BigUint::from(delta);
            if modulus < delta {
                return Err(ValueExpansionError {
                    value: value.to_string(),
                    reason: "Underflow while applying negative offset".to_string(),
                });
            }
            Ok((modulus.clone() - delta).to_bytes_be())
        }
        _ if value.starts_with("0x") || value.starts_with("0X") => {
            // Hex value - properly propagate errors
            hex::decode(&value[2..]).map_err(|e| ValueExpansionError {
                value: value.to_string(),
                reason: format!("Invalid hex: {}", e),
            })
        }
        _ => {
            // Try to parse as decimal
            value
                .parse::<u64>()
                .map(|n| {
                    let mut bytes = vec![0u8; 32];
                    bytes[24..32].copy_from_slice(&n.to_be_bytes());
                    bytes
                })
                .map_err(|e| ValueExpansionError {
                    value: value.to_string(),
                    reason: format!("Invalid decimal: {}", e),
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn test_expand_zero() {
        let modulus = [0u8; 32];
        let result = expand_value_placeholder("0", &modulus).unwrap();
        assert_eq!(result, vec![0u8; 32]);
    }

    #[test]
    fn test_expand_one() {
        let modulus = [0u8; 32];
        let result = expand_value_placeholder("1", &modulus).unwrap();
        let mut expected = vec![0u8; 32];
        expected[31] = 1;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_expand_hex() {
        let modulus = [0u8; 32];
        let result = expand_value_placeholder("0xdead", &modulus).unwrap();
        assert_eq!(result, vec![0xde, 0xad]);
    }

    #[test]
    fn test_expand_invalid_hex_returns_error() {
        let modulus = [0u8; 32];
        let result = expand_value_placeholder("0xZZZZ", &modulus);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.reason.contains("Invalid hex"));
    }

    #[test]
    fn test_expand_invalid_decimal_returns_error() {
        let modulus = [0u8; 32];
        let result = expand_value_placeholder("not_a_number", &modulus);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.reason.contains("Invalid decimal"));
    }

    #[test]
    fn test_expand_max_offsets() {
        let mut modulus = [0u8; 32];
        modulus[31] = 5; // p = 5

        let max = expand_value_placeholder("max", &modulus).unwrap();
        let max_minus = expand_value_placeholder("max-1", &modulus).unwrap();
        let max_plus = expand_value_placeholder("max+1", &modulus).unwrap();
        let p_plus = expand_value_placeholder("p+1", &modulus).unwrap();

        assert_eq!(BigUint::from_bytes_be(&max), BigUint::from(4u8));
        assert_eq!(BigUint::from_bytes_be(&max_minus), BigUint::from(3u8));
        assert_eq!(BigUint::from_bytes_be(&max_plus), BigUint::from(5u8));
        assert_eq!(BigUint::from_bytes_be(&p_plus), BigUint::from(6u8));
    }

    #[test]
    fn test_expand_field_mod_offsets_and_negative() {
        let mut modulus = [0u8; 32];
        modulus[31] = 5; // p = 5

        let field_mod_minus = expand_value_placeholder("field_mod-1", &modulus).unwrap();
        let max_field_minus = expand_value_placeholder("max_field-1", &modulus).unwrap();
        let neg_one = expand_value_placeholder("-1", &modulus).unwrap();

        assert_eq!(BigUint::from_bytes_be(&field_mod_minus), BigUint::from(4u8));
        assert_eq!(BigUint::from_bytes_be(&max_field_minus), BigUint::from(3u8));
        assert_eq!(BigUint::from_bytes_be(&neg_one), BigUint::from(4u8));
    }
}
