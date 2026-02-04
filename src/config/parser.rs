//! YAML configuration parser utilities

/// Parse attack-specific configuration values
pub fn parse_attack_config<T: serde::de::DeserializeOwned>(
    config: &serde_yaml::Value,
    key: &str,
    default: T,
) -> T {
    config
        .get(key)
        .and_then(|v| serde_yaml::from_value(v.clone()).ok())
        .unwrap_or(default)
}

/// Parse a list of test values from attack config
pub fn parse_test_values(config: &serde_yaml::Value) -> Vec<String> {
    config
        .get("test_values")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Error type for value expansion failures
#[derive(Debug, Clone)]
pub struct ValueExpansionError {
    pub value: String,
    pub reason: String,
}

impl std::fmt::Display for ValueExpansionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to expand value '{}': {}", self.value, self.reason)
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
/// - `(p-1)/2`: Half of modulus minus one
/// - `0x...`: Hexadecimal value
/// - Decimal numbers: Parsed as u64
/// 
/// # Errors
/// Returns `ValueExpansionError` if:
/// - Hex string is invalid
/// - Decimal parsing fails for non-placeholder values
pub fn expand_value_placeholder(value: &str, field_modulus: &[u8; 32]) -> Result<Vec<u8>, ValueExpansionError> {
    match value.to_lowercase().as_str() {
        "0" | "zero" => Ok(vec![0u8; 32]),
        "1" | "one" => {
            let mut bytes = vec![0u8; 32];
            bytes[31] = 1;
            Ok(bytes)
        }
        "p-1" | "max_field" => {
            // p - 1
            let mut result = field_modulus.to_vec();
            // Subtract 1
            for i in (0..32).rev() {
                if result[i] > 0 {
                    result[i] -= 1;
                    break;
                }
                result[i] = 0xff;
            }
            Ok(result)
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
            for i in 0..32 {
                let new_carry = result[i] & 1;
                result[i] = (result[i] >> 1) | (carry << 7);
                carry = new_carry;
            }
            Ok(result)
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

/// Legacy wrapper that logs warnings for invalid values
/// 
/// Use this when you need backward compatibility but want visibility into errors.
/// For new code, prefer `expand_value_placeholder` directly.
pub fn expand_value_placeholder_with_default(value: &str, field_modulus: &[u8; 32]) -> Vec<u8> {
    match expand_value_placeholder(value, field_modulus) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!("{}", e);
            vec![0u8; 32]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
