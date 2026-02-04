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

/// Expand special value placeholders
pub fn expand_value_placeholder(value: &str, field_modulus: &[u8; 32]) -> Vec<u8> {
    match value.to_lowercase().as_str() {
        "0" | "zero" => vec![0u8; 32],
        "1" | "one" => {
            let mut bytes = vec![0u8; 32];
            bytes[31] = 1;
            bytes
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
            result
        }
        "p" | "field_mod" => field_modulus.to_vec(),
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
            result
        }
        _ if value.starts_with("0x") => {
            // Hex value
            hex::decode(&value[2..]).unwrap_or_else(|_| vec![0u8; 32])
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
                .unwrap_or_else(|_| vec![0u8; 32])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_zero() {
        let modulus = [0u8; 32];
        let result = expand_value_placeholder("0", &modulus);
        assert_eq!(result, vec![0u8; 32]);
    }

    #[test]
    fn test_expand_one() {
        let modulus = [0u8; 32];
        let result = expand_value_placeholder("1", &modulus);
        let mut expected = vec![0u8; 32];
        expected[31] = 1;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_expand_hex() {
        let modulus = [0u8; 32];
        let result = expand_value_placeholder("0xdead", &modulus);
        assert_eq!(result, vec![0xde, 0xad]);
    }
}
