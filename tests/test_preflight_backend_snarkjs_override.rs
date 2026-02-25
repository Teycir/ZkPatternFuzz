mod preflight_backend_under_test {
    #![allow(dead_code, unused_imports)]
    include!("../src/preflight_backend.rs");

    #[cfg(test)]
    mod tests {
        use super::validate_snarkjs_override_path;
        use std::path::Path;

        #[test]
        fn snarkjs_override_requires_explicit_opt_in_for_path_like_values() {
            let err = validate_snarkjs_override_path(Path::new("/tmp/snarkjs"), false)
                .expect_err("path-like override should be rejected without explicit opt-in");
            assert!(err.to_string().contains("allow_external_tool_overrides"));
        }

        #[test]
        fn snarkjs_override_allows_bare_program_name_by_default() {
            validate_snarkjs_override_path(Path::new("snarkjs"), false)
                .expect("bare executable names should remain allowed");
        }
    }
}
