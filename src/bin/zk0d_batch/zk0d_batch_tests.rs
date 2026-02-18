    use super::*;

    #[test]
    fn transient_setup_reason_classifier() {
        assert!(is_transient_setup_reason("key_generation_failed"));
        assert!(is_transient_setup_reason("output_dir_locked"));
        assert!(is_transient_setup_reason("backend_preflight_failed"));
        assert!(!is_transient_setup_reason("backend_tooling_missing"));
        assert!(!is_transient_setup_reason("circom_compilation_failed"));
        assert!(!is_transient_setup_reason("completed"));
    }
