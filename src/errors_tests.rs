    use super::*;

    #[test]
    fn test_error_display() {
        let err = ZkFuzzerError::config("Invalid YAML syntax");
        assert!(err.to_string().contains("Configuration error"));
        assert!(err.to_string().contains("Invalid YAML syntax"));
    }

    #[test]
    fn test_error_suggestion() {
        let err = ZkFuzzerError::config("File not found");
        assert!(err.suggestion().is_some());
        assert!(err.suggestion().unwrap().contains("file path"));
    }

    #[test]
    fn test_unsupported_backend() {
        let err = ZkFuzzerError::unsupported_backend("unknown");
        assert!(err.to_string().contains("unknown"));
        assert!(err.suggestion().unwrap().contains("circom"));
    }
