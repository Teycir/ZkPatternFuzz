    use super::*;

    #[test]
    fn test_profile_parsing() {
        assert_eq!("quick".parse::<ProfileName>().unwrap(), ProfileName::Quick);
        assert_eq!(
            "standard".parse::<ProfileName>().unwrap(),
            ProfileName::Standard
        );
        assert_eq!("deep".parse::<ProfileName>().unwrap(), ProfileName::Deep);
        assert_eq!("perf".parse::<ProfileName>().unwrap(), ProfileName::Perf);
        assert_eq!("fast".parse::<ProfileName>().unwrap(), ProfileName::Quick);
        assert_eq!(
            "thorough".parse::<ProfileName>().unwrap(),
            ProfileName::Deep
        );
        assert_eq!(
            "performance".parse::<ProfileName>().unwrap(),
            ProfileName::Perf
        );
    }

    #[test]
    fn test_profile_iterations() {
        assert_eq!(EmbeddedProfile::quick().max_iterations, 10_000);
        assert_eq!(EmbeddedProfile::standard().max_iterations, 100_000);
        assert_eq!(EmbeddedProfile::deep().max_iterations, 1_000_000);
        assert_eq!(EmbeddedProfile::perf().max_iterations, 500_000);
    }

    #[test]
    fn test_profile_strict_backend() {
        assert!(!EmbeddedProfile::quick().strict_backend);
        assert!(EmbeddedProfile::standard().strict_backend);
        assert!(EmbeddedProfile::deep().strict_backend);
        assert!(EmbeddedProfile::perf().strict_backend);
    }

    #[test]
    fn test_profile_to_params() {
        let profile = EmbeddedProfile::standard();
        let params = profile.to_additional_params();

        assert_eq!(
            params.get("max_iterations").and_then(|v| v.as_u64()),
            Some(100_000)
        );
        assert_eq!(
            params.get("strict_backend").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            params.get("symbolic_enabled").and_then(|v| v.as_bool()),
            Some(true)
        );
    }
