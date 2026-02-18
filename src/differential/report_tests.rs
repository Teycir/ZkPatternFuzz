    use super::*;

    #[test]
    fn test_differential_report_creation() {
        let report = DifferentialReport::new(
            "test_campaign",
            vec![Framework::Circom, Framework::Noir],
            vec![],
            DifferentialStats::default(),
        );

        assert_eq!(report.campaign_name, "test_campaign");
        assert!(!report.has_critical_issues());
    }
