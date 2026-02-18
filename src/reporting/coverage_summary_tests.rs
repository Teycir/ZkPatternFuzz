    use super::*;

    #[test]
    fn test_coverage_summary_creation() {
        let summary = CoverageSummaryBuilder::new()
            .constraint_coverage(500, 1000)
            .corpus_size(100)
            .findings(5)
            .throughput(1234.5)
            .build();

        assert_eq!(summary.constraint_coverage.covered, 500);
        assert_eq!(summary.constraint_coverage.total, 1000);
        assert!((summary.constraint_coverage.percentage - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_format_number() {
        let summary = CoverageSummary::default();
        assert_eq!(summary.format_number(1234567), "1,234,567");
        assert_eq!(summary.format_number(123), "123");
        assert_eq!(summary.format_number(0), "0");
    }

    #[test]
    fn test_progress_bar() {
        let summary = CoverageSummary::default();
        let bar = summary.make_progress_bar(50.0, 10);
        // Bar should contain filled and empty parts
        assert!(bar.contains('█') || bar.contains('░'));
    }

    #[test]
    fn test_to_markdown() {
        let summary = CoverageSummaryBuilder::new()
            .constraint_coverage(800, 1000)
            .findings(3)
            .build();

        let md = summary.to_markdown();
        assert!(md.contains("## Coverage Summary"));
        assert!(md.contains("800"));
        assert!(md.contains("1000"));
        assert!(md.contains("80.0%"));
    }

    #[test]
    fn test_to_json() {
        let summary = CoverageSummaryBuilder::new()
            .constraint_coverage(100, 200)
            .build();

        let json = summary.to_json();
        assert_eq!(json["constraint_coverage"]["covered"], 100);
        assert_eq!(json["constraint_coverage"]["total"], 200);
    }
