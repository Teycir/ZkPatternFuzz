    use super::*;
    use zk_core::{FieldElement, TestCase, TestMetadata};

    fn create_entry(coverage_hash: u64, new_coverage: bool) -> CorpusEntry {
        let mut entry = CorpusEntry::new(
            TestCase {
                inputs: vec![FieldElement::from_u64(coverage_hash)],
                expected_output: None,
                metadata: TestMetadata::default(),
            },
            coverage_hash,
        );
        if new_coverage {
            entry = entry.with_new_coverage();
        }
        entry
    }

    #[test]
    fn test_minimize_corpus() {
        let entries = vec![
            create_entry(1, true),
            create_entry(2, false),
            create_entry(1, false), // Duplicate coverage
            create_entry(3, true),
        ];

        let minimized = minimize_corpus(&entries);

        // Should keep 3 unique coverage hashes
        assert_eq!(minimized.len(), 3);

        // Should prefer entries with new coverage
        let new_cov_count = minimized
            .iter()
            .filter(|e| e.discovered_new_coverage)
            .count();
        assert_eq!(new_cov_count, 2);
    }

    #[test]
    fn test_deduplicate_corpus() {
        let entries = vec![
            create_entry(1, true),
            create_entry(1, false), // Same input (same coverage_hash used for input)
            create_entry(2, true),
        ];

        let deduped = deduplicate_corpus(&entries);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_minimization_stats() {
        let stats = MinimizationStats::compute(100, 30);
        assert_eq!(stats.original_size, 100);
        assert_eq!(stats.minimized_size, 30);
        assert!((stats.reduction_percentage - 70.0).abs() < 0.1);
    }
