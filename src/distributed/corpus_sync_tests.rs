    use super::*;
    use crate::corpus::create_corpus;

    #[test]
    fn test_sync_manager_creation() {
        let corpus = create_corpus(1000);
        let manager = CorpusSyncManager::new(corpus);
        assert_eq!(manager.global_corpus_size().expect("size failed"), 0);
    }

    #[test]
    fn test_receive_entries() {
        let corpus = create_corpus(1000);
        let manager = CorpusSyncManager::new(corpus);

        let entries = vec![
            SerializableCorpusEntry {
                inputs: vec!["0x01".to_string()],
                coverage_hash: 1,
                discovered_new_coverage: true,
                energy: 50,
            },
            SerializableCorpusEntry {
                inputs: vec!["0x02".to_string()],
                coverage_hash: 2,
                discovered_new_coverage: false,
                energy: 10,
            },
        ];

        manager
            .receive_entries("node-1", entries)
            .expect("receive failed");
        assert_eq!(manager.global_corpus_size().expect("size failed"), 2);
    }

    #[test]
    fn test_global_corpus_manager() {
        let mut manager = GlobalCorpusManager::new();

        let entry = CorpusEntry::new(
            zk_core::TestCase {
                inputs: vec![zk_core::FieldElement::zero()],
                expected_output: None,
                metadata: Default::default(),
            },
            12345,
        );

        manager.add_from_node("node-1", vec![entry.clone()]);
        manager.add_from_node("node-2", vec![entry]); // Duplicate

        assert_eq!(manager.stats().unique_entries, 1);
    }
