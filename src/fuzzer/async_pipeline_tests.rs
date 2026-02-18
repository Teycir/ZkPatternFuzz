    use super::*;

    #[test]
    fn test_pipeline_config_defaults() {
        let config = PipelineConfig::default();
        assert_eq!(config.select_buffer, 100);
        assert_eq!(config.mutation_workers, 4);
        assert_eq!(config.execution_workers, 8);
    }

    #[test]
    fn test_pipeline_stats_default() {
        let stats = PipelineStats::default();
        assert_eq!(stats.cases_selected, 0);
        assert_eq!(stats.execution_throughput, 0.0);
    }

    #[test]
    fn test_batch_executor() {
        use zk_core::ExecutionCoverage;
        let executor = BatchExecutor::new(10, Duration::from_secs(5));

        let inputs: Vec<u64> = (0..100).collect();
        let results = executor.execute_batch(inputs, |x| {
            ExecutionResult::success(
                vec![FieldElement::from_u64(x)],
                ExecutionCoverage::default(),
            )
        });

        assert_eq!(results.len(), 100);
    }

    #[test]
    fn test_async_pipeline_creation() {
        let config = PipelineConfig::default();
        let pipeline = AsyncPipeline::new(config);

        assert!(!pipeline.is_running());
    }

    #[test]
    fn test_pipeline_stop() {
        let pipeline = AsyncPipeline::new(PipelineConfig::default());
        pipeline
            .running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        assert!(pipeline.is_running());

        pipeline.stop();
        assert!(!pipeline.is_running());
    }
