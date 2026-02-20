use super::*;
use crate::executor::FixtureCircuitExecutor;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn test_timing_stats() {
    let samples = vec![100, 200, 150, 300, 250, 175, 225, 275, 125, 350];
    let stats = TimingStats::from_samples(&samples);

    assert_eq!(stats.min_us, 100);
    assert_eq!(stats.max_us, 350);
    assert_eq!(stats.sample_count, 10);
    assert!(stats.mean_us > 200.0 && stats.mean_us < 230.0);
}

#[test]
fn test_profiler() {
    let profiler = Profiler::new().with_samples(10);
    let executor: Arc<dyn CircuitExecutor> = Arc::new(FixtureCircuitExecutor::new("test", 2, 1));
    let mut rng = StdRng::seed_from_u64(42);

    let profile = profiler.profile(&executor, &mut rng);

    assert_eq!(profile.execution_stats.sample_count, 10);
    assert!(profile.worst_case_inputs.len() <= 10);
}
