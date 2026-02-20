use super::*;
use crate::corpus::create_corpus;
use crate::coverage::create_coverage_tracker;
use crate::power_schedule::PowerSchedule;
use zk_core::Framework;

#[test]
fn test_generate_test_case_recovers_from_empty_seed_inputs() {
    let corpus = create_corpus(16);
    let coverage = create_coverage_tracker(8);

    let mut engine = FuzzingEngineCore::builder()
        .seed(Some(7))
        .input_count(3)
        .corpus(corpus.clone())
        .coverage(coverage)
        .power_scheduler(PowerScheduler::new(PowerSchedule::None))
        .structure_mutator(StructureAwareMutator::new(Framework::Circom))
        .oracles(Vec::new())
        .build()
        .expect("engine builder should succeed");

    let empty_case = TestCase {
        inputs: Vec::new(),
        expected_output: None,
        metadata: TestMetadata::default(),
    };
    assert!(corpus.add(CorpusEntry::new(empty_case, 4242)));

    let generated = engine.generate_test_case();
    assert_eq!(generated.inputs.len(), 3);
}
