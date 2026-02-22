use std::collections::BTreeMap;
use std::path::PathBuf;

use zk_fuzzer::default_post_roadmap_tracks;
use zk_postroadmap_core::{TrackExecution, TrackInput, TrackRunner};

fn sample_input() -> TrackInput {
    TrackInput {
        campaign_id: "compat-campaign".to_string(),
        run_id: "compat-run".to_string(),
        seed: Some(1337),
        corpus_dir: PathBuf::from("corpus"),
        evidence_dir: PathBuf::from("evidence"),
        output_dir: PathBuf::from("output"),
        metadata: BTreeMap::new(),
    }
}

#[tokio::test]
async fn post_roadmap_tracks_emit_contract_compatible_execution() {
    for runner in default_post_roadmap_tracks() {
        assert_track_contract_compatible(&*runner, &sample_input()).await;
    }
}

async fn assert_track_contract_compatible(runner: &dyn TrackRunner, input: &TrackInput) {
    runner
        .prepare(input)
        .await
        .expect("prepare should succeed for contract test");
    let execution = runner
        .run(input)
        .await
        .expect("run should return shared execution contract");
    runner
        .validate(&execution)
        .await
        .expect("validate should accept shared execution contract");

    assert_eq!(execution.track, runner.track());
    assert_eq!(execution.run_id, input.run_id);

    let json = serde_json::to_value(&execution).expect("serialize track execution");
    let decoded: TrackExecution =
        serde_json::from_value(json).expect("deserialize track execution with stable schema");
    assert_eq!(decoded.track, execution.track);
    assert_eq!(decoded.run_id, execution.run_id);
}
