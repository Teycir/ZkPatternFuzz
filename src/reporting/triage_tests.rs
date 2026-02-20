use super::*;
use zk_core::{AttackType, FieldElement};

fn make_finding(attack_type: AttackType, severity: Severity, description: &str) -> Finding {
    Finding {
        attack_type,
        severity,
        description: description.to_string(),
        poc: ProofOfConcept {
            witness_a: vec![FieldElement::from_u64(1)],
            witness_b: None,
            public_inputs: vec![],
            proof: None,
        },
        location: Some("test.circom:42".to_string()),
    }
}

#[test]
fn test_triage_pipeline_basic() {
    let config = TriageConfig::default();
    let mut pipeline = TriagePipeline::new(config);

    // Add a critical finding
    let finding = make_finding(
        AttackType::Soundness,
        Severity::Critical,
        "Critical soundness violation detected",
    );
    let idx = pipeline.add_finding(finding);
    assert!(idx.is_some());

    let report = pipeline.generate_report();
    assert_eq!(report.statistics.total_findings, 1);
}

#[test]
fn test_confidence_levels() {
    let config = TriageConfig::default();

    assert_eq!(
        ConfidenceLevel::from_score(0.9, &config),
        ConfidenceLevel::High
    );
    assert_eq!(
        ConfidenceLevel::from_score(0.6, &config),
        ConfidenceLevel::Medium
    );
    assert_eq!(
        ConfidenceLevel::from_score(0.3, &config),
        ConfidenceLevel::Low
    );
}

#[test]
fn test_cross_oracle_bonus() {
    let config = TriageConfig::default();
    let mut pipeline = TriagePipeline::new(config);

    let finding = make_finding(
        AttackType::Collision,
        Severity::Critical,
        "Nullifier collision detected by multiple oracles",
    );
    let idx = pipeline
        .add_finding_with_oracle(finding, "NullifierOracle")
        .unwrap();

    // Add more oracles
    pipeline.add_oracle_to_finding(idx, "CollisionOracle");
    pipeline.add_oracle_to_finding(idx, "SemanticOracle");

    let triaged = &pipeline.findings[idx];
    assert_eq!(triaged.detected_by_oracles.len(), 3);
    assert!(triaged.score_breakdown.cross_oracle_bonus > 0.0);
}

#[test]
fn test_picus_verification_bonus() {
    let config = TriageConfig::default();
    let mut pipeline = TriagePipeline::new(config);

    let finding = make_finding(
        AttackType::Underconstrained,
        Severity::High,
        "Underconstrained circuit",
    );
    let idx = pipeline.add_finding(finding).unwrap();

    let score_before = pipeline.findings[idx].confidence_score;

    pipeline.mark_picus_verified(idx);

    let score_after = pipeline.findings[idx].confidence_score;
    assert!(score_after > score_before);
}

#[test]
fn test_reproduction_bonus() {
    let config = TriageConfig::default();
    let mut pipeline = TriagePipeline::new(config);

    let finding = make_finding(
        AttackType::ArithmeticOverflow,
        Severity::Medium,
        "Arithmetic overflow detected",
    );
    let idx = pipeline.add_finding(finding).unwrap();

    let score_before = pipeline.findings[idx].confidence_score;

    // Record successful reproductions
    pipeline.record_reproduction(idx, true);
    pipeline.record_reproduction(idx, true);
    pipeline.record_reproduction(idx, false); // One failure

    let score_after = pipeline.findings[idx].confidence_score;
    assert!(score_after > score_before);

    let triaged = &pipeline.findings[idx];
    assert_eq!(triaged.reproduction_attempts, 3);
    assert_eq!(triaged.reproduction_successes, 2);
}

#[test]
fn test_deduplication() {
    let config = TriageConfig {
        enable_deduplication: true,
        ..Default::default()
    };
    let mut pipeline = TriagePipeline::new(config);

    let finding1 = make_finding(
        AttackType::Collision,
        Severity::Critical,
        "Same collision finding",
    );
    let finding2 = make_finding(
        AttackType::Collision,
        Severity::Critical,
        "Same collision finding",
    );

    let idx1 = pipeline.add_finding(finding1);
    let idx2 = pipeline.add_finding(finding2);

    assert!(idx1.is_some());
    assert!(idx2.is_none()); // Should be deduplicated

    assert_eq!(pipeline.findings.len(), 1);
}

#[test]
fn test_priority_ranking() {
    let config = TriageConfig::default();
    let mut pipeline = TriagePipeline::new(config);

    // Add findings of different severities
    pipeline.add_finding(make_finding(
        AttackType::Boundary,
        Severity::Low,
        "Low severity finding",
    ));
    pipeline.add_finding(make_finding(
        AttackType::Soundness,
        Severity::Critical,
        "Critical severity finding",
    ));
    pipeline.add_finding(make_finding(
        AttackType::ArithmeticOverflow,
        Severity::Medium,
        "Medium severity finding",
    ));

    let report = pipeline.generate_report();
    let all = report.all_findings_by_priority();

    // Critical should be ranked first
    assert_eq!(all[0].finding.severity, Severity::Critical);
    assert_eq!(all[0].priority_rank, 1);
}

#[test]
fn test_evidence_mode_filter() {
    let config = TriageConfig {
        evidence_mode_min_confidence: 0.4, // Lower threshold for test
        ..Default::default()
    };
    let mut pipeline = TriagePipeline::new(config);

    // Add various findings - critical with good PoC
    let mut critical_finding = make_finding(
        AttackType::Soundness,
        Severity::Critical,
        "Critical soundness violation detected in circuit",
    );
    critical_finding.poc.witness_b = Some(vec![FieldElement::from_u64(2)]);
    pipeline.add_finding(critical_finding);

    // Info finding with minimal evidence
    pipeline.add_finding(make_finding(
        AttackType::Boundary,
        Severity::Info,
        "Info finding",
    ));

    let evidence_findings = pipeline.evidence_mode_findings();

    // At least critical finding should be included
    assert!(
        !evidence_findings.is_empty(),
        "Evidence findings should not be empty. Total findings: {}",
        pipeline.findings.len()
    );
    for f in evidence_findings {
        assert!(f.confidence_score >= 0.4);
    }
}

#[test]
fn test_report_generation() {
    let config = TriageConfig::default();
    let mut pipeline = TriagePipeline::new(config);

    // Add findings of different confidence levels
    let mut critical = make_finding(
        AttackType::Soundness,
        Severity::Critical,
        "High confidence critical finding",
    );
    critical.poc.witness_b = Some(vec![FieldElement::from_u64(2)]);

    pipeline.add_finding(critical);
    pipeline.add_finding(make_finding(
        AttackType::Boundary,
        Severity::Info,
        "Low confidence info finding",
    ));

    let report = pipeline.generate_report();

    assert_eq!(report.statistics.total_findings, 2);
    assert!(!report.high_confidence.is_empty() || !report.medium_confidence.is_empty());
}

#[test]
fn test_markdown_generation() {
    let config = TriageConfig::default();
    let mut pipeline = TriagePipeline::new(config);

    pipeline.add_finding_with_oracle(
        make_finding(
            AttackType::Collision,
            Severity::Critical,
            "Critical nullifier collision",
        ),
        "NullifierOracle",
    );

    let report = pipeline.generate_report();
    let md = report.to_markdown();

    assert!(md.contains("# Triage Report"));
    assert!(md.contains("Total Findings"));
    assert!(md.contains("Critical"));
}
