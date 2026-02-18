
use super::*;

#[test]
fn test_power_schedule_none() {
    let scheduler = PowerScheduler::new(PowerSchedule::None);
    let metrics = TestCaseMetrics::default();
    assert_eq!(scheduler.calculate_energy(&metrics), 100);
}

#[test]
fn test_power_schedule_explore() {
    let mut scheduler = PowerScheduler::new(PowerSchedule::Explore);
    scheduler.update_globals(Duration::from_micros(100), 1000);

    // Rare path should get more energy
    let rare = TestCaseMetrics {
        path_frequency: 10,
        ..Default::default()
    };
    let common = TestCaseMetrics {
        path_frequency: 500,
        ..Default::default()
    };

    assert!(scheduler.calculate_energy(&rare) > scheduler.calculate_energy(&common));
}

#[test]
fn test_power_schedule_exploit() {
    let scheduler = PowerScheduler::new(PowerSchedule::Exploit);

    // Test case with findings should get more energy
    let with_findings = TestCaseMetrics {
        findings_count: 5,
        ..Default::default()
    };
    let without_findings = TestCaseMetrics::default();

    assert!(
        scheduler.calculate_energy(&with_findings) > scheduler.calculate_energy(&without_findings)
    );
}

#[test]
fn test_power_schedule_coe() {
    let scheduler = PowerScheduler::new(PowerSchedule::Coe);

    // Frequently selected cases should get less energy
    let fresh = TestCaseMetrics {
        selection_count: 5,
        ..Default::default()
    };
    let overused = TestCaseMetrics {
        selection_count: 100,
        ..Default::default()
    };

    assert!(scheduler.calculate_energy(&fresh) > scheduler.calculate_energy(&overused));
}

#[test]
fn test_energy_clamping() {
    let scheduler = PowerScheduler::new(PowerSchedule::Explore);

    // Even with extreme metrics, energy should be clamped
    let extreme = TestCaseMetrics {
        path_frequency: 0,
        ..Default::default()
    };

    assert!(scheduler.calculate_energy(&extreme) <= scheduler.max_energy);
}
