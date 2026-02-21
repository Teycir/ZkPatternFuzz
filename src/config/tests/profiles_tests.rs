use super::*;
use crate::config::{AttackType, FuzzConfig};

#[test]
fn test_profile_parsing() {
    assert_eq!("quick".parse::<ProfileName>().unwrap(), ProfileName::Quick);
    assert_eq!(
        "standard".parse::<ProfileName>().unwrap(),
        ProfileName::Standard
    );
    assert_eq!("deep".parse::<ProfileName>().unwrap(), ProfileName::Deep);
    assert_eq!("perf".parse::<ProfileName>().unwrap(), ProfileName::Perf);
    assert_eq!("fast".parse::<ProfileName>().unwrap(), ProfileName::Quick);
    assert_eq!(
        "thorough".parse::<ProfileName>().unwrap(),
        ProfileName::Deep
    );
    assert_eq!(
        "performance".parse::<ProfileName>().unwrap(),
        ProfileName::Perf
    );
}

#[test]
fn test_profile_iterations() {
    assert_eq!(EmbeddedProfile::quick().max_iterations, 10_000);
    assert_eq!(EmbeddedProfile::standard().max_iterations, 100_000);
    assert_eq!(EmbeddedProfile::deep().max_iterations, 1_000_000);
    assert_eq!(EmbeddedProfile::perf().max_iterations, 500_000);
}

#[test]
fn test_profile_to_params() {
    let profile = EmbeddedProfile::standard();
    let params = profile.to_additional_params();

    assert_eq!(
        params.get("max_iterations").and_then(|v| v.as_u64()),
        Some(100_000)
    );
    assert_eq!(
        params.get("symbolic_enabled").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[test]
fn test_apply_profile_merges_required_attacks() {
    let mut config = FuzzConfig::default_v2();
    apply_profile(&mut config, ProfileName::Standard);

    let attacks: Vec<AttackType> = config
        .attacks
        .iter()
        .map(|attack| attack.attack_type.clone())
        .collect();

    assert!(attacks.contains(&AttackType::Soundness));
    assert!(attacks.contains(&AttackType::Underconstrained));
    assert!(attacks.contains(&AttackType::ConstraintInference));
    assert!(attacks.contains(&AttackType::Metamorphic));
    assert!(attacks.contains(&AttackType::ConstraintSlice));
    assert!(attacks.contains(&AttackType::SpecInference));
    assert!(attacks.contains(&AttackType::WitnessCollision));
}

#[test]
fn test_apply_profile_sets_soundness_forge_attempts_default() {
    let mut config = FuzzConfig::default_v2();
    apply_profile(&mut config, ProfileName::Standard);

    let soundness = config
        .attacks
        .iter()
        .find(|attack| attack.attack_type == AttackType::Soundness)
        .expect("soundness attack should be present");

    assert_eq!(
        soundness
            .config
            .get("forge_attempts")
            .and_then(|v| v.as_u64()),
        Some(1000)
    );
}
