use rand::rngs::StdRng;
use rand::SeedableRng;
use zk_core::FieldElement;
use zk_fuzzer_core::mutators::mutate_field_element;

#[test]
fn mutate_field_element_produces_canonical_values_from_zero_seed() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let mut value = FieldElement::zero();
    for _ in 0..20_000 {
        value = mutate_field_element(&value, &mut rng);
        assert!(value.is_canonical());
    }
}

#[test]
fn mutate_field_element_produces_canonical_values_from_max_seed() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
    let mut value = FieldElement::max_value();
    for _ in 0..20_000 {
        value = mutate_field_element(&value, &mut rng);
        assert!(value.is_canonical());
    }
}

#[test]
fn mutate_field_element_is_deterministic_for_fixed_seed() {
    let mut rng_a = StdRng::seed_from_u64(42);
    let mut rng_b = StdRng::seed_from_u64(42);
    let mut a = FieldElement::from_u64(12345);
    let mut b = FieldElement::from_u64(12345);

    for _ in 0..1_000 {
        a = mutate_field_element(&a, &mut rng_a);
        b = mutate_field_element(&b, &mut rng_b);
        assert_eq!(a, b);
    }
}

#[test]
fn mutate_field_element_explores_multiple_values() {
    let mut rng = StdRng::seed_from_u64(7);
    let mut value = FieldElement::from_u64(1);
    let mut distinct = std::collections::BTreeSet::new();
    for _ in 0..2_000 {
        value = mutate_field_element(&value, &mut rng);
        distinct.insert(value.to_hex());
    }
    assert!(distinct.len() > 10);
}
