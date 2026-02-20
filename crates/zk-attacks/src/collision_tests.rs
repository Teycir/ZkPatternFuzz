use super::*;

#[test]
fn test_hamming_distance_identical() {
    let a = vec![0x00, 0xFF, 0xAA];
    let b = vec![0x00, 0xFF, 0xAA];
    assert_eq!(CollisionDetector::hamming_distance(&a, &b), 0);
}

#[test]
fn test_hamming_distance_one_bit() {
    let a = vec![0x00];
    let b = vec![0x01];
    assert_eq!(CollisionDetector::hamming_distance(&a, &b), 1);
}

#[test]
fn test_hamming_distance_all_bits() {
    let a = vec![0x00];
    let b = vec![0xFF];
    assert_eq!(CollisionDetector::hamming_distance(&a, &b), 8);
}

#[test]
fn test_hamming_distance_different_lengths() {
    let a = vec![0xFF, 0xFF];
    let b = vec![0x00];
    // First byte: 8 bits different, second byte: 8 bits (since b is shorter)
    assert_eq!(CollisionDetector::hamming_distance(&a, &b), 16);
}

#[test]
fn test_collision_analysis_no_collisions() {
    let detector = CollisionDetector::new(100);

    let pairs: Vec<(Vec<FieldElement>, Vec<u8>)> = (0..100)
        .map(|i| {
            let input = vec![FieldElement::from_u64(i)];
            let output = vec![i as u8; 32];
            (input, output)
        })
        .collect();

    let analysis = detector.analyze_collisions(&pairs);
    assert_eq!(analysis.exact_collisions, 0);
    assert_eq!(analysis.samples_tested, 100);
}

#[test]
fn test_collision_analysis_with_collision() {
    let detector = CollisionDetector::new(100);

    let mut pairs: Vec<(Vec<FieldElement>, Vec<u8>)> = Vec::new();

    // Add a collision - two different inputs, same output
    pairs.push((vec![FieldElement::from_u64(1)], vec![0xAA; 32]));
    pairs.push((vec![FieldElement::from_u64(2)], vec![0xAA; 32]));

    // Add some non-colliding pairs
    for i in 3..10 {
        pairs.push((vec![FieldElement::from_u64(i)], vec![i as u8; 32]));
    }

    let analysis = detector.analyze_collisions(&pairs);
    assert_eq!(analysis.exact_collisions, 1);
    assert!(!analysis.collision_pairs.is_empty());
    assert!(analysis.collision_pairs[0].is_exact);
}

#[test]
fn test_hash_type_security_bits() {
    assert_eq!(HashType::Poseidon.security_bits(), 128);
    assert_eq!(HashType::Generic.security_bits(), 256);
}

#[test]
fn test_generate_birthday_inputs() {
    let detector = CollisionDetector::new(100);
    let inputs = detector.generate_birthday_inputs(10, 42);
    assert_eq!(inputs.len(), 10);
    assert!(inputs.iter().all(|i| i.len() == 1));
}

#[test]
fn test_generate_poseidon_inputs() {
    let detector = CollisionDetector::new(100).with_hash_type(HashType::Poseidon);
    let inputs = detector.generate_poseidon_test_inputs(10, 42);
    assert_eq!(inputs.len(), 10);
    // Poseidon inputs vary in size
    assert!(inputs.iter().any(|i| i.len() >= 2));
}

#[test]
fn test_generate_mimc_inputs() {
    let detector = CollisionDetector::new(100).with_hash_type(HashType::MiMC);
    let inputs = detector.generate_mimc_test_inputs(10, 42);
    assert!(inputs.len() >= 10); // Extra edge cases added
                                 // MiMC inputs are message + key pairs
    assert!(inputs[0].len() == 2);
}

#[test]
fn test_near_collision_detection() {
    let detector = CollisionDetector::new(100)
        .with_hamming_threshold(4)
        .with_near_collision_detection(true);

    let mut pairs: Vec<(Vec<FieldElement>, Vec<u8>)> = Vec::new();

    // Create near-collision: outputs differ by only 1 bit
    let output_a = vec![0x00; 32];
    let mut output_b = vec![0x00; 32];
    output_b[0] = 0x01; // Single bit difference

    pairs.push((vec![FieldElement::from_u64(1)], output_a));
    pairs.push((vec![FieldElement::from_u64(2)], output_b));

    let analysis = detector.analyze_collisions(&pairs);
    assert!(analysis.min_hamming_distance <= 1);
}
