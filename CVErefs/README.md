# CVE Circuit References

This directory contains references to circuits used for CVE regression testing.

## External Circuit Locations

The actual circuit files are located on the external drive:
```
/media/elements/Repos/zk0d/
├── cat3_privacy/
│   ├── tornado-core/circuits/
│   │   ├── withdraw.circom
│   │   └── merkleTree.circom
│   └── semaphore/packages/circuits/src/
│       └── semaphore.circom
└── circuits/
    ├── range_proof.circom
    └── division.circom
```

## Status

| CVE ID | Circuit | Status |
|--------|---------|--------|
| ZK-CVE-2022-001 | tornado-core/withdraw.circom | External |
| ZK-CVE-2022-002 | semaphore/semaphore.circom | External |
| ZK-CVE-2021-001 | tornado-core/merkleTree.circom | External |
| ZK-CVE-2021-002 | tornado-core/merkleTree.circom | External |
| ZK-CVE-2023-001 | circuits/range_proof.circom | External |
| ZK-CVE-2023-002 | circuits/division.circom | External |
| ZK-CVE-2022-003 | tornado-core/withdraw.circom | External |
| ZK-CVE-2023-003 | semaphore/semaphore.circom | External |

## Testing

When running CVE regression tests:
1. The test checks if external circuits are accessible
2. If not accessible, the test is skipped (not failed)
3. If accessible, the test runs the fuzzer against the vulnerable circuit
4. The test verifies that the fuzzer detects the expected vulnerability

## Integration

The `src/cve/mod.rs` module uses these paths to:
1. Load the circuit file
2. Compile it with the appropriate backend
3. Run the fuzzer's attack strategies
4. Verify that findings match the expected vulnerability

See `circuit_references.json` for the mapping.
