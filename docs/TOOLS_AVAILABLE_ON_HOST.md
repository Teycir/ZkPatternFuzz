# Local Tool Inventory (Host)

Date checked: 2026-03-05  
Scope: this workstation used for ZkPatternFuzz operations.  
Operating mode: manual checks only.

## Goal Alignment

This inventory focuses on tools for:

- vulnerability discovery,
- exploitability proof,
- non-exploitability proof.

## Requested Tools

| Tool | Status | Identity | Primary role |
|---|---|---|---|
| `halmos` | installed | `halmos 0.3.3` | symbolic/formal fuzzing for Solidity |
| `picus` | installed | `run-picus` wrapper (`picus --help`) | formal underconstraint/safety analysis for Circom/R1CS |
| `echidna` | installed | `Echidna 2.2.5` | property-based smart-contract fuzzing |
| `medusa` | installed | `medusa version 1.4.1` | smart-contract fuzzing harness |

## ZK And Backend Toolchain

| Tool | Status | Version |
|---|---|---|
| `circom` | installed | `circom compiler 2.2.3` |
| `snarkjs` | installed | `snarkjs@0.7.6` |
| `nargo` | installed | `1.0.0-beta.18` |
| `scarb` | installed | `2.15.1` |
| `cairo-compile` | installed | `0.14.0.1` |
| `cairo-run` | installed | `0.14.0.1` |
| `z3` | installed | `4.13.0` |

## Solidity And Security Ecosystem

| Tool | Status | Version |
|---|---|---|
| `forge` | installed | `1.5.1-stable` |
| `cast` | installed | `1.5.1-stable` |
| `anvil` | installed | `1.5.1-stable` |
| `solc` | installed | `0.8.26` |
| `slither` | installed | `0.11.3` |

## Runtime And Build Dependencies

| Tool | Status | Version |
|---|---|---|
| `cargo` | installed | `1.91.0-nightly` |
| `rustc` | installed | `1.91.0-nightly` |
| `python3` | installed | `3.12.3` |
| `node` | installed | `v20.20.0` |
| `npm` | installed | `10.8.2` |
| `pnpm` | installed | `10.30.0` |
| `go` | installed | `go1.22.2` |

## Not Currently Installed

| Tool | Status |
|---|---|
| `mythril` | missing |
| `manticore` | missing |
| `starknet-compile` | missing |
| `lean` | missing |
| `lake` | missing |

## Operational Usage Mapping

| Objective | Primary tools | Expected output |
|---|---|---|
| Discovery | `zk-fuzzer`, `echidna`, `medusa`, `halmos` | oracle findings, failing invariants, corpus artifacts |
| Exploit proof | deterministic replays, backend executors, witness/tx sequences | reproducible mismatch with replay log |
| Non-exploitability proof | `picus`, solver evidence, bounded reruns | SAFE result or bounded no-counterexample evidence |

## Recheck Commands

```bash
halmos --version
picus --help | sed -n '1,8p'
echidna --version
medusa --version
```

```bash
circom --version
snarkjs --version
nargo --version
scarb --version
cairo-compile --version
cairo-run --version
z3 --version
```
