# Local Tool Inventory (Host)

Date checked: 2026-02-23
Scope: this workstation used for ZkPatternFuzz operations.
Operating mode: manual checks only (no cron requirement).

## Goal alignment
This inventory focuses on tools for:
- vulnerability discovery,
- exploitability proof (concrete exploit/replay),
- non-exploitability proof (formal/solver-backed evidence).

## Requested tools
| Tool | Status | Path | Version / Identity | Primary role |
|---|---|---|---|---|
| halmos | installed | `/home/teycir/.local/bin/halmos` | `halmos 0.3.3` | symbolic/formal fuzzing for Solidity |
| picus | installed | `/home/teycir/.local/bin/picus` | wrapper to `/home/teycir/Repos/Picus/run-picus` | formal underconstraint/safety analysis for Circom/R1CS |
| echidna | installed | `/home/teycir/.local/bin/echidna` | `Echidna 2.2.5` | property-based smart contract fuzzing |
| medusa | installed | `/home/teycir/.local/bin/medusa` | `medusa version 1.4.1` | smart contract fuzzing harness |

Notes:
- `picus --version` is not exposed; identity verified via wrapper and `picus --help` (`run-picus` usage output).
- `run-picus` command name is not in PATH directly; use `picus`.

## ZK and backend toolchain
| Tool | Status | Path | Version |
|---|---|---|---|
| circom | installed | `/home/teycir/.local/bin/circom` | `circom compiler 2.2.3` |
| snarkjs | installed | `/home/teycir/.nvm/versions/node/v20.20.0/bin/snarkjs` | `snarkjs@0.7.6` |
| nargo | installed | `/home/teycir/.nargo/bin/nargo` | `1.0.0-beta.18` |
| scarb | installed | `/home/teycir/.local/bin/scarb` | `2.15.1` |
| cairo-compile | installed | `/home/teycir/.local/bin/cairo-compile` | `0.14.0.1` |
| cairo-run | installed | `/home/teycir/.local/bin/cairo-run` | `0.14.0.1` |
| z3 | installed | `/home/teycir/.local/bin/z3` | `4.13.0` |

## Solidity/security ecosystem
| Tool | Status | Path | Version |
|---|---|---|---|
| forge | installed | `/home/teycir/.foundry/bin/forge` | `1.5.1-stable` |
| cast | installed | `/home/teycir/.foundry/bin/cast` | `1.5.1-stable` |
| anvil | installed | `/home/teycir/.foundry/bin/anvil` | `1.5.1-stable` |
| solc | installed | `/home/teycir/.local/bin/solc` | `0.8.26` |
| slither | installed | `/home/teycir/.local/bin/slither` | `0.11.3` |

## Runtime/build dependencies
| Tool | Status | Path | Version |
|---|---|---|---|
| cargo | installed | `/home/teycir/.cargo/bin/cargo` | `1.91.0-nightly` |
| rustc | installed | `/home/teycir/.cargo/bin/rustc` | `1.91.0-nightly` |
| python3 | installed | `/usr/bin/python3` | `3.12.3` |
| node | installed | `/home/teycir/.nvm/versions/node/v20.20.0/bin/node` | `v20.20.0` |
| npm | installed | `/home/teycir/.nvm/versions/node/v20.20.0/bin/npm` | `10.8.2` |
| pnpm | installed | `/home/teycir/.nvm/versions/node/v20.20.0/bin/pnpm` | `10.30.0` |
| go | installed | `/usr/bin/go` | `go1.22.2 linux/amd64` |

## Not currently installed (checked)
| Tool | Status |
|---|---|
| mythril | missing |
| manticore | missing |
| starknet-compile | missing |
| lean | missing |
| lake | missing |

## Operational usage mapping
| Objective | Primary tools | Output expected |
|---|---|---|
| Discovery (find candidate vulns) | `zk-fuzzer`, `echidna`, `medusa`, `halmos` | failing invariants, oracle findings, corpus artifacts |
| Exploit proof (prove exploit exists) | replay scripts, deterministic witnesses/tx sequences, backend executors | reproducible exploit log with expected vs observed mismatch |
| Non-exploitability proof | `picus` + solver evidence (`z3`/`cvc*`) + bounded replay checks | SAFE proof or bounded no-counterexample evidence |

## Recheck commands
Use these to re-verify local availability quickly:

```bash
halmos --version
picus --help | head -n 20
echidna --version
medusa --version
```

```bash
circom --version
snarkjs --version
nargo --version
scarb --version
z3 --version
```
