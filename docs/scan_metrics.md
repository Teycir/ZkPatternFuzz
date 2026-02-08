# Scan Metrics

This document encodes the metrics used to distinguish scan modes and to judge whether a mode is "mature enough" for surface-level discovery.

**Purpose**

The goal is to compare modes using measurable quantities that are reproducible and statistically grounded.

**Definitions**

- A confirmed finding is a unique minimal repro (hash of inputs + invariant + target).
- `L_min` is the minimum event-chain length that triggers the violation. `L_min = 1` is surface-level.
- A mode `m` is evaluated over `R` independent runs with the same budget `B` (time or iterations).

**Metrics**

- Throughput `T = tests / sec`.
- Time-to-first-TP `t_TP` in seconds.
- Precision `P = confirmed / reported` with Wilson 95% CI.
- Reproducibility `R = reproductions / attempts`.
- Surface-level recall lower bound using Chao1 on findings with `L_min = 1`:
  - `S_obs` = number of unique surface findings observed across runs.
  - `f1` = number of surface findings seen in exactly 1 run.
  - `f2` = number of surface findings seen in exactly 2 runs.
  - `S_hat = S_obs + (f1^2) / (2*f2)` when `f2 > 0`.
  - `Recall_hat = S_obs / S_hat`.
- Depth score `D = mean(L_min)` over confirmed findings.
- Deep finding share `P_deep = P(L_min >= 2)` over confirmed findings.
- Evidence score (0 to 3):
  - +1 witness check passes.
  - +1 proof verifies.
  - +1 protocol invariant violation validated.

**Mode Distinction**

- Mode 1 (Fast Skimmer): highest `T`, lowest `P` and `Recall_hat`, `D` near 1, `P_deep` near 0.
- Mode 2 (YAML Deeper Searcher): lower `T`, higher `P` and `Recall_hat`, `D` near 1, stronger evidence scores.
- Mode 3 (YAML Deepest Searcher): lowest `T`, highest `P_deep`, `D` materially > 1, strong evidence scores on chained PoCs.

**Surface-Level "Mature Enough" Criteria**

These thresholds are typical, adjust them to your risk tolerance.

- `Recall_hat >= 0.8` with 95% lower CI >= 0.7.
- `P >= 0.6` with Wilson 95% lower CI >= 0.5.
- `R >= 0.9` repro rate.

**Plain-English Summary**

Use Mode 1 to go fast and find obvious signals, but expect misses. Use Mode 2 when you want surface-level findings that are mostly true positives with low miss rate. Use Mode 3 when you need multi-step logic bugs and are willing to spend more time for deeper evidence. The metrics above quantify speed, accuracy, and depth so each mode can be compared fairly.
