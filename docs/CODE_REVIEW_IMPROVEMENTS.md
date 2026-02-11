# Code Review: Potential Improvements

Date: 2026-02-11
Scope: Full repository scan of Rust sources, bins, and core docs. Tests were not executed.

## Findings (Ordered By Severity)

- [Critical] Unconditional termination of other `zk-fuzzer` processes on startup. Location: `src/main.rs:146`.
Impact: Starting a new run can kill unrelated or long-running fuzzers (including other users on shared hosts), lose in-flight evidence, and make batch orchestration brittle.
Recommendation: Gate this behind an explicit flag (for example `--kill-existing`), prefer PID file/lockfile ownership, and use graceful shutdown signals instead of `kill -9`.

- [High] Distributed fuzzing accepts unauthenticated connections on all interfaces and does not enforce `max_message_size`. Locations: `src/distributed/network.rs:49`, `src/distributed/network.rs:255`.
Impact: Any host on the network can connect, send arbitrarily large frames, and cause memory exhaustion or inject bogus work/results.
Recommendation: Default bind to `127.0.0.1`, add optional shared-key or mutual TLS, and enforce `max_message_size` before allocating the buffer.

- [High] External tool invocations do not enforce timeouts and may hang runs indefinitely. Example: `src/reporting/evidence.rs:575`.
Impact: `npx`, `snarkjs`, `circom`, `nargo`, or `scarb` can hang or prompt interactively, stalling campaigns and leaving isolation ineffective.
Recommendation: Use `tokio::process` with timeouts or a `wait_timeout` helper; pass `--yes` to `npx` to prevent prompts; capture stderr for debugging on timeout.

- [High] PTau download uses `curl` without integrity verification. Location: `crates/zk-backends/src/circom/mod.rs:1067`.
Impact: Supply-chain risk in evidence mode and non-reproducible results if the remote file changes or is tampered with.
Recommendation: Require an explicit user-provided PTau file or validate a pinned checksum/signature before use.

- [Medium] Isolated exec worker response path is predictable in the shared temp directory. Location: `src/executor/isolated.rs:601`.
Impact: On multi-user systems, a malicious actor could pre-create a symlink and redirect writes, or race the worker response file.
Recommendation: Use `tempfile::NamedTempFile` (or open with `O_EXCL`) and pass the file descriptor or path securely.

- [Medium] Non-UTF8 circuit paths are silently replaced with an empty string when creating an executor. Location: `src/fuzzer/engine.rs:239`.
Impact: This can lead to confusing “file not found” errors against `""` rather than the actual path, and silently bypass correct path handling.
Recommendation: Propagate an error when `to_str()` fails, or keep `Path`/`OsStr` throughout executor creation.

- [Medium] `zk0d_batch` always requires invariants, even when `mode` is not `evidence`. Location: `src/bin/zk0d_batch.rs:164`.
Impact: Batch runs in `run` or `chains` mode can fail unnecessarily, reducing usability for non-evidence campaigns.
Recommendation: Gate the invariant requirement on `mode == "evidence"` or add a flag to enforce invariants explicitly.

- [Medium] Corpus loader silently drops invalid hex inputs and ignores persisted fields like `execution_count`. Location: `crates/zk-fuzzer-core/src/corpus/storage.rs:27`.
Impact: Resumed corpora can become corrupted or skew energy scheduling without clear errors.
Recommendation: Fail fast on invalid inputs and restore stored fields to preserve corpus semantics.

- [Low] Sorting by `partial_cmp(...).unwrap()` can panic on NaN confidence scores. Locations: `src/bin/zk0d_skimmer.rs:137`, `src/config/generator.rs:167`.
Impact: Edge-case scoring bugs can crash analysis and skimmer flows.
Recommendation: Use `total_cmp`, filter NaNs, or provide a deterministic fallback ordering.

- [Low] Sample config generator uses a Circom circuit path regardless of chosen framework. Location: `src/main.rs:499`.
Impact: New users selecting Noir or Halo2 get a misleading example that fails to run without manual edits.
Recommendation: Template the circuit extension and path by framework.

- [Low] Resource monitor assumes 4KB pages and 100Hz ticks on Unix. Location: `src/executor/isolation_hardening.rs:331`.
Impact: CPU and memory usage can be misreported on systems with different page sizes or clock ticks.
Recommendation: Use `libc::sysconf` for page size and ticks per second.

## Test Gaps Worth Closing

- Add a distributed-network test that rejects oversized frames and verifies authentication defaults.
- Add integration tests for executor creation with non-UTF8 paths and for corpus resume integrity.
- Add regression tests for external tool timeouts to avoid indefinite hangs.
