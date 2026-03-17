# Lessons

- When working on external target intake in this repo, do not assume the checked-in `config.env` bindings or manual external matrix reflect the user's current targets. Confirm the live target root first and prefer dynamic discovery over hardcoded path assumptions.
- When renaming runtime configuration, remove the old name completely from code paths and docs when the user explicitly asks for a full reform. Do not keep silent compatibility fallbacks.
- When choosing a first Circom target for a full fuzzing campaign, do not assume every `.circom` file is directly runnable. Prefer files with an explicit `component main`, and treat library-style template sources such as Semaphore's circuit package as non-runnable until proven otherwise.
- When the user asks for a clean target list, do not hand them the raw discovery inventory. First filter out framework repos, monorepo internals, workspace roots, test/docs fixtures, and non-runnable package types, then report prerequisites and dependency blockers for the surviving shortlist.
- In this repo, do not add or keep tests under `src/` when touching backend code. Move coverage into `tests/` and validate behavior through public APIs so production files stay test-free.
