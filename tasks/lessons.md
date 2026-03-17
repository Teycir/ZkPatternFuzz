# Lessons

- When working on external target intake in this repo, do not assume the checked-in `config.env` bindings or manual external matrix reflect the user's current targets. Confirm the live target root first and prefer dynamic discovery over hardcoded path assumptions.
- When renaming runtime configuration, remove the old name completely from code paths and docs when the user explicitly asks for a full reform. Do not keep silent compatibility fallbacks.
