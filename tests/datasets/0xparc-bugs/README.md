# 0xPARC Validation Dataset Staging

This directory is used by the validation scripts for the 0xPARC bug tracker corpus.

Expected layout:
- `tests/datasets/0xparc-bugs/circuits/` for extracted `.circom` fixtures.
- markdown source files from `https://github.com/0xPARC/zk-bug-tracker` when available.

Use `tests/scripts/extract_0xparc_bugs.py` to extract circuit snippets from markdown.
