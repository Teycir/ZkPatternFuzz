#!/usr/bin/env python3
"""Extract Circom snippets from 0xPARC markdown files into circuits/ directory."""

from __future__ import annotations

import argparse
import pathlib
import re


def extract_blocks(markdown: str) -> list[str]:
    pattern = re.compile(r"```(?:circom)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
    return [m.strip() for m in pattern.findall(markdown) if "template" in m or "pragma" in m]


def sanitize_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        default="tests/datasets/0xparc-bugs",
        help="Path containing 0xPARC markdown files",
    )
    parser.add_argument(
        "--out",
        default="tests/datasets/0xparc-bugs/circuits",
        help="Output directory for extracted circuits",
    )
    args = parser.parse_args()

    source = pathlib.Path(args.source)
    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    md_files = sorted(source.rglob("*.md"))
    extracted = 0

    for md in md_files:
        content = md.read_text(encoding="utf-8", errors="ignore")
        blocks = extract_blocks(content)
        for idx, block in enumerate(blocks, start=1):
            name = sanitize_name(md.stem)
            out_file = out_dir / f"{name}_{idx}.circom"
            out_file.write_text(block + "\n", encoding="utf-8")
            extracted += 1

    print(f"Scanned {len(md_files)} markdown files")
    print(f"Extracted {extracted} circom snippets into {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
