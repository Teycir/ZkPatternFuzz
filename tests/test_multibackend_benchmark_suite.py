#!/usr/bin/env python3
import re
from pathlib import Path
import unittest


def parse_suite_coverage(yaml_text: str):
    suite_re = re.compile(r"^\s{2}([A-Za-z0-9_\-]+):\s*$")
    positive_re = re.compile(r"^\s{4}positive:\s*(true|false)\s*$", re.IGNORECASE)
    target_re = re.compile(r"^\s{6}-\s+name:\s*(.+?)\s*$")
    framework_re = re.compile(r"^\s{8}framework:\s*(.+?)\s*$")

    suite = None
    positive = None
    in_target = False

    coverage = {
        "safe": {},
        "vulnerable": {},
    }

    for raw in yaml_text.splitlines():
        line = raw.rstrip("\n")
        m = suite_re.match(line)
        if m:
            suite = m.group(1)
            positive = None
            in_target = False
            continue

        m = positive_re.match(line)
        if m:
            positive = m.group(1).lower() == "true"
            continue

        if target_re.match(line):
            in_target = True
            continue

        if in_target:
            m = framework_re.match(line)
            if m and positive is not None:
                fw = m.group(1).strip().strip("\"'").lower()
                bucket = "vulnerable" if positive else "safe"
                coverage[bucket][fw] = coverage[bucket].get(fw, 0) + 1

    return coverage


class MultiBackendBenchmarkSuiteTests(unittest.TestCase):
    def test_suite_has_safe_and_vulnerable_targets_for_each_required_backend(self):
        suite_path = Path("targets/benchmark_suites.multibackend.dev.yaml")
        content = suite_path.read_text(encoding="utf-8")

        coverage = parse_suite_coverage(content)
        required = ["circom", "noir", "cairo", "halo2"]

        for backend in required:
            self.assertGreaterEqual(
                coverage["safe"].get(backend, 0),
                1,
                f"safe suite missing backend {backend}",
            )
            self.assertGreaterEqual(
                coverage["vulnerable"].get(backend, 0),
                1,
                f"vulnerable suite missing backend {backend}",
            )


if __name__ == "__main__":
    unittest.main()
