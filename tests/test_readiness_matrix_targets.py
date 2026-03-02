#!/usr/bin/env python3
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
MATRIX_FILES = [
    REPO_ROOT / "targets" / "zk0d_matrix_noir_readiness.yaml",
    REPO_ROOT / "targets" / "zk0d_matrix_cairo_readiness.yaml",
    REPO_ROOT / "targets" / "zk0d_matrix_halo2_readiness.yaml",
]


def parse_enabled_targets(matrix_path: Path):
    entries = []
    current = None

    for raw_line in matrix_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("- name:"):
            if current is not None:
                entries.append(current)
            current = {
                "name": line.split(":", 1)[1].strip(),
                "target_circuit": "",
                "enabled": True,
            }
            continue

        if current is None:
            continue

        if line.startswith("target_circuit:"):
            current["target_circuit"] = line.split(":", 1)[1].strip()
        elif line.startswith("enabled:"):
            value = line.split(":", 1)[1].strip().strip("'\"").lower()
            current["enabled"] = value not in {"false", "0", "no"}

    if current is not None:
        entries.append(current)

    return [entry for entry in entries if entry["enabled"]]


class ReadinessMatrixTargetTests(unittest.TestCase):
    def test_readiness_matrices_have_minimum_enabled_targets(self):
        for matrix_path in MATRIX_FILES:
            with self.subTest(matrix=str(matrix_path.relative_to(REPO_ROOT))):
                enabled_targets = parse_enabled_targets(matrix_path)
                self.assertGreaterEqual(len(enabled_targets), 5)

    def test_readiness_matrices_include_local_and_vendored_external_targets(self):
        for matrix_path in MATRIX_FILES:
            with self.subTest(matrix=str(matrix_path.relative_to(REPO_ROOT))):
                enabled_targets = parse_enabled_targets(matrix_path)
                circuits = [entry["target_circuit"] for entry in enabled_targets]
                local_count = sum(path.startswith("tests/") for path in circuits)
                external_count = sum(path.startswith("targets/external/") for path in circuits)
                self.assertGreaterEqual(local_count, 1)
                self.assertGreaterEqual(external_count, 1)

    def test_readiness_matrices_avoid_host_specific_absolute_paths_for_enabled_targets(self):
        for matrix_path in MATRIX_FILES:
            with self.subTest(matrix=str(matrix_path.relative_to(REPO_ROOT))):
                enabled_targets = parse_enabled_targets(matrix_path)
                circuits = [entry["target_circuit"] for entry in enabled_targets]
                self.assertFalse(any(path.startswith("/media/") for path in circuits))


if __name__ == "__main__":
    unittest.main()
