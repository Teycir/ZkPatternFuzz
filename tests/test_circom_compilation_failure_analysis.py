#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "analyze_circom_compilation_failures.py"
    spec = importlib.util.spec_from_file_location(
        "analyze_circom_compilation_failures", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


analysis = _load_module()


class CircomCompilationFailureAnalysisTests(unittest.TestCase):
    def test_extract_includes(self):
        with tempfile.TemporaryDirectory() as tmp:
            circuit = Path(tmp) / "a.circom"
            circuit.write_text(
                'pragma circom 2.0.0;\ninclude "circomlib/circuits/poseidon.circom";\n',
                encoding="utf-8",
            )
            includes = analysis._extract_includes(circuit)
            self.assertEqual(includes, ["circomlib/circuits/poseidon.circom"])

    def test_analyze_counts_failed_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            circuit_rel = "tests/safe_circuits/nullifier_secure.circom"
            circuit_abs = repo_root / circuit_rel
            circuit_abs.parent.mkdir(parents=True, exist_ok=True)
            circuit_abs.write_text(
                'include "circomlib/circuits/poseidon.circom";\n', encoding="utf-8"
            )
            outcomes = [
                {
                    "target_name": "nullifier_secure",
                    "reason_counts": {"circom_compilation_failed": 1},
                },
                {
                    "target_name": "range_check_safe",
                    "reason_counts": {"completed": 1},
                },
            ]
            target_map = {"nullifier_secure": circuit_rel}
            result = analysis._analyze(outcomes, target_map, repo_root)
            self.assertEqual(result["circom_compilation_failed_occurrences"], 1)
            self.assertEqual(result["failed_target_count"], 1)
            self.assertEqual(
                result["include_import_counts"]["circomlib/circuits/poseidon.circom"], 1
            )


if __name__ == "__main__":
    unittest.main()
