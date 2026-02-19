#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sys
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "validate_artifact_mirror_panics.py"
    spec = importlib.util.spec_from_file_location(
        "validate_artifact_mirror_panics", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


panic_validator = _load_module()


class ArtifactMirrorPanicTests(unittest.TestCase):
    def test_passes_when_no_panic_reasons_present(self):
        outcomes = [
            {"reason_counts": {"completed": 1}},
            {"reason_counts": {"critical_findings_detected": 1}},
        ]
        result = panic_validator._panic_summary(outcomes)
        self.assertTrue(result["passes"])
        self.assertEqual(result["panic_occurrences"], 0)
        self.assertEqual(result["affected_rows"], [])

    def test_fails_when_missing_command_panic_reason_present(self):
        outcomes = [
            {
                "suite_name": "safe",
                "target_name": "foo",
                "trial_idx": 1,
                "reason_counts": {"artifact_mirror_panic_missing_command": 1},
            }
        ]
        result = panic_validator._panic_summary(outcomes)
        self.assertFalse(result["passes"])
        self.assertEqual(result["panic_occurrences"], 1)
        self.assertEqual(len(result["affected_rows"]), 1)


if __name__ == "__main__":
    unittest.main()
