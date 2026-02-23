#!/usr/bin/env python3
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "generate_semantic_manual_labels_template.py"
    spec = importlib.util.spec_from_file_location(
        "generate_semantic_manual_labels_template", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


template_builder = _load_module()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class GenerateSemanticManualLabelsTemplateTests(unittest.TestCase):
    def test_build_template(self):
        report = {
            "run_id": "sample-run",
            "violations": [
                {
                    "finding_id": "f-1",
                    "detector": "execution_evidence",
                    "violation_summary": "forged proof accepted",
                    "assessment": {"exploitable": True, "confidence": 91},
                },
                {
                    "finding_id": "f-2",
                    "detector": "source_marker",
                    "violation_summary": "temporary bypass marker",
                    "assessment": {"exploitable": False, "confidence": 40},
                },
            ],
        }
        template = template_builder.build_template(report, "/tmp/report.json")
        self.assertEqual(template["source_report"], "/tmp/report.json")
        self.assertEqual(len(template["labels"]), 2)
        self.assertEqual(template["labels"][0]["run_id"], "sample-run")
        self.assertIsNone(template["labels"][0]["exploitable"])
        self.assertEqual(template["labels"][0]["predicted_exploitable"], True)
        self.assertEqual(template["labels"][0]["predicted_confidence"], 91)

    def test_find_default_report(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_json(
                root / "a" / "semantic_track_report.json",
                {"run_id": "a", "violations": []},
            )
            _write_json(
                root / "b" / "semantic_track_report.json",
                {"run_id": "b", "violations": []},
            )
            path = template_builder.find_default_report(root)
            self.assertIsNotNone(path)
            self.assertEqual(path.name, "semantic_track_report.json")


if __name__ == "__main__":
    unittest.main()
