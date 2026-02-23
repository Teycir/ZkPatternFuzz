#!/usr/bin/env python3
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "build_semantic_exit_report.py"
    spec = importlib.util.spec_from_file_location("build_semantic_exit_report", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


reporter = _load_module()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class BuildSemanticExitReportTests(unittest.TestCase):
    def test_discover_semantic_reports(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_json(
                root / "a" / "semantic_track_report.json",
                {"run_id": "a", "extracted_intent_sources": 1, "violations": []},
            )
            _write_json(
                root / "b" / "semantic_track_report.json",
                {"run_id": "b", "extracted_intent_sources": 2, "violations": []},
            )
            reports = reporter.discover_semantic_reports(root)
            self.assertEqual(len(reports), 2)
            self.assertTrue(reports[0].name == "semantic_track_report.json")

    def test_build_report_hits_numeric_targets_without_manual_labels(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            run1 = root / "post_roadmap" / "semantic" / "run-1"
            run2 = root / "post_roadmap" / "semantic" / "run-2"

            _write_json(
                run1 / "semantic_track_report.json",
                {
                    "run_id": "run-1",
                    "extracted_intent_sources": 12,
                    "violations": [
                        {
                            "finding_id": "f-1",
                            "assessment": {"exploitable": True},
                        },
                        {
                            "finding_id": "f-2",
                            "assessment": {"exploitable": False},
                        },
                    ],
                },
            )
            _write_json(
                run1 / "semantic_actionable_report.json",
                {
                    "findings": [
                        {"fix_suggestion": "Add verifier guard"},
                        {"fix_suggestion": "Replace bypass placeholder"},
                    ]
                },
            )

            _write_json(
                run2 / "semantic_track_report.json",
                {
                    "run_id": "run-2",
                    "extracted_intent_sources": 10,
                    "violations": [
                        {
                            "finding_id": "f-3",
                            "assessment": {"exploitable": True},
                        },
                        {
                            "finding_id": "f-4",
                            "assessment": {"exploitable": True},
                        },
                    ],
                },
            )
            _write_json(
                run2 / "semantic_actionable_report.json",
                {"findings": [{"fix_suggestion": "Enforce authorization invariant"}]},
            )

            reports = reporter.discover_semantic_reports(root)
            report = reporter.build_report(reports, None)
            summary = report["summary"]
            targets = report["targets"]

            self.assertEqual(summary["semantic_runs"], 2)
            self.assertEqual(summary["total_intent_sources"], 22)
            self.assertEqual(summary["total_semantic_violations"], 4)
            self.assertEqual(summary["total_fix_suggestions"], 3)
            self.assertTrue(targets["intent_sources_ge_20"])
            self.assertTrue(targets["semantic_violations_ge_3"])
            self.assertTrue(targets["actionable_reports_present"])
            self.assertFalse(targets["manual_precision_ge_0_80"])
            self.assertTrue(targets["overall_pass"])

    def test_manual_precision_computation(self):
        labels_payload = {
            "labels": [
                {"run_id": "run-1", "finding_id": "f-1", "exploitable": True},
                {"run_id": "run-1", "finding_id": "f-2", "exploitable": True},
                {"run_id": "run-1", "finding_id": "f-3", "exploitable": False},
            ]
        }
        labels = reporter.parse_manual_labels(labels_payload)
        stats = reporter.compute_manual_precision(
            labels,
            {
                ("run-1", "f-1"): True,
                ("run-1", "f-2"): False,
                ("run-1", "f-3"): True,
            },
        )
        self.assertEqual(stats["matched_labels"], 3)
        self.assertEqual(stats["predicted_positive"], 2)
        self.assertEqual(stats["true_positive"], 1)
        self.assertEqual(stats["false_positive"], 1)
        self.assertEqual(stats["precision"], 0.5)


if __name__ == "__main__":
    unittest.main()
