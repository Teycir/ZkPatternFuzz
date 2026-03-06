#!/usr/bin/env python3
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
import unittest

import yaml


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "build_validation_corpus_report.py"
    spec = importlib.util.spec_from_file_location(
        "build_validation_corpus_report", module_path
    )
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


def _write_yaml(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


class BuildValidationCorpusReportTests(unittest.TestCase):
    def test_git_head_returns_none_outside_git_checkout(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_validation_git_") as tmpdir:
            root = Path(tmpdir)
            self.assertIsNone(reporter.git_head(root))

    def test_summarize_benchmark_lane_counts_positive_and_negative_controls(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_validation_benchmark_") as tmpdir:
            root = Path(tmpdir)
            summary_path = root / "artifacts" / "benchmark" / "summary.json"
            _write_json(
                summary_path,
                {
                    "total_runs": 6,
                    "vulnerable_recall": 0.5,
                    "vulnerable_high_confidence_recall": 0.25,
                    "safe_false_positive_rate": 0.0,
                    "safe_high_confidence_false_positive_rate": 0.0,
                    "overall_completion_rate": 1.0,
                    "suites": [
                        {"suite_name": "vuln", "positive": True, "runs_total": 4},
                        {"suite_name": "safe", "positive": False, "runs_total": 2},
                    ],
                },
            )
            lane = {
                "evidence_paths": {
                    "summary_json": "artifacts/benchmark/summary.json",
                    "report_md": "docs/report.md",
                }
            }
            details = reporter.summarize_benchmark_lane(lane, root)
            self.assertEqual(details["positive_control_runs"], 4)
            self.assertEqual(details["negative_control_runs"], 2)
            self.assertEqual(details["total_runs"], 6)

    def test_summarize_semantic_lane_uses_overall_pass_flag(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_validation_semantic_") as tmpdir:
            root = Path(tmpdir)
            summary_path = root / "artifacts" / "semantic" / "latest_report.json"
            _write_json(
                summary_path,
                {
                    "summary": {
                        "semantic_runs": 1,
                        "total_intent_sources": 25,
                        "total_semantic_violations": 4,
                        "total_fix_suggestions": 4,
                    },
                    "targets": {"overall_pass": True},
                },
            )
            lane = {"evidence_paths": {"summary_json": "artifacts/semantic/latest_report.json"}}
            details = reporter.summarize_semantic_lane(lane, root)
            self.assertEqual(details["status"], "pass")
            self.assertTrue(details["overall_pass"])
            self.assertEqual(details["total_semantic_violations"], 4)

    def test_summarize_cve_lane_counts_catalog_entries_and_fixtures(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_validation_cve_") as tmpdir:
            root = Path(tmpdir)
            catalog_path = root / "templates" / "known_vulnerabilities.yaml"
            fixtures_dir = root / "tests" / "cve_fixtures"
            fixtures_dir.mkdir(parents=True, exist_ok=True)
            (fixtures_dir / "a.circom").write_text("template A() {}\n", encoding="utf-8")
            (fixtures_dir / "b.circom").write_text("template B() {}\n", encoding="utf-8")
            _write_yaml(
                catalog_path,
                {
                    "vulnerabilities": [
                        {
                            "id": "ZK-CVE-1",
                            "regression_test": {
                                "enabled": True,
                                "circuit_path": "tests/cve_fixtures/a.circom",
                            },
                        },
                        {
                            "id": "ZK-CVE-2",
                            "regression_test": {
                                "enabled": False,
                                "circuit_path": "elsewhere/b.circom",
                            },
                        },
                    ]
                },
            )
            lane = {
                "evidence_paths": {
                    "catalog_yaml": "templates/known_vulnerabilities.yaml",
                    "fixtures_dir": "tests/cve_fixtures",
                }
            }
            details = reporter.summarize_cve_lane(lane, root)
            self.assertEqual(details["catalog_entries"], 2)
            self.assertEqual(details["enabled_regressions"], 1)
            self.assertEqual(details["bundled_fixture_refs"], 1)
            self.assertEqual(details["bundled_fixture_files"], 2)

    def test_build_report_aggregates_lane_counts(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_validation_report_") as tmpdir:
            root = Path(tmpdir)
            _write_json(
                root / "artifacts" / "benchmark" / "summary.json",
                {
                    "total_runs": 3,
                    "vulnerable_recall": 1.0,
                    "vulnerable_high_confidence_recall": 0.0,
                    "safe_false_positive_rate": 0.0,
                    "safe_high_confidence_false_positive_rate": 0.0,
                    "overall_completion_rate": 1.0,
                    "suites": [
                        {"suite_name": "vuln", "positive": True, "runs_total": 2},
                        {"suite_name": "safe", "positive": False, "runs_total": 1},
                    ],
                },
            )
            replay_dir = root / "artifacts" / "replay"
            replay_dir.mkdir(parents=True, exist_ok=True)
            (replay_dir / "replay_command.txt").write_text("python3 replay.py\n", encoding="utf-8")
            (replay_dir / "exploit_notes.md").write_text(
                "# Notes\n\n## Conclusion\n`exploitable`\n", encoding="utf-8"
            )
            (replay_dir / "replay.log").write_text("ok\n", encoding="utf-8")
            (replay_dir / "impact.md").write_text("impact\n", encoding="utf-8")
            _write_json(
                root / "artifacts" / "semantic" / "latest_report.json",
                {
                    "summary": {
                        "semantic_runs": 1,
                        "total_intent_sources": 30,
                        "total_semantic_violations": 5,
                        "total_fix_suggestions": 5,
                    },
                    "targets": {"overall_pass": True},
                },
            )
            fixtures_dir = root / "tests" / "cve_fixtures"
            fixtures_dir.mkdir(parents=True, exist_ok=True)
            (fixtures_dir / "fixture.circom").write_text("template F() {}\n", encoding="utf-8")
            _write_yaml(
                root / "templates" / "known_vulnerabilities.yaml",
                {
                    "vulnerabilities": [
                        {
                            "id": "ZK-CVE-1",
                            "regression_test": {
                                "enabled": True,
                                "circuit_path": "tests/cve_fixtures/fixture.circom",
                            },
                        }
                    ]
                },
            )
            manifest = {
                "schema_version": "1",
                "title": "Validation Corpus",
                "lanes": [
                    {
                        "id": "bench",
                        "kind": "benchmark_publication",
                        "title": "Bench",
                        "description": "desc",
                        "rerun_command": "run bench",
                        "evidence_paths": {
                            "summary_json": "artifacts/benchmark/summary.json",
                            "report_md": "docs/report.md",
                        },
                    },
                    {
                        "id": "replay",
                        "kind": "deterministic_replay",
                        "title": "Replay",
                        "description": "desc",
                        "rerun_command": "run replay",
                        "evidence_paths": {
                            "replay_command": "artifacts/replay/replay_command.txt",
                            "exploit_notes": "artifacts/replay/exploit_notes.md",
                            "replay_log": "artifacts/replay/replay.log",
                            "impact_md": "artifacts/replay/impact.md",
                            "report_md": "docs/replay.md",
                        },
                    },
                    {
                        "id": "semantic",
                        "kind": "semantic_validation",
                        "title": "Semantic",
                        "description": "desc",
                        "rerun_command": "run semantic",
                        "evidence_paths": {
                            "summary_json": "artifacts/semantic/latest_report.json",
                            "campaign_readme": "campaigns/semantic/README.md",
                            "guide_md": "docs/guide.md",
                        },
                    },
                    {
                        "id": "cve",
                        "kind": "cve_regression_lane",
                        "title": "CVE",
                        "description": "desc",
                        "rerun_command": "run cve",
                        "evidence_paths": {
                            "catalog_yaml": "templates/known_vulnerabilities.yaml",
                            "runner_rs": "tests/cve_regression_runner.rs",
                            "fixtures_dir": "tests/cve_fixtures",
                            "catalog_readme": "CVErefs/README.md",
                        },
                    },
                ],
            }
            (root / "campaigns" / "semantic").mkdir(parents=True, exist_ok=True)
            (root / "campaigns" / "semantic" / "README.md").write_text("semantic\n", encoding="utf-8")
            (root / "docs").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "report.md").write_text("report\n", encoding="utf-8")
            (root / "docs" / "replay.md").write_text("replay\n", encoding="utf-8")
            (root / "docs" / "guide.md").write_text("guide\n", encoding="utf-8")
            (root / "tests" / "cve_regression_runner.rs").write_text("// runner\n", encoding="utf-8")
            (root / "CVErefs").mkdir(parents=True, exist_ok=True)
            (root / "CVErefs" / "README.md").write_text("cve\n", encoding="utf-8")

            report = reporter.build_report(manifest, root)
            summary = report["summary"]
            self.assertEqual(summary["lane_count"], 4)
            self.assertEqual(summary["published_positive_control_runs"], 2)
            self.assertEqual(summary["published_negative_control_runs"], 1)
            self.assertEqual(summary["deterministic_replay_cases"], 1)
            self.assertEqual(summary["semantic_validation_runs"], 1)
            self.assertEqual(summary["cve_catalog_entries"], 1)


if __name__ == "__main__":
    unittest.main()
