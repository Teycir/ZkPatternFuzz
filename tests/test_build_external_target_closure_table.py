#!/usr/bin/env python3
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "build_external_target_closure_table.py"
    spec = importlib.util.spec_from_file_location(
        "build_external_target_closure_table", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


closure = _load_module()


class BuildExternalTargetClosureTableTests(unittest.TestCase):
    def test_load_matrix_targets_supports_name_and_override_id_forms(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "matrix.yaml"
            path.write_text(
                """
version: 1
targets:
  - name: ext003_demo_target
  - name: no_prefix_target
    run_overrides_file: external/target_run_overrides/ext014_anything.json
""".strip()
                + "\n",
                encoding="utf-8",
            )
            targets = closure.load_matrix_targets(path)

        self.assertEqual(
            [item["target_id"] for item in targets],
            ["EXT-003", "EXT-014"],
        )

    def test_classify_no_exploit_doc_detects_pending_and_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            pending = Path(tmp) / "pending.md"
            pending.write_text("Conclusion: pending_proof.\n", encoding="utf-8")
            closed = Path(tmp) / "closed.md"
            closed.write_text(
                "Conclusion: not_exploitable_within_bounds.\n", encoding="utf-8"
            )

            self.assertEqual(closure.classify_no_exploit_doc(pending), "pending_proof")
            self.assertEqual(
                closure.classify_no_exploit_doc(closed),
                "not_exploitable_within_bounds",
            )

    def test_classify_no_exploit_doc_prefers_closed_over_historical_pending_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            mixed = Path(tmp) / "mixed.md"
            mixed.write_text(
                "Status update: pending_proof -> bounded_non_exploit_evidence_present.\n"
                "Result: **not exploitable within checked bounds**.\n",
                encoding="utf-8",
            )

            self.assertEqual(
                closure.classify_no_exploit_doc(mixed),
                "not_exploitable_within_bounds",
            )

    def test_resolve_target_row_ext005_stays_blocked_when_findings_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            no_exploit = base / "artifacts" / "proof_runs" / "ext005" / "run_x" / "no_exploit_proof.md"
            no_exploit.parent.mkdir(parents=True, exist_ok=True)
            no_exploit.write_text(
                "Conclusion: not_exploitable_within_bounds.\n", encoding="utf-8"
            )
            summary = base / "artifacts" / "external_targets" / "x" / "report_foo_ext005" / "summary.json"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text(json.dumps({"modes": {"misc": {"status": "completed"}}}), encoding="utf-8")

            file_index = {
                "EXT-005": {
                    "no_exploit_proof.md": [no_exploit],
                    "summary.json": [summary],
                }
            }
            row = closure.resolve_target_row(
                target_id="EXT-005",
                target_name="ext005_ezkl_cargo",
                file_index=file_index,
                ext005_open_findings=3,
            )

        self.assertEqual(row["closure_class"], "blocked")
        self.assertIn("3 finding(s) still open", row["current_scope"])

    def test_resolve_target_row_prefers_exploit_when_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            exploit = base / "artifacts" / "external_targets" / "x" / "EXT-003" / "run" / "exploit_notes.md"
            exploit.parent.mkdir(parents=True, exist_ok=True)
            exploit.write_text("# exploit\n", encoding="utf-8")
            no_exploit = base / "artifacts" / "external_targets" / "x" / "EXT-003" / "run" / "no_exploit_proof.md"
            no_exploit.write_text("not_exploitable_within_bounds\n", encoding="utf-8")

            file_index = {
                "EXT-003": {
                    "exploit_notes.md": [exploit],
                    "no_exploit_proof.md": [no_exploit],
                }
            }
            row = closure.resolve_target_row(
                target_id="EXT-003",
                target_name="ext003_zkfuzz_vulnerable_iszero",
                file_index=file_index,
                ext005_open_findings=0,
            )

        self.assertEqual(row["closure_class"], "exploitable")
        self.assertEqual(row["current_scope"], "target-level closed")


if __name__ == "__main__":
    unittest.main()
