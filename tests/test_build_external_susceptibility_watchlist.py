#!/usr/bin/env python3
import importlib.util
import sys
import tempfile
from pathlib import Path
import unittest

import yaml


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "build_external_susceptibility_watchlist.py"
    spec = importlib.util.spec_from_file_location(
        "build_external_susceptibility_watchlist", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


watchlist = _load_module()


class BuildExternalSusceptibilityWatchlistTests(unittest.TestCase):
    def test_classify_cargo_framework_detects_known_framework_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            halo2_path = root / "halo2" / "Cargo.toml"
            halo2_path.parent.mkdir(parents=True, exist_ok=True)
            halo2_path.write_text("halo2_proofs = \"0.3\"\n", encoding="utf-8")

            plonky2_path = root / "plonky2" / "Cargo.toml"
            plonky2_path.parent.mkdir(parents=True, exist_ok=True)
            plonky2_path.write_text("plonky2 = { git = \"https://example.com\" }\n", encoding="utf-8")

            sp1_path = root / "sp1" / "Cargo.toml"
            sp1_path.parent.mkdir(parents=True, exist_ok=True)
            sp1_path.write_text("name = \"sp1-sample\"\n", encoding="utf-8")

            self.assertEqual(watchlist.classify_cargo_framework(halo2_path), "halo2")
            self.assertEqual(watchlist.classify_cargo_framework(plonky2_path), "plonky2")
            self.assertEqual(watchlist.classify_cargo_framework(sp1_path), "sp1")

    def test_detect_new_repo_candidates_marks_support_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            circom_repo = root / "repo_circom"
            circom_repo.mkdir(parents=True, exist_ok=True)
            (circom_repo / "sample.circom").write_text("template T(){}\n", encoding="utf-8")

            plonky2_repo = root / "repo_plonky2"
            plonky2_repo.mkdir(parents=True, exist_ok=True)
            (plonky2_repo / "Cargo.toml").write_text(
                "plonky2 = { git = \"https://example.com\" }\n",
                encoding="utf-8",
            )

            rows = watchlist.detect_new_repo_candidates([circom_repo, plonky2_repo])

        self.assertEqual(rows[0]["framework"], "circom")
        self.assertEqual(rows[0]["support_status"], "supported_by_current_executor")
        self.assertEqual(rows[1]["framework"], "plonky2")
        self.assertEqual(rows[1]["support_status"], "not_supported_by_current_executor")

    def test_build_candidate_shortlist_respects_manual_exclusion_and_repo_cap(self):
        external_all_rows = [
            {
                "name": "a1",
                "framework": "circom",
                "target_circuit": "/repo1/circuits/a1_iszero.circom",
                "main_component": "main",
                "intel": {"framework_prior": {"known_issue_count": 10}},
            },
            {
                "name": "a2",
                "framework": "circom",
                "target_circuit": "/repo1/circuits/a2_lessthan.circom",
                "main_component": "main",
                "intel": {"framework_prior": {"known_issue_count": 10}},
            },
            {
                "name": "b1",
                "framework": "circom",
                "target_circuit": "/repo2/circuits/b1_vuln.circom",
                "main_component": "main",
                "intel": {"framework_prior": {"known_issue_count": 8}},
            },
        ]
        manual_rows = [
            {"target_circuit": "/repo1/circuits/a1_iszero.circom"},
        ]
        shortlist = watchlist.build_candidate_shortlist(
            external_all_rows=external_all_rows,
            manual_rows=manual_rows,
            catalog_repo_paths=["/repo1", "/repo2"],
            limit=5,
            per_repo_limit=1,
        )
        chosen_paths = [row["target_circuit"] for row in shortlist]
        self.assertEqual(len(shortlist), 2)
        self.assertNotIn("/repo1/circuits/a1_iszero.circom", chosen_paths)
        self.assertIn("/repo1/circuits/a2_lessthan.circom", chosen_paths)
        self.assertIn("/repo2/circuits/b1_vuln.circom", chosen_paths)

    def test_build_matrix_yaml_sets_targets_disabled(self):
        matrix_yaml = watchlist.build_matrix_yaml(
            shortlist=[
                {
                    "name": "candidate_one",
                    "framework": "circom",
                    "target_circuit": "/repo/candidate.circom",
                    "main_component": "main",
                    "score": 42.0,
                    "reasons": ["framework_prior=45"],
                }
            ],
            generated_utc="2026-03-02T00:00:00+00:00",
        )
        payload = yaml.safe_load(matrix_yaml)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(len(payload["targets"]), 1)
        self.assertFalse(payload["targets"][0]["enabled"])
        self.assertEqual(payload["targets"][0]["framework"], "circom")

    def test_build_repo_priority_ranking_orders_by_risk(self):
        external_all_rows = [
            {
                "name": "r1_high",
                "framework": "circom",
                "target_circuit": "/repo1/circuits/high_vuln_iszero.circom",
                "main_component": "main",
                "intel": {"framework_prior": {"known_issue_count": 40}},
            },
            {
                "name": "r1_mid",
                "framework": "circom",
                "target_circuit": "/repo1/circuits/mid_lessthan.circom",
                "main_component": "main",
                "intel": {"framework_prior": {"known_issue_count": 10}},
            },
            {
                "name": "r2_low",
                "framework": "halo2",
                "target_circuit": "/repo2/Cargo.toml",
                "main_component": "main",
                "intel": {"framework_prior": {"known_issue_count": 1}},
            },
        ]
        ranking = watchlist.build_repo_priority_ranking(
            external_all_rows=external_all_rows,
            manual_rows=[],
            catalog_repo_paths=["/repo1", "/repo2"],
            topk=2,
        )
        self.assertEqual(len(ranking), 2)
        self.assertEqual(ranking[0]["repo_path"], "/repo1")
        self.assertGreater(ranking[0]["risk_index"], ranking[1]["risk_index"])

    def test_render_markdown_includes_repo_priority_section(self):
        report = {
            "generated_utc": "2026-03-02T00:00:00+00:00",
            "source_root": "/media/elements/Repos",
            "summary": {
                "zk_like_repos_discovered": 1,
                "catalog_repositories": 1,
                "new_zk_repos_not_in_catalog": 0,
                "shortlist_candidates": 1,
            },
            "new_repos_not_in_catalog": [],
            "candidate_shortlist": [
                {
                    "score": 60.0,
                    "framework": "circom",
                    "target_circuit": "/repo1/c1.circom",
                    "repo_path": "/repo1",
                }
            ],
            "scan_roadmap": [
                {
                    "rank": 1,
                    "tier": "P0",
                    "risk_index": 60.0,
                    "candidate_target_count": 3,
                    "repo_path": "/repo1",
                    "top_target": "/repo1/c1.circom",
                    "frameworks": ["circom"],
                }
            ],
        }
        md = watchlist.render_markdown(report)
        self.assertIn("## Repo Priority Ranking (Most Likely -> Least Likely)", md)
        self.assertIn("| 1 | `P0` | 60.00 | 3 | `/repo1` | `/repo1/c1.circom` |", md)


if __name__ == "__main__":
    unittest.main()
