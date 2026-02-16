#!/usr/bin/env python3
"""
ZkPatternFuzz Validation Dataset Integration Script

This script integrates multiple real-world vulnerability datasets for validation:
- zkBugs: 110 reproducible vulnerabilities from zkSecurity
- 0xPARC zk-bug-tracker: Community-maintained bug database
- User's zk0d targets: Custom test circuits

Usage:
    python3 scripts/integrate_validation_datasets.py
"""

import json
import os
import yaml
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from datetime import datetime

# Configuration
REPO_ROOT = Path(__file__).resolve().parents[1]


def _env_path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    if not value:
        return default
    return Path(value).expanduser().resolve()


TARGETS_DIR = _env_path("ZKFUZZ_TARGETS_DIR", REPO_ROOT / "targets")
ZKBUGS_DIR = TARGETS_DIR / "zkbugs" / "dataset"
ZKBUGTRACKER_DIR = TARGETS_DIR / "zk-bug-tracker"
ZK0D_DIR = TARGETS_DIR / "zk0d"
OUTPUT_DIR = _env_path("ZKFUZZ_VALIDATION_OUTPUT_DIR", REPO_ROOT / "tests" / "validation")

@dataclass
class ValidationTarget:
    """Represents a validation target (vulnerable circuit)."""
    id: str
    name: str
    dsl: str
    project: str
    vulnerability_type: str
    impact: str
    circuit_path: str
    config_path: Optional[str]
    source: str  # "zkbugs", "0xparc", "zk0d"
    severity: str
    reproduced: bool
    
@dataclass
class ValidationReport:
    """Aggregated validation dataset report."""
    generated_at: str
    total_targets: int
    by_dsl: Dict[str, int]
    by_vulnerability: Dict[str, int]
    by_source: Dict[str, int]
    targets: List[Dict]

class DatasetIntegrator:
    """Integrates multiple vulnerability datasets."""
    
    def __init__(self):
        self.targets: List[ValidationTarget] = []
        self.stats = {
            "zkbugs": 0,
            "0xparc": 0,
            "zk0d": 0
        }

    def normalize_path(self, path: Path) -> str:
        """Normalize a filesystem path for reproducible JSON/YAML output."""
        resolved = path.resolve()
        try:
            return resolved.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            return resolved.as_posix()
        
    def parse_zkbugs(self) -> List[ValidationTarget]:
        """Parse zkBugs dataset."""
        targets = []
        
        if not ZKBUGS_DIR.exists():
            print(f"⚠️  zkBugs directory not found: {ZKBUGS_DIR}")
            return targets
        
        # Iterate through DSL directories
        for dsl_dir in ZKBUGS_DIR.iterdir():
            if not dsl_dir.is_dir() or dsl_dir.name == "zkbugs_similar_bugs.json":
                continue
                
            dsl = dsl_dir.name
            
            # Iterate through projects
            for project_dir in dsl_dir.iterdir():
                if not project_dir.is_dir():
                    continue
                    
                project = project_dir.name
                
                # Iterate through repos
                for repo_dir in project_dir.iterdir():
                    if not repo_dir.is_dir():
                        continue
                        
                    repo = repo_dir.name
                    
                    # Iterate through bugs
                    for bug_dir in repo_dir.iterdir():
                        if not bug_dir.is_dir():
                            continue
                            
                        config_file = bug_dir / "zkbugs_config.json"
                        if not config_file.exists():
                            continue
                        
                        try:
                            with open(config_file) as f:
                                config = json.load(f)
                            
                            # Each config has one key (bug name)
                            for bug_name, bug_data in config.items():
                                # Find circuit file
                                circuit_path = None
                                circuits_dir = bug_dir / "circuits"
                                if circuits_dir.exists():
                                    circuit_files = list(circuits_dir.glob("*.circom"))
                                    if circuit_files:
                                        circuit_path = str(circuit_files[0])
                                
                                target = ValidationTarget(
                                    id=bug_data.get("Id", f"{dsl}/{project}/{repo}/{bug_dir.name}"),
                                    name=bug_name,
                                    dsl=dsl,
                                    project=project,
                                    vulnerability_type=bug_data.get("Vulnerability", "Unknown"),
                                    impact=bug_data.get("Impact", "Unknown"),
                                    circuit_path=self.normalize_path(Path(circuit_path)) if circuit_path else self.normalize_path(bug_dir),
                                    config_path=self.normalize_path(config_file),
                                    source="zkbugs",
                                    severity="Critical" if bug_data.get("Vulnerability") == "Under-Constrained" else "High",
                                    reproduced=bug_data.get("Reproduced", False)
                                )
                                targets.append(target)
                                self.stats["zkbugs"] += 1
                                
                        except Exception as e:
                            print(f"  ⚠️  Error parsing {config_file}: {e}")
        
        print(f"✅ Parsed {len(targets)} targets from zkBugs")
        return targets
    
    def parse_0xparc(self) -> List[ValidationTarget]:
        """Parse 0xPARC zk-bug-tracker (README-based)."""
        targets = []
        
        if not ZKBUGTRACKER_DIR.exists():
            print(f"⚠️  0xPARC directory not found: {ZKBUGTRACKER_DIR}")
            return targets
        
        readme = ZKBUGTRACKER_DIR / "README.md"
        if not readme.exists():
            print("⚠️  README.md not found in zk-bug-tracker")
            return targets
        
        # Parse README to extract bug information
        # For now, create synthetic targets based on known bugs
        known_bugs = [
            ("Dark Forest", "Missing Bit Length Check", "Under-Constrained"),
            ("Circom-Pairing", "Missing Output Check", "Under-Constrained"),
            ("Semaphore", "Missing Range Check", "Under-Constrained"),
            ("Aztec 2.0", "Nondeterministic Nullifier", "Under-Constrained"),
            ("0xPARC StealthDrop", "Nondeterministic Nullifier", "Under-Constrained"),
            ("MACI 1.0", "Under-constrained Circuit", "Under-Constrained"),
            ("MiMC Hash", "Assigned but not Constrained", "Under-Constrained"),
            ("Polygon zkEVM", "Missing Remainder Constraint", "Under-Constrained"),
            ("ZK Email", "Under-constrained Circuit", "Under-Constrained"),
        ]
        
        for i, (project, bug_type, vuln_type) in enumerate(known_bugs):
            target = ValidationTarget(
                id=f"0xparc-{i+1}",
                name=f"{project}: {bug_type}",
                dsl="circom",
                project=project.lower().replace(" ", "_"),
                vulnerability_type=vuln_type,
                impact="Soundness",
                circuit_path=f"synthetic/{project.lower().replace(' ', '_')}.circom",
                config_path=None,
                source="0xparc",
                severity="Critical",
                reproduced=False
            )
            targets.append(target)
            self.stats["0xparc"] += 1
        
        print(f"✅ Created {len(targets)} synthetic targets from 0xPARC tracker")
        return targets
    
    def parse_zk0d(self) -> List[ValidationTarget]:
        """Parse user's zk0d targets."""
        targets = []
        
        if not ZK0D_DIR.exists():
            print(f"⚠️  zk0d directory not found: {ZK0D_DIR}")
            return targets
        
        # Parse zk0d_targets.yaml
        targets_yaml = TARGETS_DIR / "zk0d_targets.yaml"
        if targets_yaml.exists():
            with open(targets_yaml) as f:
                config = yaml.safe_load(f)
            
            for i, target in enumerate(config.get("targets", [])):
                if not target.get("enabled", True):
                    continue
                
                vt = ValidationTarget(
                    id=f"zk0d-{i+1}",
                    name=target.get("name", f"zk0d-target-{i}"),
                    dsl="circom",
                    project="iden3",
                    vulnerability_type="Unknown",
                    impact="Unknown",
                    circuit_path=self.normalize_path(ZK0D_DIR),
                    config_path=self.normalize_path(targets_yaml),
                    source="zk0d",
                    severity="High",
                    reproduced=False
                )
                targets.append(vt)
                self.stats["zk0d"] += 1
        
        # Also check for individual circuit files
        for circuit_file in ZK0D_DIR.rglob("*.circom"):
            target = ValidationTarget(
                id=f"zk0d-circuit-{len(targets)}",
                name=circuit_file.stem,
                dsl="circom",
                project="custom",
                vulnerability_type="Unknown",
                impact="Unknown",
                circuit_path=self.normalize_path(circuit_file),
                config_path=None,
                source="zk0d",
                severity="Unknown",
                reproduced=False
            )
            targets.append(target)
            self.stats["zk0d"] += 1
        
        print(f"✅ Parsed {len(targets)} targets from zk0d")
        return targets
    
    def generate_summary(self) -> Dict:
        """Generate summary statistics."""
        by_dsl = {}
        by_vulnerability = {}
        by_source = {"zkbugs": 0, "0xparc": 0, "zk0d": 0}
        
        for target in self.targets:
            # By DSL
            by_dsl[target.dsl] = by_dsl.get(target.dsl, 0) + 1
            
            # By vulnerability type
            by_vulnerability[target.vulnerability_type] = by_vulnerability.get(target.vulnerability_type, 0) + 1
            
            # By source
            by_source[target.source] = by_source.get(target.source, 0) + 1
        
        return {
            "total": len(self.targets),
            "by_dsl": by_dsl,
            "by_vulnerability": by_vulnerability,
            "by_source": by_source
        }
    
    def export_targets_json(self):
        """Export targets to JSON."""
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        
        output_file = OUTPUT_DIR / "validation_targets.json"
        targets_data = [asdict(t) for t in self.targets]
        
        with open(output_file, 'w') as f:
            json.dump(targets_data, f, indent=2)
        
        print(f"✅ Exported {len(targets_data)} targets to {output_file}")
    
    def export_campaign_configs(self):
        """Generate campaign configs for each target."""
        campaigns_dir = OUTPUT_DIR / "campaigns"
        campaigns_dir.mkdir(parents=True, exist_ok=True)
        
        generated = 0
        for target in self.targets:
            if target.source != "zkbugs" or not target.circuit_path:
                continue
            
            # Create campaign config
            campaign = {
                "campaign": {
                    "name": f"Validation: {target.name}",
                    "version": "1.0",
                    "target": {
                        "framework": target.dsl,
                        "circuit_path": target.circuit_path
                    },
                    "parameters": {
                        "additional": {
                            "evidence_mode": True,
                            "strict_backend": True,
                            "timeout_seconds": 600
                        }
                    }
                },
                "attacks": self.get_attacks_for_vulnerability(target.vulnerability_type)
            }
            
            # Save campaign
            safe_name = target.id.replace("/", "_").replace(" ", "_")
            campaign_file = campaigns_dir / f"{safe_name}.yaml"
            
            with open(campaign_file, 'w') as f:
                yaml.dump(campaign, f, default_flow_style=False)
            
            generated += 1
        
        print(f"✅ Generated {generated} campaign configs in {campaigns_dir}")
    
    def get_attacks_for_vulnerability(self, vuln_type: str) -> List[Dict]:
        """Map vulnerability type to attack configurations."""
        mapping = {
            "Under-Constrained": [
                {"type": "underconstrained", "config": {"witness_pairs": 5000, "max_execution_time_ms": 300000}}
            ],
            "Over-Constrained": [
                {"type": "soundness", "config": {"mutation_attempts": 1000}}
            ],
            "Soundness": [
                {"type": "soundness", "config": {"mutation_attempts": 1000}},
                {"type": "underconstrained", "config": {"witness_pairs": 3000}}
            ],
            "Assigned but Unconstrained": [
                {"type": "underconstrained", "config": {"witness_pairs": 3000}},
                {"type": "constraint_inference"}
            ],
            "Missing Constraint": [
                {"type": "underconstrained", "config": {"witness_pairs": 5000}},
                {"type": "constraint_inference"}
            ],
            "Wrong translation of logic into constraints": [
                {"type": "underconstrained", "config": {"witness_pairs": 5000}},
                {"type": "soundness"}
            ]
        }
        return mapping.get(vuln_type, [{"type": "underconstrained"}])
    
    def generate_report(self):
        """Generate validation dataset report."""
        summary = self.generate_summary()
        
        report = ValidationReport(
            generated_at=datetime.now().isoformat(),
            total_targets=summary["total"],
            by_dsl=summary["by_dsl"],
            by_vulnerability=summary["by_vulnerability"],
            by_source=summary["by_source"],
            targets=[asdict(t) for t in self.targets[:100]]  # First 100 for brevity
        )
        
        # Write report
        report_file = OUTPUT_DIR / "dataset_report.json"
        with open(report_file, 'w') as f:
            json.dump(asdict(report), f, indent=2)
        
        # Write markdown summary
        md_file = OUTPUT_DIR / "dataset_summary.md"
        with open(md_file, 'w') as f:
            f.write("# ZkPatternFuzz Validation Dataset Summary\n\n")
            f.write(f"Generated: {report.generated_at}\n\n")
            f.write(f"## Overview\n\n")
            f.write(f"**Total Targets:** {report.total_targets}\n\n")
            
            f.write("### By Source\n\n")
            f.write("| Source | Count |\n|--------|-------|\n")
            for source, count in sorted(report.by_source.items()):
                f.write(f"| {source} | {count} |\n")
            
            f.write("\n### By DSL\n\n")
            f.write("| DSL | Count |\n|-----|-------|\n")
            for dsl, count in sorted(report.by_dsl.items(), key=lambda x: -x[1]):
                f.write(f"| {dsl} | {count} |\n")
            
            f.write("\n### By Vulnerability Type\n\n")
            f.write("| Type | Count |\n|------|-------|\n")
            for vuln, count in sorted(report.by_vulnerability.items(), key=lambda x: -x[1]):
                f.write(f"| {vuln} | {count} |\n")
            
            f.write("\n## Sample Targets\n\n")
            for i, target in enumerate(self.targets[:10]):
                f.write(f"{i+1}. **{target.name}** ({target.dsl})\n")
                f.write(f"   - Source: {target.source}\n")
                f.write(f"   - Vulnerability: {target.vulnerability_type}\n")
                f.write(f"   - Severity: {target.severity}\n\n")
        
        print(f"✅ Generated reports: {report_file}, {md_file}")
    
    def run(self):
        """Run full integration."""
        print("=" * 60)
        print("ZkPatternFuzz Validation Dataset Integration")
        print("=" * 60)
        print()
        
        # Parse datasets
        print("📊 Parsing datasets...")
        print()
        
        zkbugs_targets = self.parse_zkbugs()
        self.targets.extend(zkbugs_targets)
        
        xparc_targets = self.parse_0xparc()
        self.targets.extend(xparc_targets)
        
        zk0d_targets = self.parse_zk0d()
        self.targets.extend(zk0d_targets)
        
        print()
        print(f"📈 Total targets integrated: {len(self.targets)}")
        print()
        
        # Generate outputs
        print("📝 Generating outputs...")
        self.export_targets_json()
        self.export_campaign_configs()
        self.generate_report()
        
        print()
        print("=" * 60)
        print("Integration complete!")
        print("=" * 60)
        print()
        
        # Summary
        summary = self.generate_summary()
        print("Summary:")
        print(f"  - Total targets: {summary['total']}")
        print(f"  - From zkBugs: {summary['by_source'].get('zkbugs', 0)}")
        print(f"  - From 0xPARC: {summary['by_source'].get('0xparc', 0)}")
        print(f"  - From zk0d: {summary['by_source'].get('zk0d', 0)}")
        print()
        print(f"Outputs written to: {OUTPUT_DIR}")

if __name__ == "__main__":
    integrator = DatasetIntegrator()
    integrator.run()
