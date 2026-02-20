use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) fn seed_corpus(&mut self) -> anyhow::Result<()> {
        if self.wall_clock_timeout_reached() {
            tracing::warn!("Skipping corpus seeding: wall-clock timeout already reached");
            return Ok(());
        }

        // Add zero case
        self.add_to_corpus(self.create_test_case_with_value(FieldElement::zero()));

        // Add one case
        self.add_to_corpus(self.create_test_case_with_value(FieldElement::one()));

        // Add interesting values from input specs
        for input in &self.config.inputs {
            for interesting in &input.interesting {
                if let Ok(fe) = FieldElement::from_hex(interesting) {
                    self.add_to_corpus(self.create_test_case_with_value(fe));
                }
            }
        }

        // Add field boundary values
        let boundary_values = vec![
            "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000", // p - 1
            "0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000", // (p-1)/2
        ];

        for hex in boundary_values {
            if let Ok(fe) = FieldElement::from_hex(hex) {
                self.add_to_corpus(self.create_test_case_with_value(fe));
            }
        }

        // Generate seeds from extracted constraints (R1CS/ACIR/PLONK) when available
        if let Some(inspector) = self.executor.constraint_inspector() {
            if let Some(config) = self.constraint_guided_config()? {
                if self.wall_clock_timeout_reached() {
                    tracing::warn!(
                        "Skipping constraint-guided seed generation: wall-clock timeout reached"
                    );
                    return Ok(());
                }
                let expected_len = self.config.inputs.len().max(1);
                let input_wire_indices = collect_input_wire_indices(inspector, expected_len);
                let mut generator = ConstraintSeedGenerator::new(config);

                let constraints = inspector.get_constraints();
                let output = if constraints.is_empty() {
                    tracing::debug!("Constraint-guided seeds skipped: no constraints available");
                    ConstraintSeedOutput::default()
                } else {
                    tracing::info!(
                        "Generating constraint-guided seeds from {} R1CS constraints...",
                        constraints.len()
                    );
                    generator.generate_from_r1cs(&constraints, &input_wire_indices, expected_len)
                };

                if !output.seeds.is_empty() {
                    tracing::info!(
                        "Constraint-guided seeds: {} solutions ({} symbolic, {} skipped, {} pruned)",
                        output.stats.solutions,
                        output.stats.symbolic_constraints,
                        output.stats.skipped_constraints,
                        output.stats.pruned_constraints
                    );

                    for inputs in output.seeds {
                        if self.wall_clock_timeout_reached() {
                            tracing::warn!(
                                "Stopping constraint-guided corpus seeding early: wall-clock timeout reached"
                            );
                            return Ok(());
                        }
                        if inputs.len() == expected_len {
                            self.add_to_corpus(TestCase {
                                inputs,
                                expected_output: None,
                                metadata: TestMetadata::default(),
                            });
                        }
                    }
                }
            } else {
                tracing::debug!("Constraint-guided seeds disabled via config");
            }
        } else {
            tracing::debug!("Constraint-guided seeds skipped: constraint inspector unavailable");
        }

        // Generate seeds from symbolic execution
        let wall_clock_deadline = self.wall_clock_deadline;
        let symbolic_test_cases = if let Some(ref mut symbolic) = self.symbolic {
            let timeout_reached = || {
                wall_clock_deadline
                    .map(|deadline| Instant::now() >= deadline)
                    .unwrap_or(false)
            };

            if timeout_reached() {
                tracing::warn!("Skipping symbolic seed generation: wall-clock timeout reached");
                return Ok(());
            }
            tracing::info!("Generating symbolic execution seeds...");

            let mut test_cases = Vec::new();

            // Generate initial seeds using symbolic solver
            let symbolic_seeds = symbolic.generate_seeds(20);
            let expected_len = self.config.inputs.len();
            for inputs in symbolic_seeds {
                if timeout_reached() {
                    tracing::warn!(
                        "Stopping symbolic seed collection early: wall-clock timeout reached"
                    );
                    break;
                }
                if inputs.len() == expected_len {
                    test_cases.push(TestCase {
                        inputs,
                        expected_output: None,
                        metadata: TestMetadata::default(),
                    });
                }
            }

            // Generate vulnerability-targeted test cases
            let vuln_patterns = vec![
                VulnerabilityPattern::OverflowBoundary,
                VulnerabilityPattern::ZeroDivision,
                VulnerabilityPattern::BitDecomposition { bits: 8 },
                VulnerabilityPattern::BitDecomposition { bits: 64 },
            ];

            for pattern in vuln_patterns {
                if timeout_reached() {
                    tracing::warn!(
                        "Stopping symbolic vulnerability seed generation early: wall-clock timeout reached"
                    );
                    break;
                }
                let targeted_tests = symbolic.generate_vulnerability_tests(pattern);
                for inputs in targeted_tests {
                    if timeout_reached() {
                        tracing::warn!(
                            "Stopping symbolic vulnerability seed collection early: wall-clock timeout reached"
                        );
                        break;
                    }
                    if inputs.len() >= expected_len {
                        let truncated: Vec<_> = inputs.into_iter().take(expected_len).collect();
                        test_cases.push(TestCase {
                            inputs: truncated,
                            expected_output: None,
                            metadata: TestMetadata::default(),
                        });
                    }
                }
            }

            let stats = symbolic.stats();
            tracing::info!(
                "Symbolic execution: {} paths explored, {} tests generated",
                stats.paths_explored,
                stats.tests_generated
            );

            test_cases
        } else {
            Vec::new()
        };

        // Add symbolic test cases to corpus
        for test_case in symbolic_test_cases {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping symbolic corpus insertion early: wall-clock timeout reached"
                );
                return Ok(());
            }
            self.add_to_corpus(test_case);
        }

        // Add random cases
        for _ in 0..10 {
            if self.wall_clock_timeout_reached() {
                tracing::warn!("Stopping random corpus seeding early: wall-clock timeout reached");
                return Ok(());
            }
            let test_case = self.generate_random_test_case();
            self.add_to_corpus(test_case);
        }

        Ok(())
    }

    pub(super) fn seed_external_inputs_from_config(&mut self) -> anyhow::Result<()> {
        let path = self
            .config
            .campaign
            .parameters
            .additional
            .get("seed_inputs_path")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());

        let Some(path) = path else {
            return Ok(());
        };

        let seeds = self.load_seed_inputs_from_path(&path)?;
        if seeds.is_empty() {
            tracing::warn!("External seed inputs were empty: {}", path);
            return Ok(());
        }

        let added = self.seed_corpus_from_inputs(&seeds);
        tracing::info!("Seeded corpus with {} external inputs from {}", added, path);
        Ok(())
    }

    pub(super) fn load_seed_inputs_from_path(
        &self,
        path: &str,
    ) -> anyhow::Result<Vec<Vec<FieldElement>>> {
        let raw = std::fs::read_to_string(path)?;
        let json: serde_json::Value = serde_json::from_str(&raw)?;

        let mut seeds = Vec::new();
        match json {
            serde_json::Value::Array(entries) => {
                for entry in entries {
                    if let Some(seed) = self.build_seed_from_json(&entry) {
                        seeds.push(seed);
                    }
                }
            }
            serde_json::Value::Object(_) => {
                if let Some(seed) = self.build_seed_from_json(&json) {
                    seeds.push(seed);
                }
            }
            _ => {
                anyhow::bail!("seed_inputs_path must be a JSON object or array");
            }
        }

        Ok(seeds)
    }

    pub(super) fn build_seed_from_json(
        &self,
        entry: &serde_json::Value,
    ) -> Option<Vec<FieldElement>> {
        let map = entry.as_object()?;
        let mut inputs = Vec::with_capacity(self.config.inputs.len());
        let mut missing = Vec::new();

        for spec in &self.config.inputs {
            let name = spec.name.as_str();
            let value = if let Some(v) = map.get(name) {
                Self::parse_field_value(v)
            } else if let Some((base, idx)) = Self::split_indexed_name(name) {
                map.get(base)
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.get(idx))
                    .and_then(Self::parse_field_value)
            } else {
                None
            };

            match value {
                Some(v) => inputs.push(v),
                None => missing.push(name.to_string()),
            }
        }

        if !missing.is_empty() {
            tracing::warn!(
                "Skipping external seed: missing {} inputs (e.g. {})",
                missing.len(),
                match missing.first().cloned() {
                    Some(name) => name,
                    None => "<unknown>".to_string(),
                }
            );
            return None;
        }

        Some(inputs)
    }

    pub(super) fn split_indexed_name(name: &str) -> Option<(&str, usize)> {
        let (base, idx_str) = name.rsplit_once('_')?;
        if idx_str.chars().all(|c| c.is_ascii_digit()) {
            let idx = match idx_str.parse::<usize>() {
                Ok(idx) => idx,
                Err(err) => {
                    tracing::warn!("Invalid indexed input suffix '{}': {}", idx_str, err);
                    return None;
                }
            };
            return Some((base, idx));
        }
        None
    }

    pub(super) fn parse_field_value(value: &serde_json::Value) -> Option<FieldElement> {
        match value {
            serde_json::Value::String(s) => Self::parse_field_string(s),
            serde_json::Value::Number(n) => Self::parse_field_string(&n.to_string()),
            serde_json::Value::Bool(b) => {
                if *b {
                    Self::parse_field_string("1")
                } else {
                    Self::parse_field_string("0")
                }
            }
            _ => None,
        }
    }

    pub(super) fn parse_field_string(raw: &str) -> Option<FieldElement> {
        let trimmed = raw.trim();
        if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
            return match FieldElement::from_hex(trimmed) {
                Ok(value) => Some(value),
                Err(err) => {
                    tracing::debug!("Invalid corpus hex field literal '{}': {}", trimmed, err);
                    None
                }
            };
        }

        let value = num_bigint::BigUint::parse_bytes(trimmed.as_bytes(), 10)?;
        let bytes = value.to_bytes_be();
        if bytes.len() > 32 {
            return None;
        }
        let mut buf = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        buf[start..start + bytes.len()].copy_from_slice(&bytes);
        Some(FieldElement(buf))
    }

    /// Load corpus from a previous run for resumption (Phase 0: Milestone 0.2)
    ///
    /// This enables long-running campaigns to be interrupted and resumed without
    /// losing accumulated coverage. The corpus is loaded from disk and merged
    /// with the current (empty) corpus.
    ///
    /// # Arguments
    ///
    /// * `corpus_dir` - Path to the corpus directory from a previous run
    ///
    /// # Returns
    ///
    /// Number of test cases loaded from the corpus directory
    pub(super) fn load_resume_corpus(
        &mut self,
        corpus_dir: &std::path::Path,
    ) -> anyhow::Result<usize> {
        if !corpus_dir.exists() {
            tracing::warn!("Resume corpus directory does not exist: {:?}", corpus_dir);
            return Ok(0);
        }

        tracing::info!("Loading resume corpus from {:?}", corpus_dir);

        // Load corpus entries from disk
        let entries = corpus_storage::load_corpus_from_dir(corpus_dir)?;

        if entries.is_empty() {
            tracing::info!("Resume corpus directory is empty");
            return Ok(0);
        }

        // Add each entry to the current corpus
        let mut added = 0;
        for entry in entries {
            // Add to corpus (deduplication handled internally)
            self.add_to_corpus(entry.test_case);
            added += 1;
        }

        tracing::info!(
            "Resumed from corpus: {} test cases loaded from {:?}",
            added,
            corpus_dir
        );

        Ok(added)
    }

    /// Check for and load resume corpus from config if --resume was specified
    pub(super) fn maybe_load_resume_corpus(&mut self) -> anyhow::Result<usize> {
        let additional = &self.config.campaign.parameters.additional;

        // Check if resume_corpus_dir was set by CLI
        let resume_dir = additional
            .get("resume_corpus_dir")
            .and_then(|v| v.as_str())
            .map(std::path::PathBuf::from);

        match resume_dir {
            Some(dir) => self.load_resume_corpus(&dir),
            None => Ok(0),
        }
    }

    pub(super) fn add_to_corpus(&self, test_case: TestCase) {
        self.core.add_to_corpus(self.executor.as_ref(), test_case);
    }

    pub(super) fn create_test_case_with_value(&self, value: FieldElement) -> TestCase {
        self.core.create_test_case_with_value(value)
    }

    pub(super) fn generate_random_test_case(&mut self) -> TestCase {
        self.core.generate_random_test_case()
    }

    pub(super) fn generate_test_case(&mut self) -> TestCase {
        self.core.generate_test_case()
    }

    /// Execute test case and update coverage
    ///
    /// Note: There's a potential race condition between checking is_new and
    /// adding to corpus. However, the corpus.add() method has its own
    /// duplicate detection which prevents actual duplicates. The worst case
    /// is that we might miss adding a test case that another thread added
    /// first with the same coverage, which is acceptable behavior.
    /// Execute test case, update coverage, and learn patterns (mutable version)
    pub(super) fn execute_and_learn(&mut self, test_case: &TestCase) -> ExecutionResult {
        self.core
            .execute_and_learn(self.executor.as_ref(), test_case)
    }

    /// Export corpus to disk for persistence
    pub fn export_corpus(&self, output_dir: &std::path::Path) -> anyhow::Result<usize> {
        self.core.export_corpus(output_dir)
    }

    /// Seed corpus with externally supplied inputs (for phased scheduling).
    /// Returns the number of inputs added.
    pub fn seed_corpus_from_inputs(&mut self, inputs: &[Vec<FieldElement>]) -> usize {
        if inputs.is_empty() {
            return 0;
        }

        let expected = self.config.inputs.len();
        let mut added = 0usize;

        for input in inputs {
            if expected > 0 && input.len() != expected {
                continue;
            }
            let test_case = TestCase {
                inputs: input.clone(),
                expected_output: None,
                metadata: TestMetadata::default(),
            };
            self.add_to_corpus(test_case);
            added += 1;
        }

        added
    }

    /// Collect inputs from the current corpus (for phased scheduling).
    pub fn collect_corpus_inputs(&self, limit: usize) -> Vec<Vec<FieldElement>> {
        if limit == 0 {
            return Vec::new();
        }

        let mut collected = Vec::new();
        let mut entries = self.core.corpus().interesting_entries();
        if entries.is_empty() {
            entries = self.core.corpus().all_entries();
        }

        for entry in entries {
            if collected.len() >= limit {
                break;
            }
            collected.push(entry.test_case.inputs);
        }

        collected
    }
}
