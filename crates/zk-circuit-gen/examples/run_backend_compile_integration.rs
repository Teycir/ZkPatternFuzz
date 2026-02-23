use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Serialize;
use zk_circuit_gen::{generate_random_circuit_dsl, render_backend_template, Backend};

const DEFAULT_OUTPUT_DIR: &str = "artifacts/circuit_gen/backend_compile_integration_sample";
const DEFAULT_SEED: u64 = 1_337;
const DEFAULT_CIRCUITS: usize = 20;

#[derive(Debug, Clone)]
struct CliArgs {
    backend: Backend,
    circuits: usize,
    seed: u64,
    output_json: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
struct BackendCompileIntegrationResult {
    case_id: String,
    circuit_name: String,
    success: bool,
    stderr_excerpt: String,
}

#[derive(Debug, Clone, Serialize)]
struct BackendCompileIntegrationReport {
    backend: Backend,
    seed: u64,
    circuits: usize,
    succeeded: usize,
    failed: usize,
    report_path: PathBuf,
    results: Vec<BackendCompileIntegrationResult>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let output_dir = args
        .output_json
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&output_dir)?;
    let compile_dir = output_dir.join("compile_tmp");
    fs::create_dir_all(&compile_dir)?;

    let mut rng = StdRng::seed_from_u64(args.seed);
    let mut results = Vec::new();
    let mut succeeded = 0usize;

    for ordinal in 0..args.circuits {
        let dsl = generate_random_circuit_dsl(&mut rng, args.backend, ordinal);
        let rendered = render_backend_template(&dsl, args.backend)?;
        let case_id = format!("{}_{}", args.backend.as_str(), ordinal);
        let (success, stderr_excerpt) = match args.backend {
            Backend::Halo2 => {
                compile_halo2_template_with_rustc_stub(&compile_dir, &case_id, &rendered)?
            }
            _ => {
                return Err(format!(
                    "backend compile integration currently supports only `halo2`, got `{}`",
                    args.backend.as_str()
                )
                .into())
            }
        };

        if success {
            succeeded += 1;
        }
        results.push(BackendCompileIntegrationResult {
            case_id,
            circuit_name: dsl.name,
            success,
            stderr_excerpt,
        });
    }

    let failed = args.circuits.saturating_sub(succeeded);
    let report = BackendCompileIntegrationReport {
        backend: args.backend,
        seed: args.seed,
        circuits: args.circuits,
        succeeded,
        failed,
        report_path: args.output_json.clone(),
        results,
    };
    fs::write(
        &args.output_json,
        serde_json::to_string_pretty(&report)? + "\n",
    )?;

    println!(
        "backend compile integration complete: backend={} circuits={} succeeded={} failed={} report={}",
        args.backend.as_str(),
        report.circuits,
        report.succeeded,
        report.failed,
        report.report_path.display()
    );

    if report.failed > 0 {
        return Err(format!(
            "compile integration failures detected: {} (report: {})",
            report.failed,
            report.report_path.display()
        )
        .into());
    }
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut backend = Backend::Halo2;
    let mut circuits = DEFAULT_CIRCUITS;
    let mut seed = DEFAULT_SEED;
    let mut output_json = PathBuf::from(DEFAULT_OUTPUT_DIR).join("latest_report.json");

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--backend" => backend = parse_backend(&next_value(&mut args, "--backend")?)?,
            "--circuits" => circuits = next_value(&mut args, "--circuits")?.parse::<usize>()?,
            "--seed" => seed = next_value(&mut args, "--seed")?.parse::<u64>()?,
            "--output-json" => {
                output_json = PathBuf::from(next_value(&mut args, "--output-json")?);
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    if circuits == 0 {
        return Err("--circuits must be greater than zero".into());
    }

    Ok(CliArgs {
        backend,
        circuits,
        seed,
        output_json,
    })
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_backend(raw: &str) -> Result<Backend, Box<dyn Error>> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "circom" => Ok(Backend::Circom),
        "noir" => Ok(Backend::Noir),
        "halo2" => Ok(Backend::Halo2),
        "cairo" => Ok(Backend::Cairo),
        _ => Err(format!("unsupported backend `{raw}`").into()),
    }
}

fn compile_halo2_template_with_rustc_stub(
    compile_dir: &Path,
    case_id: &str,
    rendered: &str,
) -> Result<(bool, String), Box<dyn Error>> {
    let wrapper_path = compile_dir.join(format!("{case_id}.rs"));
    let artifact_path = compile_dir.join(format!("lib{case_id}.rlib"));
    let wrapper = format!("{}\n\n{}", halo2_stub_prelude(), rendered);
    fs::write(&wrapper_path, wrapper)?;
    let output = Command::new("rustc")
        .arg("--edition=2021")
        .arg("--crate-type=lib")
        .arg(&wrapper_path)
        .arg("-o")
        .arg(&artifact_path)
        .output()?;
    if output.status.success() {
        return Ok((true, String::new()));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr_excerpt = stderr.lines().take(12).collect::<Vec<_>>().join("\n");
    Ok((false, stderr_excerpt))
}

fn halo2_stub_prelude() -> &'static str {
    r#"#![allow(dead_code)]
#![allow(unused_imports)]

mod halo2_proofs {
    pub mod circuit {
        pub trait Layouter<F> {}
        #[derive(Clone, Debug)]
        pub struct SimpleFloorPlanner;
        #[derive(Clone, Debug)]
        pub struct Value<F>(pub Option<F>);
    }

    pub mod poly {
        #[derive(Clone, Copy, Debug)]
        pub struct Rotation;
        impl Rotation {
            pub fn cur() -> Self {
                Self
            }
        }
    }

    pub mod plonk {
        use super::circuit::Layouter;
        use super::poly::Rotation;
        use std::marker::PhantomData;

        #[derive(Clone, Copy, Debug)]
        pub struct Advice;

        #[derive(Clone, Copy, Debug)]
        pub struct Column<T> {
            _index: usize,
            _marker: PhantomData<T>,
        }

        #[derive(Clone, Debug)]
        pub struct Error;

        #[derive(Clone, Debug)]
        pub struct Expression<F> {
            _marker: PhantomData<F>,
        }

        impl<F> std::ops::Sub for Expression<F> {
            type Output = Expression<F>;
            fn sub(self, _rhs: Self) -> Self::Output {
                Expression {
                    _marker: PhantomData,
                }
            }
        }

        pub struct VirtualCells<F> {
            _marker: PhantomData<F>,
        }

        impl<F> VirtualCells<F> {
            pub fn query_advice(
                &mut self,
                _column: Column<Advice>,
                _rotation: Rotation,
            ) -> Expression<F> {
                Expression {
                    _marker: PhantomData,
                }
            }
        }

        pub struct ConstraintSystem<F> {
            next: usize,
            _marker: PhantomData<F>,
        }

        impl<F> ConstraintSystem<F> {
            pub fn advice_column(&mut self) -> Column<Advice> {
                let index = self.next;
                self.next += 1;
                Column {
                    _index: index,
                    _marker: PhantomData,
                }
            }

            pub fn create_gate(
                &mut self,
                _name: &str,
                mut gate: impl FnMut(&mut VirtualCells<F>) -> Vec<Expression<F>>,
            ) {
                let mut cells = VirtualCells {
                    _marker: PhantomData,
                };
                let _ = gate(&mut cells);
            }
        }

        impl<F> Default for ConstraintSystem<F> {
            fn default() -> Self {
                Self {
                    next: 0,
                    _marker: PhantomData,
                }
            }
        }

        pub trait Circuit<F>: Sized {
            type Config: Clone;
            type FloorPlanner;
            fn without_witnesses(&self) -> Self;
            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config;
            fn synthesize(
                &self,
                config: Self::Config,
                layouter: impl Layouter<F>,
            ) -> Result<(), Error>;
        }
    }
}

mod halo2curves {
    pub mod bn256 {
        #[derive(Clone, Copy, Debug)]
        pub struct Fr(pub u64);
    }
}
"#
}

fn print_help() {
    println!(
        "\
run_backend_compile_integration

Generate random circuits and compile rendered templates for one backend.
Current compile integration is implemented for `halo2`.

Usage:
  cargo run -q -p zk-circuit-gen --example run_backend_compile_integration -- [options]

Options:
  --backend <name>         Backend name (default: halo2)
  --circuits <n>           Number of generated circuits (default: {DEFAULT_CIRCUITS})
  --seed <u64>             RNG seed (default: {DEFAULT_SEED})
  --output-json <path>     Output report path (default: {DEFAULT_OUTPUT_DIR}/latest_report.json)
"
    );
}
