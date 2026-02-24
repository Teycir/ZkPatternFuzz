use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(about = "Generate Circom seed inputs (configurable)")]
struct Args {
    /// Preset configuration (default: tornado)
    #[arg(long, default_value = "tornado")]
    preset: String,

    /// Path to circuit file
    #[arg(long)]
    circuit: Option<String>,

    /// Source root to copy (preserves relative includes)
    #[arg(long)]
    source_root: Option<String>,

    /// Output seed JSON path
    #[arg(long)]
    output: Option<String>,

    /// Build root (workspace temp staging)
    #[arg(long)]
    build_root: Option<String>,

    /// Merkle tree levels for default input
    #[arg(long, default_value_t = 0)]
    levels: usize,

    /// Ensure Circom 2 pragma is present
    #[arg(long, default_value_t = false)]
    ensure_pragma: bool,

    /// Comma-separated public inputs list
    #[arg(long)]
    public_inputs: Option<String>,

    /// Replacement spec: from=>to (repeatable)
    #[arg(long)]
    replace: Vec<String>,

    /// Comment out lines containing this substring (repeatable)
    #[arg(long)]
    comment_out: Vec<String>,

    /// Extract spec: signal|alt=>input (repeatable)
    #[arg(long)]
    extract: Vec<String>,

    /// Extra file to copy alongside circuit (repeatable)
    #[arg(long)]
    extra_file: Vec<String>,

    /// Include dir for circom (-l) (repeatable)
    #[arg(long)]
    include_dir: Vec<String>,

    /// Symlink entry name=path (repeatable)
    #[arg(long)]
    symlink: Vec<String>,

    /// Base input JSON file
    #[arg(long)]
    input_json: Option<String>,

    /// Override input: key=value (repeatable; value may be JSON)
    #[arg(long)]
    input: Vec<String>,
}

#[derive(Default)]
struct Defaults {
    circuit: Option<String>,
    output: Option<String>,
    build_root: Option<String>,
    levels: usize,
    ensure_pragma: bool,
    replace: Vec<String>,
    comment_out: Vec<String>,
    public_inputs: Vec<String>,
    extract: Vec<String>,
    extra_files: Vec<String>,
    include_dirs: Vec<String>,
    symlinks: Vec<String>,
    input_json: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let defaults = preset_defaults(&args.preset)?;

    let circuit = args
        .circuit
        .or_else(|| defaults.circuit.clone())
        .ok_or_else(|| anyhow::anyhow!("Missing --circuit (or use --preset tornado)"))?;
    let output = args
        .output
        .or_else(|| defaults.output.clone())
        .ok_or_else(|| anyhow::anyhow!("Missing --output (or preset default output)"))?;
    let build_root = args
        .build_root
        .or_else(|| defaults.build_root.clone())
        .ok_or_else(|| anyhow::anyhow!("Missing --build-root (or preset default build root)"))?;

    let levels = if args.levels > 0 {
        args.levels
    } else {
        defaults.levels
    };

    let ensure_pragma = args.ensure_pragma || defaults.ensure_pragma;
    let replace = merge_vec(defaults.replace, args.replace);
    let comment_out = merge_vec(defaults.comment_out, args.comment_out);
    let extract_specs = {
        let merged = merge_vec(defaults.extract, args.extract);
        if merged.is_empty() {
            bail!("No --extract signals specified");
        }
        merged
    };
    let extra_files = merge_vec(defaults.extra_files, args.extra_file);
    let include_dirs = merge_vec(defaults.include_dirs, args.include_dir);
    let symlinks = merge_vec(defaults.symlinks, args.symlink);

    let public_inputs = if let Some(list) = args.public_inputs {
        list.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    } else {
        defaults.public_inputs
    };

    let input_json = args.input_json.or(defaults.input_json);

    let build_root = PathBuf::from(build_root);
    let work_circuits = build_root.join("circuits");
    let work_node_modules = build_root.join("node_modules");
    let build_dir = build_root.join("build");
    fs::create_dir_all(&work_circuits)?;
    fs::create_dir_all(&work_node_modules)?;
    fs::create_dir_all(&build_dir)?;

    let circuit_path = PathBuf::from(&circuit);
    let source_root = args.source_root.map(PathBuf::from);
    let local_circuit = if let Some(root) = &source_root {
        copy_dir(root, &work_circuits)?;
        let rel = circuit_path
            .strip_prefix(root)
            .with_context(|| "circuit path must be under source_root")?;
        work_circuits.join(rel)
    } else {
        let circuit_name = circuit_path.file_name().ok_or_else(|| {
            anyhow::anyhow!(
                "Circuit path '{}' must include a file name",
                circuit_path.display()
            )
        })?;
        let dest = work_circuits.join(circuit_name);
        fs::copy(&circuit_path, &dest)
            .with_context(|| format!("Failed to copy circuit from {}", circuit_path.display()))?;
        for extra in &extra_files {
            let extra_path = resolve_extra_path(extra, &circuit_path, None)?;
            let extra_name = extra_path.file_name().ok_or_else(|| {
                anyhow::anyhow!(
                    "Extra file path '{}' must include a file name",
                    extra_path.display()
                )
            })?;
            let dest_extra = work_circuits.join(extra_name);
            fs::copy(&extra_path, &dest_extra)?;
        }
        dest
    };

    for spec in &symlinks {
        if let Some((name, target)) = spec.split_once('=') {
            let link_path = work_node_modules.join(name);
            let target_path = PathBuf::from(target);
            if fs::symlink_metadata(&link_path).is_ok() {
                let remove_file_res = fs::remove_file(&link_path);
                let remove_dir_res = fs::remove_dir_all(&link_path);
                if remove_file_res.is_err() && remove_dir_res.is_err() {
                    let file_err = remove_file_res.expect_err("remove_file_res.is_err() checked");
                    let dir_err = remove_dir_res.expect_err("remove_dir_res.is_err() checked");
                    anyhow::bail!(
                        "Failed to remove existing symlink target '{}': remove_file={}, remove_dir_all={}",
                        link_path.display(),
                        file_err,
                        dir_err
                    );
                }
            }
            create_symlink(&target_path, &link_path)?;
        }
    }

    let mut files_to_edit = vec![local_circuit.clone()];
    for extra in &extra_files {
        let extra_path = resolve_extra_path(extra, &circuit_path, source_root.as_deref())?;
        let local_path = if let Some(root) = &source_root {
            let rel = extra_path.strip_prefix(root).with_context(|| {
                format!(
                    "Extra path '{}' is not under source root '{}'",
                    extra_path.display(),
                    root.display()
                )
            })?;
            work_circuits.join(rel)
        } else {
            let extra_name = extra_path.file_name().ok_or_else(|| {
                anyhow::anyhow!(
                    "Extra path '{}' must include a file name",
                    extra_path.display()
                )
            })?;
            work_circuits.join(extra_name)
        };
        files_to_edit.push(local_path);
    }

    for file_path in files_to_edit {
        apply_edits(
            &file_path,
            ensure_pragma,
            &replace,
            &comment_out,
            &public_inputs,
        )?;
    }

    let mut circom_args = vec![
        local_circuit.to_string_lossy().to_string(),
        "--r1cs".to_string(),
        "--wasm".to_string(),
        "--sym".to_string(),
        "--json".to_string(),
        "-o".to_string(),
        build_dir.to_string_lossy().to_string(),
    ];
    for inc in include_dirs {
        circom_args.push("-l".to_string());
        circom_args.push(inc);
    }
    run_command("circom", &circom_args)?;

    let basename = local_circuit
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Local circuit path '{}' has no valid UTF-8 stem",
                local_circuit.display()
            )
        })?;
    let wasm_path = build_dir
        .join(format!("{}_js", basename))
        .join(format!("{}.wasm", basename));
    let sym_path = build_dir.join(format!("{}.sym", basename));

    let temp_dir = tempfile::Builder::new()
        .prefix("zkfuzzer_seed_")
        .tempdir()?;
    let input_path = temp_dir.path().join("input.json");
    let witness_path = temp_dir.path().join("witness.wtns");
    let witness_json_path = temp_dir.path().join("witness.json");

    let mut input = if let Some(path) = input_json {
        load_input_json(&path)?
    } else if levels > 0 {
        build_default_input(levels)
    } else {
        bail!("Missing --input-json (or supply --levels for default input)");
    };

    apply_input_overrides(&mut input, &args.input)?;
    fs::write(&input_path, serde_json::to_string(&input)?)?;

    run_command(
        "npx",
        &[
            "snarkjs".to_string(),
            "wtns".to_string(),
            "calculate".to_string(),
            wasm_path.to_string_lossy().to_string(),
            input_path.to_string_lossy().to_string(),
            witness_path.to_string_lossy().to_string(),
        ],
    )?;

    run_command(
        "npx",
        &[
            "snarkjs".to_string(),
            "wtns".to_string(),
            "export".to_string(),
            "json".to_string(),
            witness_path.to_string_lossy().to_string(),
            witness_json_path.to_string_lossy().to_string(),
        ],
    )?;

    let witness: Vec<String> = serde_json::from_str(&fs::read_to_string(&witness_json_path)?)?;
    let sym_map = read_sym_map(&sym_path)?;

    let mut final_input = input;
    for spec in extract_specs {
        let (signal, input_name) = parse_extract_spec(&spec)?;
        let idx = resolve_signal_index(&sym_map, &signal)
            .ok_or_else(|| anyhow::anyhow!("Failed to locate signal '{}'", signal))?;
        let value = witness
            .get(idx)
            .ok_or_else(|| anyhow::anyhow!("Witness index {} out of bounds", idx))?
            .clone();
        final_input.insert(input_name, Value::String(value));
    }

    if let Some(parent) = Path::new(&output).parent() {
        fs::create_dir_all(parent)?;
    }
    let out = Value::Array(vec![Value::Object(final_input)]);
    fs::write(&output, serde_json::to_string_pretty(&out)?)?;

    println!("Seed inputs written to {}", output);
    Ok(())
}

fn preset_defaults(preset: &str) -> Result<Defaults> {
    let mut defaults = Defaults::default();
    if preset == "tornado" {
        let default_build_root = std::env::temp_dir()
            .join("zkfuzzer_tornado_seed_rs")
            .to_string_lossy()
            .to_string();
        let zk0d_base = std::env::var("ZK0D_BASE")
            .context("ZK0D_BASE is required when using --preset tornado")?;
        defaults.circuit = Some(
            Path::new(&zk0d_base)
                .join("cat3_privacy/tornado-core/circuits/withdraw.circom")
                .to_string_lossy()
                .to_string(),
        );
        defaults.output = Some("campaigns/zk0d/tornado_withdraw_seed_inputs.json".to_string());
        defaults.build_root = Some(default_build_root);
        defaults.levels = 20;
        defaults.ensure_pragma = true;
        defaults
            .replace
            .push("signal private input=>signal input".to_string());
        defaults
            .replace
            .push("MiMCSponge(2, 1)=>MiMCSponge(2, 220, 1)".to_string());
        defaults
            .replace
            .push("s * (1 - s) === 0=>s * (1 - s) === 0;".to_string());
        defaults
            .comment_out
            .push("hasher.nullifierHash === nullifierHash".to_string());
        defaults
            .comment_out
            .push("root === hashers[levels - 1].hash".to_string());
        defaults.public_inputs = vec![
            "root".to_string(),
            "nullifierHash".to_string(),
            "recipient".to_string(),
            "relayer".to_string(),
            "fee".to_string(),
            "refund".to_string(),
        ];
        defaults.extract = vec![
            "main.tree.hashers[19].hash|main.tree.hashers[19].hash[0]=>root".to_string(),
            "main.hasher.nullifierHash|main.hasher.nullifierHash[0]=>nullifierHash".to_string(),
        ];
        defaults.extra_files.push("merkleTree.circom".to_string());
        defaults
            .symlinks
            .push("circomlib=third_party/circomlib".to_string());
    }
    Ok(defaults)
}

fn merge_vec<T: Clone>(mut base: Vec<T>, mut extra: Vec<T>) -> Vec<T> {
    base.append(&mut extra);
    base
}

fn resolve_extra_path(
    extra: &str,
    circuit_path: &Path,
    source_root: Option<&Path>,
) -> Result<PathBuf> {
    let extra_path = PathBuf::from(extra);
    let path = if extra_path.is_absolute() {
        extra_path
    } else {
        let parent = circuit_path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "Circuit path '{}' has no parent directory",
                circuit_path.display()
            )
        })?;
        parent.join(extra)
    };
    if let Some(root) = source_root {
        path.strip_prefix(root)
            .context("extra file must be under source_root")?;
    }
    Ok(path)
}

fn copy_dir(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)?;
    run_command(
        "cp",
        &[
            "-R".to_string(),
            format!("{}/.", src.display()),
            dest.to_string_lossy().to_string(),
        ],
    )
}

fn apply_edits(
    path: &Path,
    ensure_pragma: bool,
    replace: &[String],
    comment_out: &[String],
    public_inputs: &[String],
) -> Result<()> {
    let mut source =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    if ensure_pragma && !source.contains("pragma circom") {
        source = format!("pragma circom 2.0.0;\n\n{}", source);
    }
    for spec in replace {
        if let Some((from, to)) = spec.split_once("=>") {
            source = source.replace(from, to);
        }
    }
    if !public_inputs.is_empty() && !source.contains("component main {public") {
        let list = public_inputs.join(", ");
        if let Some(pos) = source.find("component main") {
            let remainder = &source[pos..];
            if let Some(end) = remainder.find(';') {
                let line = &remainder[..=end];
                if let Some((_lhs, rhs)) = line.split_once('=') {
                    let rhs_clean = rhs.trim().trim_end_matches(';');
                    let replacement =
                        format!("component main {{public [{}]}} = {};", list, rhs_clean);
                    source = source.replacen(line, &replacement, 1);
                }
            }
        }
    }
    if !comment_out.is_empty() {
        let mut lines = Vec::new();
        for line in source.lines() {
            let mut updated = line.to_string();
            if !line.trim_start().starts_with("//") {
                for pattern in comment_out {
                    if !pattern.is_empty() && line.contains(pattern) {
                        updated = format!("// {}", line);
                        break;
                    }
                }
            }
            lines.push(updated);
        }
        source = lines.join("\n");
    }
    fs::write(path, source).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn load_input_json(path: &str) -> Result<Map<String, Value>> {
    let raw = fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&raw)?;
    let obj = match value {
        Value::Array(mut arr) => arr
            .drain(..)
            .next()
            .and_then(|v| v.as_object().cloned())
            .ok_or_else(|| anyhow::anyhow!("input json array is empty"))?,
        Value::Object(map) => map,
        _ => bail!("input json must be object or array"),
    };
    let normalized = normalize_value(Value::Object(obj));
    let object = normalized
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("normalized input is not a JSON object"))?;
    Ok(object)
}

fn normalize_value(value: Value) -> Value {
    match value {
        Value::Number(n) => Value::String(n.to_string()),
        Value::Bool(b) => Value::String(if b { "1".to_string() } else { "0".to_string() }),
        Value::Null => Value::String("0".to_string()),
        Value::Array(arr) => Value::Array(arr.into_iter().map(normalize_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, normalize_value(v)))
                .collect(),
        ),
        Value::String(s) => Value::String(s),
    }
}

fn apply_input_overrides(input: &mut Map<String, Value>, overrides: &[String]) -> Result<()> {
    for entry in overrides {
        if let Some((key, raw)) = entry.split_once('=') {
            let parsed: Value = serde_json::from_str(raw).with_context(|| {
                format!(
                    "Invalid override value for '{}': '{}' is not valid JSON",
                    key, raw
                )
            })?;
            input.insert(key.to_string(), normalize_value(parsed));
        } else {
            bail!("Invalid --input override '{}': expected key=value", entry);
        }
    }
    Ok(())
}

fn build_default_input(levels: usize) -> Map<String, Value> {
    let mut input = Map::new();
    input.insert("root".to_string(), Value::String("0".to_string()));
    input.insert("nullifierHash".to_string(), Value::String("0".to_string()));
    input.insert("recipient".to_string(), Value::String("0".to_string()));
    input.insert("relayer".to_string(), Value::String("0".to_string()));
    input.insert("fee".to_string(), Value::String("0".to_string()));
    input.insert("refund".to_string(), Value::String("0".to_string()));
    input.insert("nullifier".to_string(), Value::String("1".to_string()));
    input.insert("secret".to_string(), Value::String("2".to_string()));
    input.insert(
        "pathElements".to_string(),
        Value::Array(vec![Value::String("0".to_string()); levels]),
    );
    input.insert(
        "pathIndices".to_string(),
        Value::Array(vec![Value::String("0".to_string()); levels]),
    );
    input
}

fn read_sym_map(sym_path: &Path) -> Result<HashMap<String, usize>> {
    let contents = fs::read_to_string(sym_path)
        .with_context(|| format!("Failed to read {}", sym_path.display()))?;
    let mut map = HashMap::new();
    for (line_number, line) in contents.lines().enumerate() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() < 2 {
            bail!(
                "Malformed .sym line {} in {} (expected at least 2 columns): {}",
                line_number + 1,
                sym_path.display(),
                line
            );
        }

        let index = match parts.get(1) {
            Some(raw) => raw.trim().parse::<isize>().with_context(|| {
                format!(
                    "Invalid witness index '{}' at .sym line {} in {}",
                    raw,
                    line_number + 1,
                    sym_path.display()
                )
            })?,
            None => {
                bail!(
                    "Missing witness index at .sym line {} in {}",
                    line_number + 1,
                    sym_path.display()
                );
            }
        };
        if index < 0 {
            bail!(
                "Negative witness index {} at .sym line {} in {}",
                index,
                line_number + 1,
                sym_path.display()
            );
        }
        let chosen = index as usize;

        let name = parts.last().map(|s| s.trim()).filter(|s| !s.is_empty());
        let signal_name = name.ok_or_else(|| {
            anyhow::anyhow!(
                "Missing signal name at .sym line {} in {}",
                line_number + 1,
                sym_path.display()
            )
        })?;
        map.insert(signal_name.to_string(), chosen);
    }
    Ok(map)
}

fn parse_extract_spec(spec: &str) -> Result<(String, String)> {
    if let Some((signal, input)) = spec.split_once("=>") {
        Ok((signal.to_string(), input.to_string()))
    } else {
        bail!(
            "Invalid --extract spec '{}': expected 'signal|alt=>input_name'",
            spec
        )
    }
}

fn resolve_signal_index(map: &HashMap<String, usize>, spec: &str) -> Option<usize> {
    let candidates: Vec<&str> = spec
        .split('|')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    for candidate in candidates {
        if let Some(idx) = map.get(candidate) {
            return Some(*idx);
        }
        let with_main = format!("main.{}", candidate);
        if let Some(idx) = map.get(&with_main) {
            return Some(*idx);
        }
        let suffix_matches: Vec<_> = map
            .keys()
            .filter(|k| {
                *k == candidate || k.ends_with(&format!(".{}", candidate)) || k.ends_with(candidate)
            })
            .collect();
        if suffix_matches.len() == 1 {
            return map.get(suffix_matches[0]).copied();
        }
    }
    None
}

fn run_command(cmd: &str, args: &[String]) -> Result<()> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("Failed to run {}", cmd))?;
    if !output.status.success() {
        bail!(
            "{} failed: {}",
            cmd,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link).with_context(|| {
        format!(
            "Failed to symlink {} -> {}",
            link.display(),
            target.display()
        )
    })
}

#[cfg(not(unix))]
fn create_symlink(target: &Path, link: &Path) -> Result<()> {
    fs::create_dir_all(link)?;
    run_command(
        "cp",
        &[
            "-R".to_string(),
            target.to_string_lossy().to_string(),
            link.to_string_lossy().to_string(),
        ],
    )
}
