// Generate deterministic witness seeds for tests/ground_truth_circuits/merkle_unconstrained.circom
// using the local Circom + snarkjs toolchain.
//
// The constructed witnesses intentionally set path_elements[i] = intermediate[i].
// In the vulnerable circuit, that makes each hasher input pair independent of
// path_indices[i], so multiple distinct selector vectors produce the same root.
//
// Usage:
//   node scripts/gen_merkle_unconstrained_seed_inputs.mjs [out.json]
//
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

function stripQuotes(value) {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    const first = trimmed[0];
    const last = trimmed[trimmed.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

function loadEnvMaster() {
  const repoRoot = path.resolve(path.dirname(process.argv[1] || "."), "..");
  const candidates = [];

  if (process.env.ZKF_ENV_MASTER_FILE) {
    candidates.push(process.env.ZKF_ENV_MASTER_FILE);
  }
  candidates.push(
    path.join(repoRoot, ".env.master"),
    path.join(repoRoot, ".env.paths"),
    path.join(repoRoot, ".env"),
  );

  for (const candidate of candidates) {
    if (!candidate || !fs.existsSync(candidate)) {
      continue;
    }
    const lines = fs.readFileSync(candidate, "utf8").split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      const noExport = line.startsWith("export ") ? line.slice(7).trim() : line;
      const eq = noExport.indexOf("=");
      if (eq <= 0) continue;
      const key = noExport.slice(0, eq).trim();
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
      if (Object.prototype.hasOwnProperty.call(process.env, key)) continue;
      process.env[key] = stripQuotes(noExport.slice(eq + 1));
    }
    break;
  }

  return repoRoot;
}

const REPO_ROOT = loadEnvMaster();

const outPath =
  process.argv[2] ??
  path.join("campaigns", "benchmark", "seed_inputs", "merkle_unconstrained_seed_inputs.json");

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "zkf-merkle-seeds-"));
const helperCircuitPath = path.join(tempDir, "poseidon2_helper.circom");
const helperBaseName = "poseidon2_helper";
const helperWasmDir = path.join(tempDir, `${helperBaseName}_js`);
const helperWasmPath = path.join(helperWasmDir, `${helperBaseName}.wasm`);
const helperWitnessPath = path.join(tempDir, `${helperBaseName}.wtns`);
const helperWitnessJsonPath = path.join(tempDir, `${helperBaseName}.witness.json`);
const helperSymPath = path.join(tempDir, `${helperBaseName}.sym`);

const helperSource = `pragma circom 2.0.0;
include "circomlib/circuits/poseidon.circom";

template Poseidon2Helper() {
    signal input left;
    signal input right;
    signal output out;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;
    out <== hasher.out;
}

component main = Poseidon2Helper();
`;

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: REPO_ROOT,
    encoding: "utf8",
    stdio: "pipe",
  });
  if (result.status === 0) {
    return;
  }
  if (result.error) {
    throw result.error;
  }
  throw new Error(
    `${command} ${args.join(" ")} failed with status ${result.status ?? "unknown"}:\n${result.stderr ?? ""}`,
  );
}

function compileHelper() {
  fs.writeFileSync(helperCircuitPath, helperSource);
  run("circom", [
    helperCircuitPath,
    "--wasm",
    "--sym",
    "-o",
    tempDir,
    "-l",
    path.join(REPO_ROOT, "node_modules"),
  ]);
}

function resolveOutputIndex() {
  const lines = fs.readFileSync(helperSymPath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const parts = line.split(",");
    if (parts.length >= 4 && parts[3].trim() === "main.out") {
      const idx = Number.parseInt(parts[0], 10);
      if (Number.isInteger(idx)) {
        return idx;
      }
    }
  }
  throw new Error("Failed to resolve main.out witness index from helper sym file");
}

function poseidon2(left, right, outIndex) {
  const inputPath = path.join(tempDir, "poseidon2_input.json");
  fs.writeFileSync(
    inputPath,
    `${JSON.stringify({ left: left.toString(), right: right.toString() }, null, 2)}\n`,
  );
  run("snarkjs", ["wc", helperWasmPath, inputPath, helperWitnessPath]);
  run("snarkjs", ["wej", helperWitnessPath, helperWitnessJsonPath]);
  const witness = JSON.parse(fs.readFileSync(helperWitnessJsonPath, "utf8"));
  const value = witness[outIndex];
  if (typeof value !== "string") {
    throw new Error(`Unexpected witness output at index ${outIndex}: ${JSON.stringify(value)}`);
  }
  return value;
}

compileHelper();
const outputIndex = resolveOutputIndex();

const leaf = "7";
const level1 = poseidon2(leaf, leaf, outputIndex);
const level2 = poseidon2(level1, level1, outputIndex);
const root = poseidon2(level2, level2, outputIndex);
const pathElements = [leaf, level1, level2];
const selectorVectors = [
  ["0", "0", "0"],
  ["1", "1", "1"],
  ["2", "3", "4"],
  ["9", "5", "7"],
];

const seeds = selectorVectors.map((pathIndices) => ({
  root,
  leaf,
  path_elements: pathElements,
  path_indices: pathIndices,
}));

fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, `${JSON.stringify(seeds, null, 2)}\n`);
fs.rmSync(tempDir, { recursive: true, force: true });
console.log(outPath);
