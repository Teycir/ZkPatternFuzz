#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ARRAY_FLAGS = new Set([
  'replace',
  'comment_out',
  'extract',
  'extra_file',
  'include_dir',
  'symlink',
  'input',
]);

function parseArgs(argv) {
  const args = {
    replace: [],
    comment_out: [],
    extract: [],
    extra_file: [],
    include_dir: [],
    symlink: [],
    input: [],
  };
  for (let i = 2; i < argv.length; i += 1) {
    const key = argv[i];
    if (!key.startsWith('--')) continue;
    const name = key.slice(2);
    const next = argv[i + 1];
    const hasValue = next && !next.startsWith('--');
    const value = hasValue ? next : true;
    if (ARRAY_FLAGS.has(name)) {
      args[name].push(value);
    } else if (args[name] !== undefined) {
      if (Array.isArray(args[name])) {
        args[name].push(value);
      } else {
        args[name] = [args[name], value];
      }
    } else {
      args[name] = value;
    }
    if (hasValue) i += 1;
  }
  return args;
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function safeSymlink(target, linkPath) {
  try {
    if (fs.existsSync(linkPath)) return;
    fs.symlinkSync(target, linkPath, 'dir');
  } catch (err) {
    throw new Error(`Failed to symlink ${linkPath} -> ${target}: ${err.message}`);
  }
}

function copyFile(src, dest) {
  ensureDir(path.dirname(dest));
  fs.copyFileSync(src, dest);
}

function copyDir(src, dest) {
  ensureDir(dest);
  execFileSync('cp', ['-R', `${src}/.`, dest]);
}

function readSymMap(symPath) {
  const map = new Map();
  const lines = fs.readFileSync(symPath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    const parts = line.split(',');
    if (parts.length < 2) continue;
    const rawPrimary = Number(parts[1] ? parts[1].trim() : parts[0].trim());
    const fallback = Number(parts[0].trim());
    const idx = Number.isNaN(rawPrimary) || rawPrimary < 0 ? fallback : rawPrimary;
    const name = parts[parts.length - 1].trim();
    if (!Number.isNaN(idx) && name) {
      map.set(name, idx);
    }
  }
  return map;
}

function resolveSignalIndex(symMap, signalSpec) {
  const candidates = signalSpec.split('|').map((s) => s.trim()).filter(Boolean);
  for (const candidate of candidates) {
    if (symMap.has(candidate)) return symMap.get(candidate);
    if (!candidate.startsWith('main.') && symMap.has(`main.${candidate}`)) {
      return symMap.get(`main.${candidate}`);
    }
    const suffixMatches = [...symMap.keys()].filter(
      (k) => k === candidate || k.endsWith(`.${candidate}`) || k.endsWith(candidate)
    );
    if (suffixMatches.length === 1) return symMap.get(suffixMatches[0]);
  }
  return undefined;
}

function parseReplace(spec) {
  const parts = spec.split('=>');
  if (parts.length < 2) {
    throw new Error(`Invalid replace spec '${spec}', expected 'from=>to'`);
  }
  const from = parts.shift();
  const to = parts.join('=>');
  return [from, to];
}

function commentOutLines(source, patterns) {
  if (!patterns.length) return source;
  const lines = source.split(/\r?\n/);
  const updated = lines.map((line) => {
    if (line.trimStart().startsWith('//')) return line;
    for (const pattern of patterns) {
      if (pattern && line.includes(pattern)) {
        return `// ${line}`;
      }
    }
    return line;
  });
  return updated.join('\n');
}

function applyPublicInputs(source, publicInputs) {
  if (!publicInputs || !publicInputs.length) return source;
  if (source.includes('component main {public')) return source;
  const list = publicInputs.join(', ');
  return source.replace(
    /component\s+main\s*=\s*([^;]+);/,
    `component main {public [${list}]} = $1;`
  );
}

function ensurePragma(source) {
  if (source.includes('pragma circom')) return source;
  return `pragma circom 2.0.0;\n\n${source}`;
}

function applyEdits(filePath, edits) {
  let source = fs.readFileSync(filePath, 'utf8');
  if (edits.ensurePragma) {
    source = ensurePragma(source);
  }
  if (edits.replace.length) {
    for (const spec of edits.replace) {
      if (!spec) continue;
      const [from, to] = parseReplace(spec);
      source = source.split(from).join(to);
    }
  }
  if (edits.publicInputs.length) {
    source = applyPublicInputs(source, edits.publicInputs);
  }
  if (edits.commentOut.length) {
    source = commentOutLines(source, edits.commentOut);
  }
  fs.writeFileSync(filePath, source);
}

function normalizeInputValue(value) {
  if (Array.isArray(value)) {
    return value.map(normalizeInputValue);
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, val] of Object.entries(value)) {
      out[key] = normalizeInputValue(val);
    }
    return out;
  }
  if (typeof value === 'number' || typeof value === 'bigint') {
    return value.toString();
  }
  if (value === null || value === undefined) return '0';
  return String(value);
}

function parseInputOverrides(pairs) {
  const overrides = {};
  for (const pair of pairs) {
    if (pair === true) continue;
    const [key, ...rest] = pair.split('=');
    if (!key || rest.length === 0) continue;
    const raw = rest.join('=');
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (_) {
      parsed = raw;
    }
    overrides[key] = normalizeInputValue(parsed);
  }
  return overrides;
}

function buildDefaultInput(levels) {
  return {
    root: '0',
    nullifierHash: '0',
    recipient: '0',
    relayer: '0',
    fee: '0',
    refund: '0',
    nullifier: '1',
    secret: '2',
    pathElements: Array.from({ length: levels }, () => '0'),
    pathIndices: Array.from({ length: levels }, () => '0'),
  };
}

function parseExtractSpec(spec) {
  if (!spec) return null;
  const parts = spec.split('=>');
  if (parts.length === 1) {
    return { signal: parts[0], input: parts[0] };
  }
  const signal = parts[0];
  const input = parts.slice(1).join('=>');
  return { signal, input };
}

function main() {
  const args = parseArgs(process.argv);
  const repoRoot = path.resolve(__dirname, '..');
  const preset = args.preset || 'tornado';

  const defaults = {
    circuit: null,
    output: null,
    buildRoot: '/tmp/zkfuzzer_seed',
    levels: 0,
    ensurePragma: false,
    replace: [],
    commentOut: [],
    publicInputs: [],
    extract: [],
    extraFiles: [],
    includeDirs: [],
    symlinks: [],
    inputJson: null,
  };

  if (preset === 'tornado') {
    const zk0dBase = process.env.ZK0D_BASE || '/media/elements/Repos/zk0d';
    defaults.circuit = path.join(
      zk0dBase,
      'cat3_privacy',
      'tornado-core',
      'circuits',
      'withdraw.circom'
    );
    defaults.output = path.join(repoRoot, 'campaigns', 'zk0d', 'tornado_withdraw_seed_inputs.json');
    defaults.buildRoot = '/tmp/zkfuzzer_tornado_seed';
    defaults.levels = 20;
    defaults.ensurePragma = true;
    defaults.replace.push('signal private input=>signal input');
    defaults.replace.push('MiMCSponge(2, 1)=>MiMCSponge(2, 220, 1)');
    defaults.replace.push('s * (1 - s) === 0=>s * (1 - s) === 0;');
    defaults.commentOut.push('hasher.nullifierHash === nullifierHash');
    defaults.commentOut.push('root === hashers[levels - 1].hash');
    defaults.publicInputs = ['root', 'nullifierHash', 'recipient', 'relayer', 'fee', 'refund'];
    defaults.extract = [
      'main.tree.hashers[19].hash|main.tree.hashers[19].hash[0]=>root',
      'main.hasher.nullifierHash|main.hasher.nullifierHash[0]=>nullifierHash',
    ];
    defaults.extraFiles = ['merkleTree.circom'];
    defaults.symlinks = [`circomlib=${path.join(repoRoot, 'third_party', 'circomlib')}`];
  }

  const circuitPath = args.circuit || defaults.circuit;
  if (!circuitPath) {
    throw new Error('Missing --circuit (or use --preset tornado).');
  }

  const outputPath = args.output || defaults.output || path.join(process.cwd(), 'seed_inputs.json');
  const buildRoot = args.build_dir || defaults.buildRoot || '/tmp/zkfuzzer_seed';
  const levels = Number(args.levels || defaults.levels || 0);
  const ensurePragmaFlag = args.ensure_pragma === 'true' || args.ensure_pragma === true || defaults.ensurePragma;

  const replaceSpecs = [...defaults.replace, ...(args.replace || [])].filter(Boolean);
  const commentOut = [...defaults.commentOut, ...(args.comment_out || [])].filter(Boolean);
  const publicInputs = (args.public_inputs ? args.public_inputs.split(',') : defaults.publicInputs)
    .map((s) => s.trim())
    .filter(Boolean);
  const extractSpecs = [...defaults.extract, ...(args.extract || [])].filter(Boolean);
  const extraFiles = [...defaults.extraFiles, ...(args.extra_file || [])].filter(Boolean);
  const includeDirs = [...defaults.includeDirs, ...(args.include_dir || [])].filter(Boolean);
  const symlinks = [...defaults.symlinks, ...(args.symlink || [])].filter(Boolean);

  const sourceRoot = args.source_root || null;

  const workCircuits = path.join(buildRoot, 'circuits');
  const workNodeModules = path.join(buildRoot, 'node_modules');
  const buildDir = path.join(buildRoot, 'build');

  ensureDir(workCircuits);
  ensureDir(workNodeModules);
  ensureDir(buildDir);

  let localCircuit = '';

  if (sourceRoot) {
    copyDir(sourceRoot, workCircuits);
    const rel = path.relative(sourceRoot, circuitPath);
    localCircuit = path.join(workCircuits, rel);
  } else {
    localCircuit = path.join(workCircuits, path.basename(circuitPath));
    copyFile(circuitPath, localCircuit);
    for (const extra of extraFiles) {
      const full = path.isAbsolute(extra)
        ? extra
        : path.join(path.dirname(circuitPath), extra);
      copyFile(full, path.join(workCircuits, path.basename(full)));
    }
  }

  for (const spec of symlinks) {
    const [name, target] = spec.split('=');
    if (!name || !target) continue;
    safeSymlink(path.resolve(target), path.join(workNodeModules, name));
  }

  const filesToEdit = new Set([localCircuit]);
  for (const extra of extraFiles) {
    const full = sourceRoot
      ? path.join(workCircuits, path.relative(sourceRoot, path.join(path.dirname(circuitPath), extra)))
      : path.join(workCircuits, path.basename(extra));
    filesToEdit.add(full);
  }

  for (const filePath of filesToEdit) {
    applyEdits(filePath, {
      ensurePragma: ensurePragmaFlag,
      replace: replaceSpecs,
      commentOut,
      publicInputs,
    });
  }

  const circomArgs = [localCircuit, '--r1cs', '--wasm', '--sym', '--json', '-o', buildDir];
  for (const inc of includeDirs) {
    circomArgs.push('-l', inc);
  }
  execFileSync('circom', circomArgs, { stdio: 'inherit' });

  const basename = path.basename(localCircuit, path.extname(localCircuit));
  const wasmPath = path.join(buildDir, `${basename}_js`, `${basename}.wasm`);
  const symPath = path.join(buildDir, `${basename}.sym`);

  const tempDir = fs.mkdtempSync(path.join(buildRoot, 'tmp-'));
  const inputPath = path.join(tempDir, 'input.json');
  const witnessPath = path.join(tempDir, 'witness.wtns');
  const witnessJsonPath = path.join(tempDir, 'witness.json');

  let input = null;
  if (args.input_json) {
    input = JSON.parse(fs.readFileSync(args.input_json, 'utf8'));
  } else if (defaults.inputJson) {
    input = JSON.parse(fs.readFileSync(defaults.inputJson, 'utf8'));
  } else if (levels > 0) {
    input = buildDefaultInput(levels);
  } else {
    throw new Error('Missing --input-json (or supply --levels for default input).');
  }

  input = normalizeInputValue(input);
  const overrides = parseInputOverrides(args.input || []);
  for (const [key, value] of Object.entries(overrides)) {
    input[key] = value;
  }

  fs.writeFileSync(inputPath, JSON.stringify(input));
  execFileSync('npx', ['snarkjs', 'wtns', 'calculate', wasmPath, inputPath, witnessPath], {
    stdio: 'inherit',
  });
  execFileSync('npx', ['snarkjs', 'wtns', 'export', 'json', witnessPath, witnessJsonPath], {
    stdio: 'inherit',
  });

  const witness = JSON.parse(fs.readFileSync(witnessJsonPath, 'utf8'));
  const symMap = readSymMap(symPath);

  const extracts = extractSpecs.map(parseExtractSpec).filter(Boolean);
  if (!extracts.length) {
    throw new Error('No --extract signals specified.');
  }

  const finalInput = { ...input };
  for (const extract of extracts) {
    const idx = resolveSignalIndex(symMap, extract.signal);
    if (idx === undefined || idx === null) {
      throw new Error(`Failed to locate signal '${extract.signal}' in .sym`);
    }
    finalInput[extract.input] = witness[idx];
  }

  ensureDir(path.dirname(outputPath));
  fs.writeFileSync(outputPath, JSON.stringify([finalInput], null, 2));
  console.log(`Seed inputs written to ${outputPath}`);
}

main();
