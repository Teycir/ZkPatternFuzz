// Generate a constraint-satisfying seed input for
//   credentialAtomicQueryV3-16-16-64 (MTP flow, NOOP query, no revocation check)
// using circomlibjs Poseidon primitives (no network needed).
//
// Output format matches ZkPatternFuzz seed loader expectations:
// - Scalars are provided as decimal strings
// - Arrays are provided under their base name (e.g. "value": [...])
//
// Usage:
//   node scripts/gen_credentialAtomicQueryV3_seed_inputs.mjs [out.json]
//
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

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

  let envFile = null;
  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) {
      envFile = candidate;
      break;
    }
  }
  if (!envFile) {
    return repoRoot;
  }

  const lines = fs.readFileSync(envFile, "utf8").split(/\r?\n/);
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

  return repoRoot;
}

const REPO_ROOT = loadEnvMaster();

async function loadBuildPoseidon() {
  const candidates = [];

  if (process.env.CIRCUIT_NODE_MODULES_DIR) {
    candidates.push(
      path.join(process.env.CIRCUIT_NODE_MODULES_DIR, "circomlibjs", "main.js"),
    );
  }
  if (process.env.ZK0D_BASE) {
    candidates.push(
      path.join(
        process.env.ZK0D_BASE,
        "cat3_privacy",
        "circuits",
        "node_modules",
        "circomlibjs",
        "main.js",
      ),
    );
  }
  candidates.push(path.join(process.cwd(), "node_modules", "circomlibjs", "main.js"));
  candidates.push(path.join(REPO_ROOT, "node_modules", "circomlibjs", "main.js"));

  for (const candidate of candidates) {
    if (!candidate || !fs.existsSync(candidate)) {
      continue;
    }
    const mod = await import(pathToFileURL(candidate).href);
    if (typeof mod.buildPoseidon === "function") {
      return mod.buildPoseidon;
    }
  }

  try {
    const mod = await import("circomlibjs");
    if (typeof mod.buildPoseidon === "function") {
      return mod.buildPoseidon;
    }
  } catch {
    // Keep error handling below for a clear message.
  }

  throw new Error(
    "Could not resolve circomlibjs buildPoseidon. Set CIRCUIT_NODE_MODULES_DIR or ZK0D_BASE, or install circomlibjs locally.",
  );
}

const buildPoseidon = await loadBuildPoseidon();

const OUT_PATH =
  process.argv[2] ??
  path.join("campaigns", "zk0d", "credentialAtomicQueryV3_seed_inputs.json");

const poseidon = await buildPoseidon();
const F = poseidon.F;

// circomlibjs represents field elements as Uint8Array.
const fe = (x) => F.e(BigInt(x));
const toDec = (feVal) => F.toObject(feVal).toString();

// ----------------------------
// Minimal "valid" configuration
// ----------------------------
//
// We intentionally pick a configuration that:
// - Uses MTP flow (proofType=2) to avoid EdDSA signature constraints.
// - Disables revocation checks (isRevocationChecked=0).
// - Uses NOOP operator (operator=0) and valueArraySize=0.
// - Uses a non-merklized claim (merklizeLocation=0) so claimPath SMT is skipped.
// - Sets claim subject = userGenesisID (subjectLocation=2 and claim[1]=userGenesisID),
//   with claimSubjectProfileNonce=0 so SelectProfile() returns userGenesisID.
//
// This is not "protocol realistic", but it is constraint-satisfying and is a good
// starting point for seed-based fuzzing runs without external test vectors.

const schema = 1n;

// claimFlags is a 32-bit field extracted from claim[0] bits [128..159].
// We need:
// - subjectLocation (claimFlags[0..2]) = 2 => 0b010 => claimFlags[1]=1
// - expirationFlag (claimFlags[3]) = 0
// - merklizeLocation (claimFlags[5..7]) = 0 (non-merklized)
let claimFlags = 0n;
claimFlags |= 1n << 1n;

// claim[0] = schema (low 128 bits) || claimFlags (next 32 bits) || zeros
const claim0 = schema + (claimFlags << 128n);

// userGenesisID must fit in 248 bits (ProfileID/SelectProfile path).
const userGenesisID = 1n;

const issuerClaim = [
  claim0,
  userGenesisID, // subjectOtherIdenId when subjectLocation==2
  0n,
  0n,
  0n,
  0n,
  0n,
  0n,
];

// getClaimHiHv(): Poseidon(4) over index slots and value slots.
const issuerClaimHi = poseidon(issuerClaim.slice(0, 4).map(fe));
const issuerClaimHv = poseidon(issuerClaim.slice(4, 8).map(fe));
const issuerClaimHash = poseidon([issuerClaimHi, issuerClaimHv]);

// checkClaimExists() uses circomlib SMTVerifier and leaf hash:
//   SMTHash1(key,value) = Poseidon(3)([key, value, 1])
// A "single-leaf tree" is accepted by providing all-zero siblings and setting
// root = leaf_hash (insertion at level 0).
const issuerClaimClaimsTreeRoot = poseidon([issuerClaimHi, issuerClaimHv, fe(1n)]);
const issuerClaimRevTreeRoot = 0n;
const issuerClaimRootsTreeRoot = 0n;
const issuerClaimIdenState = poseidon(
  [issuerClaimClaimsTreeRoot, fe(issuerClaimRevTreeRoot), fe(issuerClaimRootsTreeRoot)],
);

const zeros = (n) => Array.from({ length: n }, () => "0");

const seed = {
  // Common (Sig + MTP)
  proofType: "2",
  requestID: "1",
  userGenesisID: userGenesisID.toString(),
  profileNonce: "0",
  claimSubjectProfileNonce: "0",
  issuerID: "2",
  isRevocationChecked: "0",

  issuerClaimNonRevMtp: zeros(16),
  issuerClaimNonRevMtpNoAux: "0",
  issuerClaimNonRevMtpAuxHi: "0",
  issuerClaimNonRevMtpAuxHv: "0",
  issuerClaimNonRevClaimsTreeRoot: "0",
  issuerClaimNonRevRevTreeRoot: "0",
  issuerClaimNonRevRootsTreeRoot: "0",
  issuerClaimNonRevState: "0",

  timestamp: "0", // must fit in 64 bits due to Num2Bits(64)(timestamp)
  claimSchema: schema.toString(),

  claimPathMtp: zeros(16),
  claimPathMtpNoAux: "0",
  claimPathMtpAuxHi: "0",
  claimPathMtpAuxHv: "0",
  claimPathKey: "0",
  claimPathValue: "0",

  slotIndex: "0", // must fit in 3 bits
  operator: "0", // must fit in 5 bits
  value: zeros(64),
  valueArraySize: "0",

  issuerClaim: issuerClaim.map((v) => v.toString()),
  issuerClaimMtp: zeros(16),
  issuerClaimClaimsTreeRoot: toDec(issuerClaimClaimsTreeRoot),
  issuerClaimRevTreeRoot: issuerClaimRevTreeRoot.toString(),
  issuerClaimRootsTreeRoot: issuerClaimRootsTreeRoot.toString(),
  issuerClaimIdenState: toDec(issuerClaimIdenState),
  verifierID: "0",
  nullifierSessionID: "0",

  // Sig-specific inputs (disabled for proofType=2, but must be present)
  issuerAuthClaim: zeros(8),
  issuerAuthClaimMtp: zeros(16),
  issuerAuthClaimsTreeRoot: "0",
  issuerAuthRevTreeRoot: "0",
  issuerAuthRootsTreeRoot: "0",
  issuerAuthState: "0",
  issuerAuthClaimNonRevMtp: zeros(16),
  issuerAuthClaimNonRevMtpNoAux: "0",
  issuerAuthClaimNonRevMtpAuxHi: "0",
  issuerAuthClaimNonRevMtpAuxHv: "0",
  issuerClaimSignatureR8x: "0",
  issuerClaimSignatureR8y: "0",
  issuerClaimSignatureS: "0",

  // Linked proofs
  linkNonce: "0",

  // Optional debug context (ignored by seed loader)
  _derived: {
    issuerClaimHi: toDec(issuerClaimHi),
    issuerClaimHv: toDec(issuerClaimHv),
    issuerClaimHash: toDec(issuerClaimHash),
  },
};

fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
fs.writeFileSync(OUT_PATH, JSON.stringify([seed], null, 2) + "\n", "utf8");

console.log(`Wrote seed inputs: ${OUT_PATH}`);
console.log(`issuerClaimClaimsTreeRoot = ${seed.issuerClaimClaimsTreeRoot}`);
console.log(`issuerClaimIdenState      = ${seed.issuerClaimIdenState}`);
