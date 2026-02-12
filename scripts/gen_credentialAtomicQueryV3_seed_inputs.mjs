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

// Reuse the target's vendored node_modules.
import { buildPoseidon } from "/media/elements/Repos/zk0d/cat3_privacy/circuits/node_modules/circomlibjs/main.js";

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
