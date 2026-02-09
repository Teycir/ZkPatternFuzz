// Ground Truth Circuit: Hash Length Extension Vulnerability
// Vulnerability: Hash function implementation vulnerable to length extension
// CVE Reference: Synthetic
// Attack Type: Soundness
// Expected: Fuzzer should detect hash weakness allowing forged proofs

pragma circom 2.0.0;

include "circomlib/circuits/bitify.circom";

// VULNERABLE: This circuit uses a weak iterative hash that's vulnerable to length extension
template HashLengthExtension() {
    signal input message[4];    // 4 field elements to hash
    signal input secret_prefix; // Secret prepended to message (for MAC)
    
    signal output hash_result;
    
    // VULNERABLE: Merkle-Damgård style construction without proper finalization
    // This is susceptible to length extension attacks where an attacker can:
    // 1. See H(secret || message) 
    // 2. Compute H(secret || message || attacker_suffix) WITHOUT knowing secret
    
    signal intermediate[5];
    intermediate[0] <== secret_prefix;
    
    // Simple compression function (for demonstration)
    // Real MD hashes (SHA-1, SHA-256) have this vulnerability
    for (var i = 0; i < 4; i++) {
        // BUG: Simple additive hash - trivially broken
        // Even with multiplication, length extension applies
        intermediate[i + 1] <== intermediate[i] * 7 + message[i];
    }
    
    // MISSING: Proper finalization that would prevent length extension
    // A secure hash should include:
    // 1. Message length in the final block
    // 2. Distinct finalization constants
    // 3. Truncation or additional mixing
    
    hash_result <== intermediate[4];
    
    // ATTACK SCENARIO:
    // Attacker knows: hash_result = H(secret_prefix || message)
    // Attacker wants: H(secret_prefix || message || extension)
    // 
    // Because there's no finalization, attacker can:
    // 1. Use hash_result as new intermediate state
    // 2. Continue the hash with extension blocks
    // 3. Produce valid hash WITHOUT knowing secret_prefix
}

// Vulnerable MAC construction
template WeakMAC() {
    signal input key;
    signal input message[2];
    signal input claimed_mac;
    
    signal output valid;
    
    // VULNERABLE: Simple keyed hash MAC
    // MAC = H(key || message)
    // This construction is vulnerable to length extension
    
    signal step1;
    step1 <== key * 31337;
    
    signal step2;
    step2 <== step1 + message[0] * 7;
    
    signal step3;
    step3 <== step2 + message[1] * 11;
    
    signal computed_mac;
    computed_mac <== step3;
    
    // Check if claimed MAC matches
    signal diff;
    diff <== computed_mac - claimed_mac;
    
    component isZero = IsZero();
    isZero.in <== diff;
    
    valid <== isZero.out;
    
    // SECURE ALTERNATIVE would be HMAC:
    // MAC = H(key XOR opad || H(key XOR ipad || message))
    // Or use Poseidon which is designed for ZK and doesn't have this issue
}

// Poseidon-based sponge (helper - not vulnerable)
template IsZero() {
    signal input in;
    signal output out;
    
    signal inv;
    inv <-- in != 0 ? 1/in : 0;
    
    out <== 1 - in * inv;
    in * out === 0;
}

component main {public [message]} = HashLengthExtension();
