# Security Model

## Threat Model

### Assumptions

1. **Hash function security**: `keccak256` is preimage and second-preimage resistant
2. **One-time use**: Each key pair is used for exactly one signature
3. **Key secrecy**: Private key material is never exposed before signing
4. **Random key generation**: Keys are generated with cryptographically secure randomness

### Attacker Capabilities

We assume an attacker can:
- Observe all signatures and public keys
- Attempt to forge signatures
- Have access to a quantum computer (Grover's algorithm)
- Attempt side-channel attacks (timing, power analysis)

### Security Properties

| Property | Guarantee | Assumption |
|----------|-----------|------------|
| Unforgeability | 256-bit classical, 128-bit quantum | One-time use |
| Non-repudiation | Signature proves possession of private key | Key secrecy |
| Integrity | Message cannot be modified without detection | Hash security |

## Key Security

### One-Time Property

**CRITICAL**: Signing two different messages with the same key can leak private key material.

Example attack:
```
Message A = 0b10110...
Signature A reveals: priv[0][1], priv[1][0], priv[2][1], ...

Message B = 0b11010...
Signature B reveals: priv[0][1], priv[1][1], priv[2][0], ...

Attacker now has both priv[1][0] and priv[1][1]!
```

**Mitigation**: Key rotation after every signature (see [Threshold Signing](./threshold.md)).

### Key Generation

Keys MUST be generated with:
- Cryptographically secure random number generator
- At least 256 bits of entropy per preimage
- Isolated, secure environment

```go
// GOOD: Secure key generation
for i := 0; i < 256; i++ {
    privKey[i][0] = make([]byte, 32)
    privKey[i][1] = make([]byte, 32)
    crypto.Read(privKey[i][0])
    crypto.Read(privKey[i][1])
}

// BAD: Predictable key generation
for i := 0; i < 256; i++ {
    privKey[i][0] = sha256(fmt.Sprintf("key-%d-0", i))  // NEVER DO THIS
}
```

## Implementation Security

### Hash Function Usage

This implementation uses `keccak256` exclusively:
- No length-extension vulnerabilities
- 256-bit output provides 128-bit quantum security
- Well-audited in Ethereum ecosystem

**Critical**: Use `abi.encodePacked` NOT `abi.encode`:
```solidity
// CORRECT
keccak256(abi.encodePacked(preimage))

// WRONG - adds length prefix, breaks verification
keccak256(abi.encode(preimage))
```

### Bit Ordering

This implementation uses MSB-first ordering:
- Bit 0 = leftmost bit of the 256-bit value
- Bit 255 = rightmost bit

Ensure off-chain signers use the same convention.

### Domain Separation

For threshold signing, messages include domain separation:
```solidity
keccak256(abi.encodePacked(
    safeTxHash,   // Transaction data
    nextPKH,      // Key rotation commitment
    module,       // Prevents cross-contract replay
    chainId       // Prevents cross-chain replay
))
```

## Side-Channel Resistance

### Timing Attacks

The standard verification has early exit on failure:
```solidity
if (hash != expected) return false;  // Leaks timing info
```

For side-channel resistance, use `verifyBranchless`:
```solidity
// Constant time - always processes all 256 elements
verifier.verifyBranchless(bits, sig, pub)
```

### Gas Consumption Patterns

| Function | Valid Sig Gas | Invalid Sig Gas |
|----------|--------------|-----------------|
| verifyFast | ~390K | Variable (early exit) |
| verifyUnrolled | ~380K | Variable (early exit) |
| verifyBranchless | ~435K | ~435K (constant) |

## Recommendations

### For High-Security Applications

1. Use `verifyBranchless` to prevent timing side-channels
2. Implement key rotation in the same transaction as signing
3. Use threshold signing (MPC) to distribute key material
4. Audit all off-chain key management code

### For Gas-Optimized Applications

1. Use `verifyUnrolled` for lowest gas cost
2. Ensure key rotation is enforced at the application level
3. Consider batching multiple operations per signature

### General Guidelines

1. Never reuse keys - implement automatic rotation
2. Validate public key format before storing
3. Use domain separation to prevent replay attacks
4. Keep private keys in secure enclaves or HSMs
5. Implement emergency key invalidation mechanism
