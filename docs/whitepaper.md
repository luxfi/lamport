# Threshold Lamport Signatures via T-Chain MPC

**A Quantum-Safe Threshold Signing Protocol for Any EVM Chain**

## Abstract

We present a novel approach to threshold Lamport one-time signatures (OTS) that enables quantum-resistant multi-party control of assets on any EVM-compatible blockchain. Our key insight is that the threshold property (t-of-n signing) can be enforced entirely off-chain by a dedicated MPC network (T-Chain), while on-chain verification remains a standard Lamport signature—requiring only keccak256 hash operations available on all EVM chains.

This design provides:
- **Universal Compatibility**: Works on any EVM chain without precompiles
- **Quantum Resistance**: Security based only on hash function preimage resistance
- **Threshold Control**: t-of-n signing with MPC-enforced authorization
- **Key Rotation**: One-time key property preserved through PKH commitment chains

## 1. Introduction

### 1.1 The Quantum Threat

Current blockchain signatures (ECDSA, Ed25519) rely on the hardness of the discrete logarithm problem, which is efficiently solvable by quantum computers running Shor's algorithm. With estimates of cryptographically-relevant quantum computers arriving within 10-15 years, preparing quantum-resistant cryptography is essential for long-term asset security.

### 1.2 Lamport Signatures

Lamport signatures, invented by Leslie Lamport in 1979, provide quantum resistance using only hash functions. Their security depends solely on the preimage resistance of the hash function—a property believed to resist quantum attacks (Grover's algorithm only provides quadratic speedup, addressable by doubling hash output size).

**Key Properties**:
- **One-time**: Each key pair can only sign ONE message safely
- **Large keys**: ~16KB public key, ~8KB signature
- **Simple verification**: 256 hash comparisons

### 1.3 The Threshold Challenge

Standard Lamport signatures provide single-signer quantum resistance. However, many high-security applications require threshold signing (t-of-n authorization). Naive approaches to threshold Lamport face challenges:

1. **Share revelation**: Revealing partial preimages might leak information
2. **Coordination**: Parties must agree on the message before revealing material
3. **Remote chains**: Adding precompiles to every target chain is impractical

## 2. Architecture

### 2.1 Key Insight: Off-Chain Threshold, On-Chain Verification

Our fundamental insight is to separate concerns:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    THRESHOLD LAMPORT ARCHITECTURE                   │
│                                                                     │
│  T-Chain MPC Network                 │       Remote EVM Chain       │
│  ═══════════════════                 │       ════════════════       │
│                                      │                              │
│  ┌─────────────────────────┐         │    ┌──────────────────────┐  │
│  │  Threshold Control      │         │    │  Standard Lamport    │  │
│  │  (t-of-n authorization) │────────────▶│  Verification Only   │  │
│  │                         │         │    │                      │  │
│  │  • DKG for shares       │  Single │    │  keccak256(sig[i])   │  │
│  │  • Partial signatures   │  Lamport│    │     == pub[i][bit]   │  │
│  │  • Aggregation          │   Sig   │    │                      │  │
│  └─────────────────────────┘         │    └──────────────────────┘  │
│                                      │                              │
│  Threshold enforced HERE             │    NO precompile needed!     │
└─────────────────────────────────────────────────────────────────────┘
```

**The remote chain sees ONE standard Lamport signature**. It has no knowledge of the threshold scheme—verification is simply checking that each revealed preimage hashes to the corresponding public key element.

### 2.2 System Components

1. **T-Chain**: Lux's threshold MPC network
   - Holds shares of Lamport private keys
   - Coordinates threshold signing protocol
   - Aggregates partial signatures

2. **Safe Module**: On-chain contract on target chain
   - Stores PKH (32 bytes) instead of full public key
   - Verifies Lamport signatures
   - Enforces key rotation via nextPKH

3. **Key Chains**: Pre-generated sequences of one-time keys
   - Each signature commits to the next PKH
   - Enables continuous operation

## 3. Protocol Specification

### 3.1 Setup Phase (DKG)

The T-Chain network runs distributed key generation:

```
For each Lamport key pair (256 × 2 preimages):
    1. Generate n shares using additive secret sharing
    2. Party i receives share_i[j][b] for all j ∈ [0,255], b ∈ {0,1}
    3. Public key computed: pub[j][b] = H(∑ share_i[j][b])
    4. Compute PKH = H(pub)
```

### 3.2 Signing Protocol

**Phase 1: Digest Agreement** (prevents equivocation attack)

```
1. Coordinator broadcasts transaction details: (to, value, data, operation)
2. Each party i locally computes:
   safeTxHash = ISafe.getTransactionHash(to, value, data, ..., nonce)
3. Each party broadcasts commitment: H(safeTxHash || party_id)
4. Wait for t commitments
5. Verify all commitments match same safeTxHash
```

**Critical**: Parties MUST compute safeTxHash locally. Never accept a prepacked hash from the coordinator—this prevents the 2022 "different messages to different signers" attack.

**Phase 2: Partial Signature Generation**

```
For message m = H(safeTxHash || nextPKH || module || chainId):
    For each bit j ∈ [0,255]:
        bit = (m >> (255-j)) & 1
        partial_i[j] = share_i[j][bit]  // Reveal only needed half
```

**Phase 3: Aggregation**

```
Coordinator collects t partials:
    For each j ∈ [0,255]:
        sig[j] = ⊕ partial_i[j]  // XOR for additive sharing
    Return sig
```

### 3.3 On-Chain Verification

The Safe module verifies using standard Lamport:

```solidity
function verify_u256(
    uint256 bits,
    bytes[256] calldata sig,
    bytes32[2][256] calldata pub
) public pure returns (bool) {
    for (uint256 i; i < 256; i++) {
        uint256 bit = (bits & (1 << (255 - i))) > 0 ? 1 : 0;
        if (keccak256(sig[i]) != pub[i][bit]) return false;
    }
    return true;
}
```

### 3.4 Key Rotation

Each signature commits to the next public key:

```
message = H(safeTxHash || nextPKH || address(this) || chainid)
```

After verification, the module updates: `pkh = nextPKH`

## 4. Security Analysis

### 4.1 Threat Model

We assume:
- Up to t-1 MPC parties may be corrupted (Byzantine)
- Quantum adversary with access to a cryptographically-relevant quantum computer
- Network adversary can delay/reorder messages (but not forge)

### 4.2 Security Properties

**Quantum Resistance**: Security reduces to keccak256 preimage resistance. Even with Grover's algorithm (providing √N speedup for search), 256-bit keccak256 provides ~128 bits of quantum security.

**Threshold Enforcement**: With additive secret sharing, reconstructing any preimage requires all t shares. Fewer than t shares reveal nothing about the preimage.

**One-Time Property**: Each Lamport key is used exactly once. The nextPKH commitment ensures orderly rotation.

**Replay Protection**: Domain separation via `(safeTxHash, nextPKH, address(this), chainid)` prevents:
- Cross-chain replay (chainid)
- Cross-contract replay (address(this))
- Signature reuse (one-time keys + nonce in safeTxHash)

### 4.3 Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Equivocation (different messages to signers) | 1-round digest agreement with H(safeTxHash) broadcast |
| Coordinator provides fake hash | Each party computes safeTxHash locally |
| Key reuse | On-chain nonce + key rotation via nextPKH |
| Replay on other chain | chainid in domain separator |
| Replay on other module | address(this) in domain separator |

## 5. Performance

### 5.1 Computation (Apple M1 Max)

| Operation | Latency |
|-----------|---------|
| Key Generation | ~1.2ms |
| Sign (single) | ~0.8ms |
| Verify | ~0.6ms |
| Threshold Aggregate (3-of-5) | ~0.3ms |

### 5.2 Sizes

| Component | Size |
|-----------|------|
| Private Key | 16,384 bytes |
| Public Key | 16,384 bytes |
| Signature | 8,192 bytes |
| PKH (on-chain storage) | 32 bytes |

### 5.3 Gas Costs (EVM)

| Operation | Gas |
|-----------|-----|
| Verify (Solidity) | ~100,000 |
| Verify (Precompile) | ~15,800 |
| Store PKH | ~20,000 |
| Rotate PKH | ~5,000 |

## 6. Optimization Roadmap

### 6.1 Winternitz OTS (W-OTS)

Winternitz extends Lamport with hash chains, reducing signature size:

- **W-OTS (w=4)**: ~2KB signatures (4× reduction)
- **W-OTS (w=16)**: ~1KB signatures (8× reduction)
- Trade-off: More hashes per verification

### 6.2 Merkle OTS

Use Merkle trees to enable multiple signatures from one root:

- **XMSS**: ~2KB signatures, 2^20 messages per key
- **LMS**: NIST-approved stateful hash-based signatures

### 6.3 SPHINCS+

Stateless hash-based signatures (NIST FIPS 205):

- **SLH-DSA-128s**: ~7KB signatures, unlimited uses
- Slower signing but no state management

## 7. Integration with Lux Ecosystem

### 7.1 Ringtail Comparison

| Property | Lamport | Ringtail |
|----------|---------|----------|
| Basis | Hash functions | Lattice (Module-LWE) |
| Key Size | 16KB | ~2KB |
| Signature Size | 8KB | ~4KB |
| Verification | 256 hashes | Polynomial ops |
| Deployment | Any EVM | Lux precompile |
| Threshold | Via MPC | Native |

**Recommendation**:
- **Remote chains**: Use Threshold Lamport (works anywhere)
- **Lux-native**: Use Ringtail (smaller, native threshold)

### 7.2 Safe Integration

The `SafeThresholdLamportModule` enables any Safe to be controlled by T-Chain:

```solidity
// Deploy module
SafeThresholdLamportModule module = new SafeThresholdLamportModule(safe);

// Initialize with first PKH from T-Chain DKG
module.init(initialPkh);

// Execute via threshold signature
module.execWithThresholdLamport(to, value, data, op, sig, pub, nextPkh);
```

## 8. Conclusion

Threshold Lamport signatures via T-Chain MPC provide a practical path to quantum-resistant multi-party control on any EVM chain. By keeping threshold enforcement off-chain while using standard Lamport verification on-chain, we achieve universal compatibility without requiring precompile deployment.

The protocol is simple, auditable, and relies only on the well-understood security of keccak256. As quantum computers advance, this approach provides a robust defense for high-value digital assets.

## References

1. Lamport, L. (1979). "Constructing Digital Signatures from a One-Way Function"
2. Merkle, R. (1979). "A Certified Digital Signature"
3. Buchmann et al. (2011). "XMSS - A Practical Forward Secure Signature Scheme"
4. NIST FIPS 205 (2024). "Stateless Hash-Based Digital Signature Standard"
5. Grover, L. (1996). "A Fast Quantum Mechanical Algorithm for Database Search"

## Appendix A: Solidity Reference Implementation

See: [SafeThresholdLamportModule.sol](../../../standard/contracts/safe/SafeThresholdLamportModule.sol)

## Appendix B: Go Reference Implementation

See: [github.com/luxfi/lamport](https://github.com/luxfi/lamport)
