# Lamport One-Time Signatures

## What are Lamport Signatures?

Lamport signatures are quantum-resistant digital signatures invented by Leslie Lamport in 1979. Unlike ECDSA or EdDSA, Lamport signatures rely only on hash function security, making them resistant to attacks from quantum computers.

## How They Work

### Key Generation

A Lamport key pair consists of:
- **Private Key**: 256 pairs of random 32-byte values = 512 × 32 = 16,384 bytes
- **Public Key**: Hash of each private key value = 512 × 32 = 16,384 bytes

```
Private Key:               Public Key:
[priv[0][0], priv[0][1]]   [H(priv[0][0]), H(priv[0][1])]
[priv[1][0], priv[1][1]]   [H(priv[1][0]), H(priv[1][1])]
...                        ...
[priv[255][0], priv[255][1]] [H(priv[255][0]), H(priv[255][1])]
```

### Signing

To sign a 256-bit message `m`:

1. For each bit position `i` (0 to 255):
   - If bit `i` of `m` is 0: reveal `priv[i][0]`
   - If bit `i` of `m` is 1: reveal `priv[i][1]`

2. The signature is the 256 revealed preimages (8,192 bytes)

```
Message: 10110...
Signature: [priv[0][1], priv[1][0], priv[2][1], priv[3][1], priv[4][0], ...]
```

### Verification

To verify a signature against message `m` and public key `pub`:

1. For each bit position `i`:
   - If bit `i` of `m` is 0: check `H(sig[i]) == pub[i][0]`
   - If bit `i` of `m` is 1: check `H(sig[i]) == pub[i][1]`

2. All 256 checks must pass

## Security Properties

### One-Time Property

**CRITICAL**: Each Lamport key can only sign ONE message safely.

If a key signs two different messages, an attacker who observes both signatures may be able to:
- Recover preimages for both bit values at some positions
- Forge signatures for messages that share the same bits in revealed positions

### Quantum Resistance

Lamport signatures only require:
- Preimage resistance: Given `H(x)`, cannot find `x`
- Second preimage resistance: Given `x`, cannot find `x' ≠ x` where `H(x) = H(x')`

These properties are believed to hold against quantum computers (unlike discrete log or factoring).

### Hash Function

This implementation uses `keccak256` which provides:
- 256-bit security against classical attacks
- 128-bit security against quantum attacks (Grover's algorithm)

## Key Rotation

Since keys are one-time use, applications must manage key rotation:

1. Generate next key pair before signing
2. Include `H(nextPubKey)` in the signed message
3. Update key registry after each signature

See [Threshold Signing](./threshold.md) for how this is handled with MPC.

## Comparison with Other Schemes

| Scheme | Signature Size | Key Size | Quantum Safe | One-Time |
|--------|---------------|----------|--------------|----------|
| ECDSA | 64 bytes | 33 bytes | No | No |
| EdDSA | 64 bytes | 32 bytes | No | No |
| ML-DSA | 2,420 bytes | 1,312 bytes | Yes | No |
| **Lamport** | 8,192 bytes | 16,384 bytes | **Yes** | **Yes** |

## Use Cases

Lamport signatures are ideal for:

1. **High-security transactions** where quantum resistance is critical
2. **Key ceremony signatures** (one-time by nature)
3. **Root key commitments** in Merkle trees
4. **Threshold signing** where MPC manages key rotation

## References

- [Original Paper](https://www.microsoft.com/en-us/research/publication/constructing-digital-signatures-from-a-one-way-function/) - Lamport, 1979
- [LP-4105](https://github.com/luxfi/lps) - Lamport OTS for Lux Safe
- [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography) - Post-Quantum Cryptography Standards
