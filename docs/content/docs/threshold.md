---
title: Threshold Signing
description: 2-round, no-reconstruction Lamport threshold protocol using additive MPC
---

# Threshold Signing

## Overview

This protocol enables T-of-N threshold Lamport signatures with a critical security property:

> **No node ever reconstructs a Lamport preimage.**

Each Lamport secret emerges only as the sum of masked contributions in the final signature—never known to any individual party.

## Non-Negotiable Goals

| Requirement | Status |
|-------------|--------|
| No reconstruction | ✅ Additive masking |
| 2 rounds | ✅ Commit + reveal |
| No coordinator trust | ✅ Any ≥ t works |
| Permissionless validators | ✅ Shares independent |
| Public coordination | ✅ Chain = bulletin board |
| Quantum safe | ✅ Hash only |
| Lamport compatible | ✅ Standard verifier |

## Core Insight

Lamport preimages are produced as the **sum of independently masked contributions**, never reconstructed at any node.

Each Lamport secret `sk[i][b]` is never known. Instead, the final preimage is:

```
sk[i][b] = r₁ + r₂ + … + rₜ   (mod 2²⁵⁶)
```

No participant ever knows the full value.

This is the Lamport analogue of Ringtail's "masked share summation".

## Protocol Specification

### Setup (One-Time, Per Lamport Key)

For each bit position `i ∈ [0..255]` and value `b ∈ {0,1}`:

1. Each signer `j` samples a random 256-bit value:
   ```
   r[j][i][b] ← random()
   ```

2. Public key commitment is:
   ```
   PK[i][b] = keccak256( Σ r[j][i][b] )
   ```

3. Each signer stores only their own r-values.

**Security guarantee**: No one ever knows:
- The sum of all r-values
- Another signer's values
- Any full preimage

This is information-theoretic security.

### Round 1 — Public Commit (Message-Independent)

Each signer posts only commitments, nothing secret:

```
Commit_j = H(
  sessionId ||
  H(all r[j][*][*]) ||
  nonce_j
)
```

This:
- Freezes participation
- Prevents equivocation
- Matches Ringtail's offline round

Public chain locks once ≥ t commits exist.

### Round 2 — Masked Contribution (Message-Dependent)

Now the message hash `m` is fixed.

For each bit `i`:
- Let `b = bit(m, i)`

Each signer `j` sends only:

```
contribution[j][i] = r[j][i][b]
```

But:
- Sent encrypted to the aggregation MPC
- Or broadcast via pairwise MPC channels
- Never published in plaintext

Each contribution alone is random and useless.

### Final Signature Formation (No Reconstruction)

The Lamport signature element for bit `i` is computed as:

```
sig[i] = Σ contribution[j][i]   (mod 2²⁵⁶)
```

This summation is done:
- Inside MPC, or
- By streaming masked sums so no party sees all inputs

⚠️ **At no point does any node know:**
- All `r[j][i]` values
- The final `sig[i]` before publication

### Public Output (Only Preimage Exposure)

The final Lamport signature is published:

```
Signature = [ sig[0], sig[1], ..., sig[255] ]
```

This is the first and only time any Lamport preimage appears.

**Verification:**
```
keccak256(sig[i]) == PK[i][bit(m,i)]
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    T-Chain (MPC Layer)                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                       │
│  │  Party 1  │  │  Party 2  │  │  Party 3  │  ...               │
│  │  r[1][*]  │  │  r[2][*]  │  │  r[3][*]  │                    │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘                    │
│        │              │              │                           │
│        ▼              ▼              ▼                           │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Additive MPC Summation                      │    │
│  │  sig[i] = Σ r[j][i][b]  (no party sees full sum)        │    │
│  └─────────────────────────────┬───────────────────────────┘    │
│                                 │                                │
│                                 ▼                                │
│                    ┌─────────────────────┐                      │
│                    │  Lamport Signature   │                      │
│                    │  (first appearance)  │                      │
│                    └──────────┬──────────┘                      │
└───────────────────────────────┼─────────────────────────────────┘
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│                      C-Chain (EVM Layer)                          │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                LamportThreshold Contract                     │ │
│  │  ┌─────────────────┐  ┌────────────────────────────────┐    │ │
│  │  │   Current PKH   │  │  Standard Lamport Verification  │    │ │
│  │  │   (32 bytes)    │  │  keccak256(sig[i]) == PK[i][b]  │    │ │
│  │  └─────────────────┘  └────────────────────────────────┘    │ │
│  └─────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────┘
```

## Comparison with Ringtail

| Ringtail | Lamport Threshold |
|----------|-------------------|
| LWE masked polynomials | Masked hash preimages |
| No secret reconstruction | Additive mask summation |
| 2 rounds | Commit + masked reveal |
| Single lattice signature | Standard Lamport signature |

## Implementation

### Go Package Structure

```
threshold/
├── config.go      # Configuration and types
├── shares.go      # Random share generation
├── commit.go      # Round 1: Commitment protocol
├── contribute.go  # Round 2: Masked contributions
├── mpc.go         # Additive MPC summation
└── aggregate.go   # Final signature formation
```

### Share Generation

```go
import "github.com/luxfi/lamport/threshold"

// Each party generates their own random shares
// No coordination needed - fully independent
myShares := threshold.GenerateRandomShares(partyID)

// Compute public key contribution
// PK[i][b] = H(Σ r[j][i][b]) requires MPC ceremony
pkContribution := threshold.ComputePKContribution(myShares)
```

### Signing Protocol

```go
// Round 1: Commit
commitment := threshold.CreateCommitment(sessionID, myShares, nonce)
// Broadcast commitment to chain

// Wait for ≥ t commitments...

// Round 2: Contribute (message-dependent)
message := computeThresholdMessage(safeTxHash, nextPKH, module, chainID)
contribution := threshold.CreateContribution(myShares, message)
// Send to MPC aggregation (encrypted)

// Final signature emerges from MPC
// No party ever sees full preimages
```

### MPC Summation

The critical operation is additive MPC summation where no party learns the result:

```go
// Each party holds contribution[j][i]
// MPC computes sig[i] = Σ contribution[j][i]
// Result published only as final signature

signature := mpc.SecureSum(contributions)
// signature is now a valid Lamport signature
```

## On-Chain Contract

The on-chain contract sees only a standard Lamport signature:

```solidity
contract LamportThreshold {
    bytes32 public currentPKH;

    function executeWithRotation(
        bytes32 safeTxHash,
        bytes32[] calldata sig,        // Standard 256-element signature
        bytes32[2][256] calldata currentPub,
        bytes32[2][256] calldata nextPub
    ) external {
        // 1. Verify current PKH
        require(
            LamportLib.computePKH(currentPub) == currentPKH,
            "Invalid current key"
        );

        // 2. Compute domain-separated message
        uint256 message = LamportLib.computeThresholdMessage(
            safeTxHash,
            LamportLib.computePKH(nextPub),
            address(this),
            block.chainid
        );

        // 3. Standard Lamport verification
        require(
            LamportLib.verify(bytes32(message), sig, currentPub),
            "Invalid signature"
        );

        // 4. Rotate to next key
        currentPKH = LamportLib.computePKH(nextPub);

        // 5. Execute transaction...
    }
}
```

## Security Properties

### Information-Theoretic Security

| Property | Guarantee |
|----------|-----------|
| Preimage secrecy | No party ever knows any full preimage |
| Threshold security | < t parties learn nothing about signature |
| Quantum resistance | Based only on hash function security |
| No trusted dealer | Parties generate shares independently |

### Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Share reconstruction | Impossible - additive MPC only |
| Coordinator attack | No coordinator has access to preimages |
| Equivocation | Round 1 commitment freezes participation |
| Key reuse | On-chain nonce + key rotation via nextPKH |
| Cross-chain replay | chainId in domain separator |
| Cross-contract replay | address(this) in domain separator |

## Key Rotation

After each signature, the key is rotated:

1. **During signing**: Next public key is committed in the message
2. **New shares**: Each party generates fresh `r[j][i][b]` for next key
3. **Atomic rotation**: Old key invalidated, new key activated on-chain

```go
// Generate next key shares (independent per party)
nextShares := threshold.GenerateRandomShares(partyID)
nextPKH := threshold.ComputePKHContribution(nextShares)

// Include in signature message
message := computeThresholdMessage(safeTxHash, nextPKH, module, chainID)
```

## References

- [LP-4105](https://lps.lux.network/docs/lp-4105) - Lamport OTS for Lux Safe
- [Ringtail](https://eprint.iacr.org/2024/1113) - 2-round threshold lattice signatures
- [Secure Multi-Party Computation](https://en.wikipedia.org/wiki/Secure_multi-party_computation)
- [Gnosis Safe](https://github.com/safe-global/safe-smart-account) - Safe contracts
