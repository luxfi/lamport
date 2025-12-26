---
title: Threshold Signing
description: T-of-N threshold Lamport signatures using Multi-Party Computation (MPC)
---

# Threshold Signing

## Overview

Threshold Lamport signing combines Multi-Party Computation (MPC) with Lamport one-time signatures to enable:

1. **Distributed Key Control**: T-of-N parties must cooperate to sign
2. **Automatic Key Rotation**: Next key committed in each signature
3. **On-Chain Simplicity**: Contract sees standard Lamport signature

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    T-Chain (MPC Layer)                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │  Party 1  │  │  Party 2  │  │  Party 3  │  ...       │
│  │ (share 1) │  │ (share 2) │  │ (share 3) │            │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘            │
│        └──────────────┼──────────────┘                  │
│                       ▼                                  │
│              ┌─────────────────┐                        │
│              │  Coordinator    │                        │
│              │ (Aggregate)     │                        │
│              └────────┬────────┘                        │
│                       ▼                                  │
│              ┌─────────────────┐                        │
│              │ Lamport Signature│ ← Combined from shares│
│              │   (8192 bytes)   │                        │
│              └────────┬────────┘                        │
└───────────────────────┼─────────────────────────────────┘
                        ▼
┌───────────────────────────────────────────────────────┐
│                  C-Chain (EVM Layer)                   │
│  ┌─────────────────────────────────────────────────┐  │
│  │            LamportThreshold Contract             │  │
│  │  ┌─────────────────┐  ┌───────────────────────┐ │  │
│  │  │   Current PKH   │  │  Verify Signature     │ │  │
│  │  │   (32 bytes)    │  │  Rotate to Next PKH   │ │  │
│  │  └─────────────────┘  └───────────────────────┘ │  │
│  └─────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────┘
```

## Implementation

### Go Package Structure

The `threshold` package provides complete MPC coordination:

```
threshold/
├── config.go      # Configuration and types
├── aggregate.go   # Signature aggregation
└── partial.go     # Partial signature generation
```

### Configuration

```go
import "github.com/luxfi/lamport/threshold"

// Create threshold config for 3-of-5 signing
config, err := threshold.NewConfig(
    3,                        // threshold (t)
    5,                        // total parties (n)
    "party-1",                // party ID
    96369,                    // chain ID
    moduleAddr,               // module address [20]byte
)
```

### Key Share Generation

Uses additive secret sharing - sum of all shares equals the original preimage:

```go
// Generate 5 shares of a Lamport keypair
shares, publicKey, err := threshold.GenerateShares(5)
if err != nil {
    panic(err)
}

// Each party receives one share
party1Share := shares[0]
party2Share := shares[1]
// ...

// Compute PKH for on-chain registration
pkh := primitives.ComputePKH(publicKey)
```

### Signing Protocol

The signing protocol has two phases to prevent equivocation attacks:

**Phase 1: Digest Commitment**

```go
// Each party broadcasts commitment BEFORE revealing signing material
commitment := config.CreateDigestCommitment(safeTxHash)

// Coordinator verifies all commitments match
valid := threshold.VerifyDigestCommitment(commitment, safeTxHash)
```

**Phase 2: Partial Signature Generation**

```go
// Each party generates partial signature from their share
partial := threshold.GeneratePartial(share, message)

// Coordinator collects t partials and aggregates
signature, err := threshold.AggregateThreshold(
    config,
    partials,     // []*PartialSignature (at least t)
    publicKey,
    safeTxHash,
    nextPKH,
)
```

### Coordinator Workflow

The `Coordinator` type manages the full signing protocol:

```go
// Create coordinator for this signing session
coord := threshold.NewCoordinator(config, publicKey, safeTxHash, nextPKH)

// Phase 1: Collect commitments
for _, commitment := range commitments {
    ready, err := coord.AddCommitment(commitment, safeTxHash)
    if ready {
        break // Have enough commitments
    }
}

// Phase 2: Collect partials
for _, partial := range partials {
    signature, err := coord.AddPartial(partial)
    if signature != nil {
        // Complete! Submit signature on-chain
        break
    }
}
```

## On-Chain Contract

```solidity
contract LamportThreshold {
    bytes32 public currentPKH;
    uint256 public immutable maxChainSize;

    constructor(uint256 _maxChainSize) {
        require(_maxChainSize > 0 && _maxChainSize <= 1000, "Invalid max size");
        maxChainSize = _maxChainSize;
    }

    function executeWithRotation(
        bytes32 safeTxHash,
        bytes32[] calldata sig,
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

        // 3. Verify signature
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

### Threshold Guarantees

| Property | Guarantee |
|----------|-----------|
| Signing | Requires T-of-N parties |
| Key Recovery | Impossible with < T shares |
| Quantum Resistance | Lamport provides PQ security |

### Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Equivocation | 1-round digest agreement with commitment broadcast |
| Fake Hash | Each party computes safeTxHash locally |
| Key Reuse | On-chain nonce + key rotation via nextPKH |
| Cross-Chain Replay | chainId in domain separator |
| Cross-Contract Replay | address(this) in domain separator |

### Domain Separation

Every message includes full context:

```go
message := primitives.ComputeThresholdMessage(
    safeTxHash,      // Transaction data
    nextPKH,         // Next key commitment
    moduleAddress,   // Module address
    chainID,         // Chain ID
)
```

## Types Reference

### Share

```go
type Share struct {
    PartyID        string
    Index          int
    PreimageShares [256][2][32]byte  // Shares for each bit position
}
```

### PartialSignature

```go
type PartialSignature struct {
    PartyID          string
    Index            int
    PreimagePartials [256][32]byte  // Revealed partial preimages
    BitMask          [32]byte       // Message hash (for verification)
}
```

### DigestCommitment

```go
type DigestCommitment struct {
    PartyID    string
    Commitment [32]byte  // H(safeTxHash || partyID)
}
```

## Error Handling

```go
var (
    ErrInvalidThreshold = errors.New("threshold: invalid threshold (must be 1 <= t <= n)")
    ErrNotEnoughParties = errors.New("threshold: not enough parties to meet threshold")
    ErrDigestMismatch   = errors.New("threshold: digest mismatch - parties disagree on message")
    ErrInvalidPartial   = errors.New("threshold: invalid partial signature failed verification")
)
```

## Integration with Safe

### Module Deployment

```solidity
// Deploy module with configurable chain size
LamportThreshold module = new LamportThreshold(256);

// Initialize with first PKH from threshold DKG
module.initialize(initialPKH);

// Enable module on Safe
safe.enableModule(address(module));
```

### Transaction Flow

1. **Propose**: User submits transaction to T-Chain coordinator
2. **Commit**: Each party broadcasts H(safeTxHash || partyID)
3. **Verify**: Wait for t commitments, verify all match
4. **Partial**: Each party generates partial signature
5. **Aggregate**: Coordinator combines t partials
6. **Execute**: Submit signature to C-Chain module
7. **Rotate**: Module updates to next PKH

## References

- [LP-4105](https://github.com/luxfi/lps) - Lamport OTS for Lux Safe
- [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
- [Gnosis Safe](https://github.com/safe-global/safe-smart-account) - Safe contracts
