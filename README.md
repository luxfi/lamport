# Lamport One-Time Signatures (OTS)

Post-quantum secure one-time signatures using only hash functions.

## Overview

Lamport signatures provide quantum resistance using only Keccak-256 hash operations.
This implementation supports:

- **Standard Lamport-256**: 256-bit message signing with one-time keys
- **Threshold MPC Control**: T-Chain MPC jointly controls ONE Lamport key
- **Key Chains**: Automatic key rotation for continuous operation
- **EVM Precompile**: Gas-efficient on-chain verification

## Security Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                    THRESHOLD LAMPORT VIA MPC                        │
│                                                                     │
│  T-Chain MPC Network              │       Any EVM Chain             │
│  ┌─────────────────────────┐      │      ┌──────────────────────┐  │
│  │  Threshold lives HERE   │      │      │  Standard Lamport    │  │
│  │  (t-of-n signing)       │─────────────│  verification only   │  │
│  │                         │      │      │  (no precompile!)    │  │
│  │  • DKG for shares       │      │      │                      │  │
│  │  • Partial signatures   │      │      │  keccak256(sig[i])   │  │
│  │  • Aggregation          │      │      │    == pub[i][bit]    │  │
│  └─────────────────────────┘      │      └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

**Key insight**: Threshold control lives OFF-CHAIN in the T-Chain MPC network.
On-chain sees ONE standard Lamport signature - works on ANY EVM chain!

## Installation

### Go
```bash
go get github.com/luxfi/lamport
```

### Solidity (Foundry)
```bash
forge install luxfi/lamport
```

### Solidity (npm)
```bash
npm install @luxfi/lamport-contracts
```

## Quick Start

### Generate Key Pair
```go
import "github.com/luxfi/lamport"

// Generate a one-time key pair
kp, err := lamport.GenerateKeyPair()

// Get public key hash for on-chain storage
pkh := kp.Public.Hash()
```

### Sign a Message
```go
// Sign a 32-byte message (ONLY USE ONCE!)
message := sha3.Sum256([]byte("Hello, quantum-safe world!"))
sig, err := lamport.Sign(kp.Private, message[:])
```

### Verify Signature
```go
valid := lamport.Verify(kp.Public, message[:], sig)
```

### Key Chain for Continuous Operation
```go
// Create a chain of 100 one-time keys
chain, err := lamport.NewKeyChain(100)

// Get current key and next PKH (for rotation)
current, _ := chain.Current()
nextPKH, _ := chain.NextPKH()

// After signing, advance to next key
chain.Advance()
```

## Threshold MPC Integration

For T-Chain integration where threshold property is enforced off-chain:

```go
import "github.com/luxfi/lamport/threshold"

// Configure threshold parameters
config := &threshold.Config{
    Threshold:     3,
    TotalParties:  5,
    PartyID:       "party-1",
    ChainID:       96369,  // Lux mainnet
    ModuleAddress: common.HexToAddress("0x..."),
}

// Compute message hash (matches on-chain computation)
msg := threshold.ComputeMessage(
    safeTxHash,
    nextPKH,
    config.ModuleAddress,
    config.ChainID,
)

// Generate partial signature (this party's share)
partial, err := threshold.SignPartial(config, privateShare, msg)

// Coordinator aggregates partials into final signature
finalSig := threshold.Aggregate(partials...)
```

## Solidity Contracts

The `contracts/` directory contains production-ready Solidity implementations:

### LamportLib - Core Library
```solidity
import {LamportLib} from "@luxfi/lamport/LamportLib.sol";

// Verify signature
bool valid = LamportLib.verify_u256(message, sig, pub);

// Compute PKH from public key
bytes32 pkh = LamportLib.computePKH(pub);

// Domain-separated message for threshold signing
uint256 m = LamportLib.computeThresholdMessage(
    safeTxHash, nextPKH, address(this), block.chainid
);
```

### LamportModule - Safe Integration
```solidity
import {LamportModule} from "@luxfi/lamport/LamportModule.sol";

// Deploy and initialize
LamportModule module = new LamportModule(safeAddress);
// Initialize via Safe transaction with initialPKH

// Execute with Lamport signature
module.execWithLamport(to, value, data, operation, sig, pub, nextPKH);
```

### Contract Files

| Contract | Description | Gas |
|----------|-------------|-----|
| `LamportLib.sol` | Core verification library | ~85k verify |
| `LamportVerifier.sol` | Standalone verifier | ~90k |
| `LamportModule.sol` | Safe module | ~150k exec |
| `LamportKeyRegistry.sol` | Key chain management | ~50k register |

## EVM Precompile

For Lux-native chains, the Lamport precompile provides gas-efficient verification:

**Precompile Address**: `0x0200000000000000000000000000000000000006`

```solidity
// Verify Lamport signature via precompile (~15,800 gas vs ~85,000)
(bool valid) = LAMPORT_PRECOMPILE.staticcall(
    abi.encode(messageHash, signature, publicKey)
);
```

## Directory Structure

```
lamport/
├── primitives/           # Go: Core Lamport types and operations
│   ├── types.go          # PrivateKey, PublicKey, Signature, KeyChain
│   ├── sign.go           # Signing functions
│   ├── verify.go         # Verification functions
│   └── lamport_test.go   # Comprehensive tests
├── threshold/            # Go: T-Chain MPC integration
│   ├── config.go         # Threshold configuration
│   ├── partial.go        # Partial signature generation
│   └── aggregate.go      # Signature aggregation
├── precompile/           # Go: EVM precompile interface
│   └── contract.go       # Precompile implementation
├── contracts/            # Solidity: Smart contracts
│   ├── LamportLib.sol    # Core verification library
│   ├── LamportVerifier.sol # Standalone verifier
│   ├── LamportModule.sol # Safe module
│   ├── ILamportModule.sol # Module interface
│   ├── LamportKeyRegistry.sol # Key chain management
│   ├── test/             # Foundry tests
│   └── foundry.toml      # Foundry config
├── docs/                 # Documentation
│   └── whitepaper.md     # Threshold Lamport whitepaper
├── main.go               # CLI tool
└── Makefile              # Build automation
```

## Performance

| Operation | Time (Apple M1 Max) | Memory |
|-----------|---------------------|--------|
| KeyGen | 1.2ms | 32KB |
| Sign | 0.8ms | 8KB |
| Verify | 0.6ms | 16KB |
| PKH (keccak256) | 0.3ms | 0 |

## Security Considerations

1. **One-Time Property**: Each key MUST only sign ONE message. Reuse reveals private key.
2. **Key Rotation**: Use KeyChain for automatic rotation with nextPKH commitment.
3. **Domain Separation**: Include chainId and module address to prevent replay.
4. **Canonical Digest**: Compute safeTxHash ON-CHAIN, never accept from coordinator.

## Related LPs

- **LP-4105**: Lamport OTS for Lux Safe
- **LP-4200**: Post-Quantum Cryptography Suite
- **LP-7324**: Ringtail Threshold Signatures
- **LP-3310**: Safe Multisig Standard

## License

BSD-3-Clause - See [LICENSE](LICENSE)
