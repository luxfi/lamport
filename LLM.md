# Lamport OTS - AI Assistant Context

> **Naming (LP-134):** MPC threshold custody for cross-chain assets lives on
> **M-Chain**. References to "T-Chain MPC" below are historical — the current
> chain providing MPC ceremonies is M-Chain.

## Overview

This repository implements Lamport one-time signatures (OTS) with threshold MPC support for the Lux Network ecosystem. The key insight is that threshold control lives off-chain in the M-Chain MPC network, while on-chain verification is standard Lamport—working on ANY EVM chain.

## Directory Structure

```
lamport/
├── primitives/           # Core Lamport types and operations
│   ├── types.go         # PrivateKey, PublicKey, Signature, KeyChain
│   ├── sign.go          # Signing functions
│   ├── verify.go        # Verification functions
│   └── lamport_test.go  # Tests
├── threshold/           # M-Chain MPC integration (LP-134)
│   ├── config.go        # Threshold configuration
│   ├── partial.go       # Partial signature generation
│   └── aggregate.go     # Signature aggregation
├── precompile/          # EVM precompile interface
│   └── contract.go      # Precompile implementation
├── docs/                # Documentation
│   └── whitepaper.md    # Threshold Lamport whitepaper
├── main.go              # CLI tool
├── go.mod               # Go module
└── Makefile             # Build automation
```

## Key Concepts

### Lamport Signatures
- 256-bit message → 256 preimages revealed (one per bit)
- Security: keccak256 preimage resistance (quantum-safe)
- One-time: Each key can only sign ONE message

### Threshold Lamport via MPC
- M-Chain MPC network holds shares of private key (LP-134)
- Each party reveals partial preimages
- Aggregation: XOR partials to get final signature
- On-chain: Standard Lamport verification (no precompile needed!)

### Key Chain
- Pre-generated sequence of one-time keys
- Each signature commits to nextPKH
- Enables continuous operation

## Usage

### Build & Test
```bash
make build     # Build CLI
make test      # Run tests
make bench     # Run benchmarks
```

### CLI
```bash
./bin/lamport keygen           # Generate key pair
./bin/lamport chain 10         # Generate 10-key chain
./bin/lamport threshold 3 5    # Demo 3-of-5 threshold
./bin/lamport benchmark        # Performance benchmarks
```

### Go Library
```go
import "github.com/luxfi/lamport/primitives"

// Generate key pair
kp, _ := primitives.GenerateKeyPair()

// Sign (one time only!)
message := primitives.Keccak256([]byte("Hello"))
sig, _ := primitives.Sign(kp.Private, message)

// Verify
valid := primitives.Verify(kp.Public, message, sig)
```

## Related Components

- **Corona** (`~/work/lux/corona`): Lattice-based threshold signatures for Lux-native
- **Standard** (`~/work/lux/standard`): Solidity contracts including SafeThresholdLamportModule
- **Threshold** (`~/work/lux/threshold`): General MPC protocols

## LPs

- **LP-4105**: Lamport OTS for Lux Safe
- **LP-4200**: Post-Quantum Cryptography Suite
- **LP-7324**: Corona Threshold Signatures
- **LP-3310**: Safe Multisig Standard

## Performance

| Operation | Latency (M1 Max) |
|-----------|------------------|
| KeyGen | ~1.2ms |
| Sign | ~0.8ms |
| Verify | ~0.6ms |
| Threshold (3-of-5) | ~0.3ms |

## Sizes

| Component | Size |
|-----------|------|
| Private Key | 16,384 bytes |
| Public Key | 16,384 bytes |
| Signature | 8,192 bytes |
| PKH | 32 bytes |
