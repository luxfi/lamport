# Lamport OTS Documentation

Quantum-resistant one-time signatures for Lux Network.

## Quick Start

```bash
# Install dependencies
cd contracts && forge install

# Run tests
forge test -vvv

# Run benchmarks
forge test --gas-report
```

## Table of Contents

1. [Overview](./overview.md) - What are Lamport signatures?
2. [API Reference](./api.md) - Contract interfaces and functions
3. [Security Model](./security.md) - Threat model and guarantees
4. [Gas Optimization](./gas.md) - Performance characteristics
5. [Integration Guide](./integration.md) - How to use in your project
6. [Threshold Signing](./threshold.md) - MPC-based multi-party signatures

## Architecture

```
lamport/
├── contracts/
│   ├── LamportLib.sol       # Core verification library
│   ├── LamportOptimized.sol # Assembly-optimized verifier
│   ├── LamportBase.sol      # Abstract base contract
│   ├── LamportTest.sol      # Test helper contract
│   └── test/
│       └── LamportLib.t.sol # Comprehensive test suite
├── primitives/              # Go implementation
├── threshold/               # MPC threshold signing
└── docs/                    # This documentation
```

## License

BSD-3-Clause
