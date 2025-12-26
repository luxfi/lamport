# Lamport OTS - Solidity Contracts

Post-quantum secure Lamport one-time signatures for EVM chains.

## Overview

These contracts provide quantum-resistant signature verification using only `keccak256` hash operations. The key insight is that threshold control lives off-chain (T-Chain MPC), while on-chain verification is standard Lamport—**works on ANY EVM chain without precompiles!**

## Contracts

| Contract | Description |
|----------|-------------|
| `LamportLib.sol` | Core library with verify_u256, computePKH, computeThresholdMessage |
| `LamportVerifier.sol` | Standalone verifier for any EVM chain |
| `LamportModule.sol` | Safe module for threshold Lamport execution |
| `ILamportModule.sol` | Interface for Lamport modules |
| `LamportKeyRegistry.sol` | On-chain key chain management |

## Installation

### Foundry

```bash
forge install luxfi/lamport
```

### Hardhat/npm

```bash
npm install @luxfi/lamport-contracts
```

## Usage

### Direct Verification

```solidity
import {LamportLib} from "@luxfi/lamport/LamportLib.sol";

contract MyContract {
    function verifySignature(
        uint256 message,
        bytes[256] calldata sig,
        bytes32[2][256] calldata pub
    ) external pure returns (bool) {
        return LamportLib.verify_u256(message, sig, pub);
    }
}
```

### With PKH Storage

Store only the 32-byte PKH on-chain, verify against full public key:

```solidity
import {LamportLib} from "@luxfi/lamport/LamportLib.sol";

contract MyContract {
    bytes32 public pkh;

    function verifyWithPKH(
        uint256 message,
        bytes[256] calldata sig,
        bytes32[2][256] calldata pub
    ) external view returns (bool) {
        // Verify PKH matches
        if (LamportLib.computePKH(pub) != pkh) return false;

        // Verify signature
        return LamportLib.verify_u256(message, sig, pub);
    }
}
```

### Safe Module Integration

Deploy the LamportModule for any Gnosis Safe:

```solidity
// Deploy module
LamportModule module = new LamportModule(safeAddress);

// Initialize via Safe transaction
safe.execTransaction(
    address(module),
    0,
    abi.encodeCall(module.init, (initialPKH)),
    Enum.Operation.Call,
    // ... signatures
);

// Enable module on Safe
safe.enableModule(address(module));

// Execute via Lamport signature
module.execWithLamport(
    to,
    value,
    data,
    0, // Call operation
    sig,
    currentPub,
    nextPKH
);
```

## Gas Costs

| Operation | Gas |
|-----------|-----|
| verify_u256 | ~85,000 |
| computePKH | ~45,000 |
| computeThresholdMessage | ~500 |
| LamportModule.execWithLamport | ~150,000 |

*Note: With Lux precompile (0x020...006), verification drops to ~15,800 gas*

## Security Model

### Threshold Lamport via MPC

```
┌─────────────────────────────────────────────────────────────────────┐
│                    THRESHOLD LAMPORT ARCHITECTURE                   │
│                                                                     │
│  T-Chain MPC Network                    Remote EVM Chain           │
│  ┌─────────────────────────┐           ┌──────────────────────┐    │
│  │  Threshold Control      │  Single   │  Standard Lamport    │    │
│  │  (t-of-n signing)       │──Lamport──│  Verification        │    │
│  │                         │   Sig     │                      │    │
│  │  • DKG for shares       │           │  keccak256(sig[i])   │    │
│  │  • Partial signatures   │           │    == pub[i][bit]    │    │
│  │  • Aggregation          │           │                      │    │
│  └─────────────────────────┘           └──────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

### Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Key reuse | One-time keys + nextPKH rotation |
| Cross-chain replay | `block.chainid` in domain separator |
| Cross-contract replay | `address(this)` in domain separator |
| Coordinator equivocation | Compute safeTxHash ON-CHAIN |

## Testing

```bash
# Run Foundry tests
forge test

# Run with verbosity
forge test -vvv

# Gas report
forge test --gas-report
```

## Sizes

| Component | Size |
|-----------|------|
| Public Key (full) | 16,384 bytes |
| Signature | 8,192 bytes |
| PKH (stored) | 32 bytes |

## Related

- **Go Implementation**: `github.com/luxfi/lamport`
- **Ringtail (Lattice)**: `github.com/luxfi/ringtail`
- **LP-4105**: Lamport OTS for Lux Safe

## License

BSD-3-Clause
