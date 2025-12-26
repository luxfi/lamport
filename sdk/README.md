# @luxfi/lamport

Quantum-resistant Lamport One-Time Signatures for EVM smart contracts.

[![npm version](https://badge.fury.io/js/@luxfi%2Flamport.svg)](https://www.npmjs.com/package/@luxfi/lamport)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

## Features

- 🔐 **Quantum-resistant** - Uses only keccak256, secure against Grover's algorithm
- ⚡ **Gas-optimized** - Assembly verification at 164K gas (7.5x improvement)
- 🔒 **Constant-time** - Side-channel resistant verification variant
- 🏦 **Safe integration** - Gnosis Safe module with atomic key rotation
- 🤝 **Threshold support** - T-of-N MPC coordination for distributed signing
- 📦 **TypeScript SDK** - Complete key generation, signing, and verification

## Installation

```bash
# npm
npm install @luxfi/lamport viem

# pnpm
pnpm add @luxfi/lamport viem

# yarn
yarn add @luxfi/lamport viem
```

## Quick Start

### Key Generation

```typescript
import { generateKeyPair, generateKeyChain } from '@luxfi/lamport'

// Generate a single key pair
const keyPair = generateKeyPair()
console.log('PKH:', keyPair.pkh)

// Generate a key chain (100 pre-generated keys)
const keyChain = generateKeyChain(100)
```

### Signing

```typescript
import { sign, signWithRotation, keccak256, toBytes } from '@luxfi/lamport'

// Sign a message
const message = keccak256(toBytes('Hello, Quantum World!'))
const signature = sign(message, keyPair.privateKey)

// Sign with key rotation (recommended)
const { signature, nextPKH } = signWithRotation(
  message,
  currentKeyPair,
  nextKeyPair
)
```

### Verification

```typescript
import { verify, computePKH } from '@luxfi/lamport'

// Off-chain verification
const valid = verify(message, signature, publicKey)

// Compute PKH for on-chain registration
const pkh = computePKH(publicKey)
```

### Safe Integration

```typescript
import { prepareSafeTransaction } from '@luxfi/lamport'

const txData = prepareSafeTransaction(
  { to, value, data, operation },
  currentKeyPair,
  nextKeyPair,
  moduleAddress,
  chainId,
  safeTxHash
)

// Use txData.signature and txData.publicKey with LamportSafe contract
```

### Threshold Signing

```typescript
import {
  generateKeyShares,
  createSigningSession,
  signPartial,
  combineSignatures,
} from '@luxfi/lamport'

// Distributed key generation
const shares = generateKeyShares({
  threshold: 3,
  total: 5,
  signers: ['alice', 'bob', 'carol', 'dave', 'eve'],
})

// Create signing session
let session = createSigningSession(message, config)

// Each signer contributes their partial
const partial = signPartial(session, myShare)
session = addPartialSignature(session, partial)

// Combine when threshold reached
if (session.complete) {
  const signature = combineSignatures(session)
}
```

## Solidity Contracts

Import contracts directly:

```solidity
import "@luxfi/lamport/contracts/Lamport.sol";
import "@luxfi/lamport/contracts/LamportSafe.sol";
import "@luxfi/lamport/contracts/LamportThreshold.sol";
import "@luxfi/lamport/contracts/LamportOptimized.sol";
```

### Contract ABIs

```typescript
import {
  LamportVerifierAbi,
  LamportSafeAbi,
  LamportThresholdAbi,
  LamportOptimizedAbi,
} from '@luxfi/lamport'
```

## Gas Costs

| Method                    | Gas       | Constant Time |
| ------------------------- | --------- | ------------- |
| `Lamport.verifyMem`       | 1,231,432 | No            |
| `LamportOptimized.verify` | 163,848   | No            |
| `verifyUnrolled`          | 137,390   | No            |
| `verifyConstantTime`      | 145,051   | Yes           |

## Security

- **Quantum-resistant**: 128-bit security against Grover's algorithm
- **One-time use**: Each key can only sign ONE message
- **Domain separation**: Prevents cross-chain and cross-contract replay
- **Constant-time**: Optional side-channel resistant verification

⚠️ **WARNING**: Lamport keys are ONE-TIME USE. Never sign two different messages with the same key pair!

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    @luxfi/lamport                        │
├─────────────────────────────────────────────────────────┤
│  TypeScript SDK                                          │
│  ├── generateKeyPair() / generateKeyChain()             │
│  ├── sign() / signWithRotation()                        │
│  ├── verify() / computePKH()                            │
│  └── Threshold: generateKeyShares(), combineSignatures()│
├─────────────────────────────────────────────────────────┤
│  Solidity Contracts                                      │
│  ├── Lamport.sol        - Pure Solidity library         │
│  ├── LamportOptimized.sol - Assembly (164K gas)         │
│  ├── LamportSafe.sol    - Gnosis Safe module            │
│  └── LamportThreshold.sol - MPC key chain               │
└─────────────────────────────────────────────────────────┘
```

## References

- [Lamport (1979)](https://www.microsoft.com/en-us/research/publication/constructing-digital-signatures-one-way-function/) - Original Lamport OTS paper
- [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography) - FIPS 203-205
- [LP-4105](https://github.com/luxfi/lps) - Lux Proposal for Lamport signatures

## License

BSD-3-Clause © Lux Network Team
