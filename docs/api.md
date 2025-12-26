# API Reference

## LamportLib

Core library for Lamport signature verification.

### Functions

#### `verify(message, signature, publicKey)`

Standard verification with dynamic signature array.

```solidity
function verify(
    bytes32 message,
    bytes32[] memory signature,
    bytes32[2][256] memory publicKey
) internal pure returns (bool valid)
```

**Parameters:**
- `message` - The 32-byte message hash to verify
- `signature` - Array of 256 bytes32 preimages
- `publicKey` - 256×2 array of public key hashes

**Returns:** `true` if signature is valid

**Gas:** ~1.8M gas (memory-heavy)

---

#### `verify_u256(bits, sig, pub)`

Optimized verification with calldata arrays.

```solidity
function verify_u256(
    uint256 bits,
    bytes[256] calldata sig,
    bytes32[2][256] calldata pub
) internal pure returns (bool valid)
```

**Parameters:**
- `bits` - The 256-bit message as uint256
- `sig` - Array of 256 variable-length preimages
- `pub` - 256×2 array of public key hashes

**Returns:** `true` if signature is valid

**Gas:** ~280K gas

---

#### `verify_u256_mem(bits, sig, pub)`

Memory version for testing and internal use.

```solidity
function verify_u256_mem(
    uint256 bits,
    bytes[256] memory sig,
    bytes32[2][256] memory pub
) internal pure returns (bool valid)
```

---

#### `computePKH(publicKey)`

Compute the public key hash.

```solidity
function computePKH(
    bytes32[2][256] memory publicKey
) internal pure returns (bytes32 pkh)
```

**Returns:** `keccak256(abi.encodePacked(publicKey))`

---

#### `computeThresholdMessage(safeTxHash, nextPKH, module, chainId)`

Compute domain-separated message for threshold signing.

```solidity
function computeThresholdMessage(
    bytes32 safeTxHash,
    bytes32 nextPKH,
    address module,
    uint256 chainId
) internal pure returns (uint256 m)
```

**Parameters:**
- `safeTxHash` - The Safe transaction hash
- `nextPKH` - Hash of the next public key (for rotation)
- `module` - Module address (prevents cross-contract replay)
- `chainId` - Chain ID (prevents cross-chain replay)

**Returns:** Domain-separated 256-bit message

---

#### `getBit(data, index)`

Extract a single bit from a bytes32 value.

```solidity
function getBit(bytes32 data, uint256 index) internal pure returns (uint256 bit)
```

**Parameters:**
- `data` - The 32-byte value
- `index` - Bit index (0 = MSB of first byte)

**Returns:** 0 or 1

---

## LamportOptimized

Assembly-optimized external verifier contract.

### Functions

#### `verifyFast(bits, sig, pub)`

Ultra-optimized verification with fixed-size preimages.

```solidity
function verifyFast(
    uint256 bits,
    bytes32[256] calldata sig,
    bytes32[2][256] calldata pub
) external pure returns (bool valid)
```

**Gas:** ~390K gas (40% cheaper than standard)

**Features:**
- Uses bytes32[256] for simpler calldata layout
- Early exit on first mismatch
- Direct calldataload operations

---

#### `verifyUnrolled(bits, sig, pub)`

Hyper-optimized with 4x loop unrolling.

```solidity
function verifyUnrolled(
    uint256 bits,
    bytes32[256] calldata sig,
    bytes32[2][256] calldata pub
) external pure returns (bool valid)
```

**Gas:** ~380K gas (45% cheaper than standard)

**Features:**
- Processes 4 bits per iteration
- Reduced loop overhead
- Larger code size

---

#### `verifyBranchless(bits, sig, pub)`

Constant-time verification for side-channel resistance.

```solidity
function verifyBranchless(
    uint256 bits,
    bytes32[256] calldata sig,
    bytes32[2][256] calldata pub
) external pure returns (bool valid)
```

**Gas:** ~435K gas (constant regardless of result)

**Features:**
- No early exit
- Constant gas consumption
- Side-channel resistant

---

## LamportBase

Abstract base contract for Lamport-protected contracts.

### State Variables

```solidity
bytes32[2][256] public pubKey;
bool public initialized;
```

### Modifiers

#### `onlyLamportOwner(bits, sig)`

Requires valid Lamport signature.

```solidity
modifier onlyLamportOwner(
    uint256 bits,
    bytes[256] calldata sig
)
```

### Functions

#### `init(initialPubKey)`

Initialize with first public key.

```solidity
function init(bytes32[2][256] calldata initialPubKey) external
```

#### `getPKH()`

Get current public key hash.

```solidity
function getPKH() external view returns (bytes32)
```

---

## Events

### LamportTest

```solidity
event PublicKeySet(bytes32 pkh);
event SignatureVerified(bytes32 indexed message);
```

### LamportBase

```solidity
event Initialized(bytes32 indexed pkh);
```

---

## Errors

```solidity
error PublicKeyNotSet();
error InvalidSignature();
error AlreadyInitialized();
```
