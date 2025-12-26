# Gas Optimization

## Benchmark Results

All benchmarks run on Foundry with Solc 0.8.31, optimizer enabled (200 runs).

### Verification Gas Costs

| Function | Gas (Valid) | Gas (Invalid) | Notes |
|----------|------------|---------------|-------|
| `verify()` | ~1.8M | ~1.8M | Dynamic array, memory-heavy |
| `verify_u256()` | ~280K | Variable | bytes[256] calldata |
| `verifyFast()` | ~390K | Variable | bytes32[256] calldata |
| `verifyUnrolled()` | ~380K | Variable | 4x loop unrolling |
| `verifyBranchless()` | ~435K | ~435K | Constant gas |

### Key Observations

1. **Memory vs Calldata**: Using `calldata` instead of `memory` saves ~85% gas
2. **Fixed vs Dynamic**: `bytes32[256]` is 40% cheaper than `bytes[256]`
3. **Loop Unrolling**: Reduces gas by ~2-5% with 4x larger code
4. **Early Exit**: Saves gas on invalid signatures (except branchless)

## Optimization Techniques

### 1. Use Fixed-Size Preimages

If preimages are always 32 bytes, use `bytes32[256]` instead of `bytes[256]`:

```solidity
// Less optimal: variable-length preimages
function verify(bytes[256] calldata sig) ...

// More optimal: fixed-length preimages
function verify(bytes32[256] calldata sig) ...
```

**Savings**: ~40% gas reduction

### 2. Direct Calldata Access

Assembly provides direct access to calldata without copying:

```solidity
assembly ("memory-safe") {
    let preimage := calldataload(sigOffset)
    mstore(memPtr, preimage)
    let hash := keccak256(memPtr, 32)
}
```

**Savings**: Eliminates memory allocation overhead

### 3. Loop Unrolling

Process multiple iterations per loop to reduce overhead:

```solidity
for (i := 0; i < 256; i += 4) {
    // Process 4 elements
    verify(i)
    verify(i+1)
    verify(i+2)
    verify(i+3)
}
```

**Trade-off**: ~3% gas savings, 4x code size increase

### 4. Branchless Accumulation

For constant-time verification:

```solidity
let accumulator := 0
for (i := 0; i < 256; i++) {
    let mismatch := xor(hash, expected)
    accumulator := or(accumulator, mismatch)
}
valid := iszero(accumulator)
```

**Trade-off**: No early exit, constant gas regardless of result

## Signature Size Optimization

### Standard Format

```
Public Key:  16,384 bytes (256 × 2 × 32)
Signature:    8,192 bytes (256 × 32)
```

### Compressed Public Key Hash (PKH)

Store only the hash of the public key on-chain:

```solidity
bytes32 public pkh;  // 32 bytes instead of 16,384

function verify(sig, pub) {
    require(keccak256(abi.encodePacked(pub)) == pkh);
    // ... verification
}
```

**Trade-off**: Caller must provide full public key in calldata

## Gas Cost Breakdown

### keccak256 Operations

- 256 hash operations per verification
- Each keccak256(32 bytes): ~30 gas
- Total hashing: ~7,680 gas

### Memory Operations

- Writing preimage to memory: ~3 gas per word
- Total memory writes: ~768 gas

### Loop Overhead

- Standard loop: ~8 gas per iteration × 256 = ~2,048 gas
- Unrolled (4x): ~8 gas per iteration × 64 = ~512 gas

### Calldata Access

- calldataload: 3 gas per 32-byte word
- Total calldata reads: ~1,536 gas

## Recommendations

### Use Case Selection

| Use Case | Recommended Function | Reason |
|----------|---------------------|--------|
| Standard verification | `verifyFast()` | Best balance |
| Maximum gas savings | `verifyUnrolled()` | Lowest gas |
| Side-channel resistance | `verifyBranchless()` | Constant time |
| Testing/internal | `verify()` | Convenience |

### Calldata Optimization

1. Use `calldata` over `memory` when possible
2. Caller provides public key (not stored on-chain)
3. Batch multiple verifications if applicable

### Contract Design

1. Store only PKH (32 bytes) instead of full key (16KB)
2. Validate PKH match before verification
3. Consider proxy patterns for upgradability
