// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.31;

/// @title LamportOptimized
/// @notice Assembly-optimized Lamport signature verification
/// @author Lux Network Team
/// @dev Gas-optimized verification using inline assembly
///
/// Three verification modes:
/// - verify: Standard with early exit (~380k gas)
/// - verifyUnrolled: 4x loop unrolling (~370k gas)
/// - verifyConstantTime: No early exit, side-channel resistant (~430k gas)
///
/// See: LP-4105 (Lamport OTS for Lux Safe)
contract LamportOptimized {
    // =========================================================================
    // Standard Verification (Early Exit)
    // =========================================================================

    /// @notice Verify Lamport signature with early exit on failure
    /// @param bits The 256-bit message
    /// @param sig Array of 256 bytes32 preimages
    /// @param pub 256x2 array of public key hashes
    /// @return valid True if signature is valid
    function verify(
        uint256 bits,
        bytes32[256] calldata sig,
        bytes32[2][256] calldata pub
    ) external pure returns (bool valid) {
        bits; sig; pub;
        assembly ("memory-safe") {
            let memPtr := mload(0x40)
            let bitsVal := calldataload(0x04)
            valid := 1

            for { let i := 0 } lt(i, 256) { i := add(i, 1) } {
                let bitPos := sub(255, i)
                let bit := and(shr(bitPos, bitsVal), 1)
                let sigOffset := add(0x24, mul(i, 32))
                mstore(memPtr, calldataload(sigOffset))
                let hash := keccak256(memPtr, 32)
                let pubOffset := add(0x2024, add(mul(i, 64), mul(bit, 32)))
                if iszero(eq(hash, calldataload(pubOffset))) {
                    valid := 0
                    break
                }
            }
        }
    }

    // =========================================================================
    // Unrolled Verification (4x Loop Unrolling)
    // =========================================================================

    /// @notice Verify with 4x loop unrolling for reduced overhead
    /// @param bits The 256-bit message
    /// @param sig Array of 256 bytes32 preimages
    /// @param pub 256x2 array of public key hashes
    /// @return valid True if signature is valid
    function verifyUnrolled(
        uint256 bits,
        bytes32[256] calldata sig,
        bytes32[2][256] calldata pub
    ) external pure returns (bool valid) {
        bits; sig; pub;
        assembly ("memory-safe") {
            let memPtr := mload(0x40)
            let bitsVal := calldataload(0x04)
            valid := 1

            for { let i := 0 } lt(i, 256) { i := add(i, 4) } {
                // Iteration 0
                {
                    let bitPos := sub(255, i)
                    let bit := and(shr(bitPos, bitsVal), 1)
                    mstore(memPtr, calldataload(add(0x24, mul(i, 32))))
                    if iszero(eq(keccak256(memPtr, 32), calldataload(add(0x2024, add(mul(i, 64), mul(bit, 32)))))) {
                        valid := 0
                        break
                    }
                }
                // Iteration 1
                {
                    let j := add(i, 1)
                    let bit := and(shr(sub(255, j), bitsVal), 1)
                    mstore(memPtr, calldataload(add(0x24, mul(j, 32))))
                    if iszero(eq(keccak256(memPtr, 32), calldataload(add(0x2024, add(mul(j, 64), mul(bit, 32)))))) {
                        valid := 0
                        break
                    }
                }
                // Iteration 2
                {
                    let j := add(i, 2)
                    let bit := and(shr(sub(255, j), bitsVal), 1)
                    mstore(memPtr, calldataload(add(0x24, mul(j, 32))))
                    if iszero(eq(keccak256(memPtr, 32), calldataload(add(0x2024, add(mul(j, 64), mul(bit, 32)))))) {
                        valid := 0
                        break
                    }
                }
                // Iteration 3
                {
                    let j := add(i, 3)
                    let bit := and(shr(sub(255, j), bitsVal), 1)
                    mstore(memPtr, calldataload(add(0x24, mul(j, 32))))
                    if iszero(eq(keccak256(memPtr, 32), calldataload(add(0x2024, add(mul(j, 64), mul(bit, 32)))))) {
                        valid := 0
                        break
                    }
                }
            }
        }
    }

    // =========================================================================
    // Constant-Time Verification (Side-Channel Resistant)
    // =========================================================================

    /// @notice Verify without early exit for constant-time execution
    /// @dev Always processes all 256 elements regardless of result
    /// @param bits The 256-bit message
    /// @param sig Array of 256 bytes32 preimages
    /// @param pub 256x2 array of public key hashes
    /// @return valid True if ALL verifications pass
    function verifyConstantTime(
        uint256 bits,
        bytes32[256] calldata sig,
        bytes32[2][256] calldata pub
    ) external pure returns (bool valid) {
        bits; sig; pub;
        assembly ("memory-safe") {
            let memPtr := mload(0x40)
            let bitsVal := calldataload(0x04)
            let acc := 0

            for { let i := 0 } lt(i, 256) { i := add(i, 1) } {
                let bitPos := sub(255, i)
                let bit := and(shr(bitPos, bitsVal), 1)
                let sigOffset := add(0x24, mul(i, 32))
                mstore(memPtr, calldataload(sigOffset))
                let hash := keccak256(memPtr, 32)
                let pubOffset := add(0x2024, add(mul(i, 64), mul(bit, 32)))
                acc := or(acc, xor(hash, calldataload(pubOffset)))
            }

            valid := iszero(acc)
        }
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    /// @notice Compute PKH from public key
    /// @param pub 256x2 array of public key hashes
    /// @return pkh The keccak256 hash
    function computePKH(
        bytes32[2][256] calldata pub
    ) external pure returns (bytes32 pkh) {
        return keccak256(abi.encodePacked(pub));
    }
}
