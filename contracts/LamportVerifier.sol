// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.31;

import {LamportLib} from "./LamportLib.sol";

/// @title LamportVerifier
/// @notice Standalone Lamport signature verifier contract
/// @author Lux Network Team
/// @dev Deploy this on any EVM chain for Lamport verification
///
/// This contract provides:
/// - PKH-based verification (store 32 bytes, verify against full key)
/// - Direct verification with full public key
/// - Key rotation tracking
///
/// See: LP-4105 (Lamport OTS for Lux Safe)
contract LamportVerifier {
    // ═══════════════════════════════════════════════════════════════════════
    // Events
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Emitted when a signature is verified
    event SignatureVerified(
        bytes32 indexed messageHash,
        bytes32 indexed pkh,
        bool valid
    );

    // ═══════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Error when public key doesn't match expected PKH
    error InvalidPublicKey(bytes32 expected, bytes32 actual);

    /// @notice Error when signature verification fails
    error InvalidSignature();

    // ═══════════════════════════════════════════════════════════════════════
    // Verification Functions
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Verify a Lamport signature with uint256 message format
    /// @param bits The 256-bit message (as uint256)
    /// @param sig Array of 256 preimages
    /// @param pub 256x2 array of public key hashes
    /// @return valid True if signature is valid
    function verify(
        uint256 bits,
        bytes[256] calldata sig,
        bytes32[2][256] calldata pub
    ) external pure returns (bool valid) {
        return LamportLib.verify_u256(bits, sig, pub);
    }

    /// @notice Verify with PKH check (ensures public key matches stored hash)
    /// @param bits The 256-bit message (as uint256)
    /// @param sig Array of 256 preimages
    /// @param pub 256x2 array of public key hashes
    /// @param expectedPKH Expected public key hash
    /// @return valid True if signature is valid AND PKH matches
    function verifyWithPKH(
        uint256 bits,
        bytes[256] calldata sig,
        bytes32[2][256] calldata pub,
        bytes32 expectedPKH
    ) external pure returns (bool valid) {
        // First verify PKH
        bytes32 actualPKH = LamportLib.computePKH(pub);
        if (actualPKH != expectedPKH) {
            return false;
        }

        // Then verify signature
        return LamportLib.verify_u256(bits, sig, pub);
    }

    /// @notice Verify a threshold Lamport signature with domain separation
    /// @param safeTxHash The Safe transaction hash
    /// @param nextPKH Hash of next public key
    /// @param sig Array of 256 preimages
    /// @param pub 256x2 array of public key hashes
    /// @param expectedPKH Expected current public key hash
    /// @return valid True if signature is valid
    function verifyThreshold(
        bytes32 safeTxHash,
        bytes32 nextPKH,
        bytes[256] calldata sig,
        bytes32[2][256] calldata pub,
        bytes32 expectedPKH
    ) external view returns (bool valid) {
        // Verify PKH
        bytes32 actualPKH = LamportLib.computePKH(pub);
        if (actualPKH != expectedPKH) {
            return false;
        }

        // Compute domain-separated message
        uint256 m = LamportLib.computeThresholdMessage(
            safeTxHash,
            nextPKH,
            address(this),
            block.chainid
        );

        // Verify signature
        return LamportLib.verify_u256(m, sig, pub);
    }

    /// @notice Compute PKH from public key (view function for off-chain use)
    /// @param pub 256x2 array of public key hashes
    /// @return pkh The keccak256 hash of the public key
    function computePKH(
        bytes32[2][256] calldata pub
    ) external pure returns (bytes32 pkh) {
        return LamportLib.computePKH(pub);
    }

    /// @notice Compute threshold message hash (for off-chain signing)
    /// @param safeTxHash The Safe transaction hash
    /// @param nextPKH Hash of next public key
    /// @return m The message to sign (as uint256)
    function computeMessage(
        bytes32 safeTxHash,
        bytes32 nextPKH
    ) external view returns (uint256 m) {
        return LamportLib.computeThresholdMessage(
            safeTxHash,
            nextPKH,
            address(this),
            block.chainid
        );
    }
}
