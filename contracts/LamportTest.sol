// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.31;

import {LamportLib} from "./LamportLib.sol";

/// @title LamportTest
/// @notice Test helper contract for Lamport signature verification
/// @author Lux Network Team
/// @dev Simple contract that stores a public key and verifies signatures
///
/// This contract is useful for:
/// - Testing Lamport signature generation and verification
/// - Demonstrating the one-time signature pattern
/// - Integration testing with off-chain signers
contract LamportTest {
    // ═══════════════════════════════════════════════════════════════════════
    // State
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice The stored public key
    bytes32[2][256] public pubKey;

    /// @notice Whether a public key has been set
    bool public pubKeySet;

    // ═══════════════════════════════════════════════════════════════════════
    // Events
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Emitted when a public key is set
    event PublicKeySet(bytes32 pkh);

    /// @notice Emitted when a signature is verified
    event SignatureVerified(bytes32 indexed message);

    // ═══════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Error when public key not set
    error PublicKeyNotSet();

    /// @notice Error when signature is invalid
    error InvalidSignature();

    // ═══════════════════════════════════════════════════════════════════════
    // Functions
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Set the public key for verification
    /// @param _pubKey The 256x2 array of public key hashes
    function setPubKey(bytes32[2][256] memory _pubKey) external {
        pubKey = _pubKey;
        pubKeySet = true;
        emit PublicKeySet(LamportLib.computePKH(_pubKey));
    }

    /// @notice Verify a signature and emit event if valid
    /// @param message The message that was signed
    /// @param signature Array of 256 bytes32 preimages
    function doSomething(bytes32 message, bytes32[] memory signature) external {
        if (!pubKeySet) revert PublicKeyNotSet();
        if (!LamportLib.verify(message, signature, pubKey)) revert InvalidSignature();
        emit SignatureVerified(message);
    }

    /// @notice Verify a signature (uint256 bits format)
    /// @param bits The message as uint256
    /// @param sig Array of 256 bytes preimages
    /// @param pub The public key (must match stored pubKey)
    function verifyBits(
        uint256 bits,
        bytes[256] calldata sig,
        bytes32[2][256] calldata pub
    ) external view returns (bool) {
        if (!pubKeySet) revert PublicKeyNotSet();
        // Verify provided pubKey matches stored (gas optimization: caller provides calldata)
        require(LamportLib.computePKH(pubKey) == keccak256(abi.encodePacked(pub)), "PKH mismatch");
        return LamportLib.verify_u256(bits, sig, pub);
    }

    /// @notice Get the PKH of the stored public key
    /// @return pkh The public key hash
    function getPKH() external view returns (bytes32) {
        return LamportLib.computePKH(pubKey);
    }
}
