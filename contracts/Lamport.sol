// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.31;

/// @title Lamport
/// @notice Pure Solidity implementation of Lamport one-time signatures
/// @author Lux Network Team
/// @dev Quantum-resistant signatures using only keccak256
///
/// SECURITY MODEL:
/// - Each key can only sign ONE message (one-time property)
/// - Security based on keccak256 preimage resistance
/// - 256-bit message -> 256 revealed preimages
///
/// See: LP-4105 (Lamport OTS for Lux Safe)
library Lamport {
    // =========================================================================
    // Core Verification
    // =========================================================================

    /// @notice Verify a Lamport signature (calldata)
    /// @param bits The 256-bit message to verify (as uint256)
    /// @param sig Array of 256 preimages (32 bytes each)
    /// @param pub 256x2 array of public key hashes
    /// @return valid True if signature is valid
    function verify(uint256 bits, bytes32[256] calldata sig, bytes32[2][256] calldata pub)
        internal
        pure
        returns (bool valid)
    {
        unchecked {
            for (uint256 i; i < 256; ++i) {
                uint256 bit = (bits >> (255 - i)) & 1;
                if (keccak256(abi.encodePacked(sig[i])) != pub[i][bit]) {
                    return false;
                }
            }
            return true;
        }
    }

    /// @notice Verify a Lamport signature (memory)
    /// @param bits The 256-bit message to verify (as uint256)
    /// @param sig Array of 256 preimages (32 bytes each)
    /// @param pub 256x2 array of public key hashes
    /// @return valid True if signature is valid
    function verifyMem(uint256 bits, bytes32[256] memory sig, bytes32[2][256] memory pub)
        internal
        pure
        returns (bool valid)
    {
        unchecked {
            for (uint256 i; i < 256; ++i) {
                uint256 bit = (bits >> (255 - i)) & 1;
                if (keccak256(abi.encodePacked(sig[i])) != pub[i][bit]) {
                    return false;
                }
            }
            return true;
        }
    }

    /// @notice Verify with dynamic signature array (for compatibility)
    /// @param message The 32-byte message hash
    /// @param signature Array of 256 bytes32 preimages
    /// @param publicKey 256x2 array of public key hashes
    /// @return valid True if signature is valid
    function verifyDynamic(
        bytes32 message,
        bytes32[] memory signature,
        bytes32[2][256] memory publicKey
    ) internal pure returns (bool valid) {
        require(signature.length == 256, "Lamport: invalid sig length");
        uint256 bits = uint256(message);
        unchecked {
            for (uint256 i; i < 256; ++i) {
                uint256 bit = (bits >> (255 - i)) & 1;
                if (keccak256(abi.encodePacked(signature[i])) != publicKey[i][bit]) {
                    return false;
                }
            }
            return true;
        }
    }

    // =========================================================================
    // Key Operations
    // =========================================================================

    /// @notice Compute public key hash from public key array
    /// @param publicKey 256x2 array of bytes32
    /// @return pkh The keccak256 hash of the packed public key
    function computePKH(bytes32[2][256] memory publicKey) internal pure returns (bytes32 pkh) {
        return keccak256(abi.encodePacked(publicKey));
    }

    /// @notice Compute PKH from calldata (gas optimized)
    /// @param publicKey 256x2 array of bytes32
    /// @return pkh The keccak256 hash
    function computePKHCalldata(bytes32[2][256] calldata publicKey)
        internal
        pure
        returns (bytes32 pkh)
    {
        return keccak256(abi.encodePacked(publicKey));
    }

    // =========================================================================
    // Domain Separation
    // =========================================================================

    /// @notice Compute domain-separated message for threshold signing
    /// @dev Prevents replay across chains and contracts
    /// @param txHash The transaction hash
    /// @param nextPKH Hash of next public key (for rotation)
    /// @param module The module address
    /// @param chainId The chain ID
    /// @return m The domain-separated message (256 bits)
    function computeMessage(bytes32 txHash, bytes32 nextPKH, address module, uint256 chainId)
        internal
        pure
        returns (uint256 m)
    {
        return uint256(keccak256(abi.encodePacked(txHash, nextPKH, module, chainId)));
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    /// @notice Extract a single bit from a bytes32 value
    /// @param data The 32-byte value
    /// @param index Bit index (0 = MSB)
    /// @return bit The bit value (0 or 1)
    function getBit(bytes32 data, uint256 index) internal pure returns (uint256 bit) {
        require(index < 256, "Lamport: index out of range");
        return (uint256(data) >> (255 - index)) & 1;
    }
}

/// @title LamportVerifier
/// @notice Standalone verifier contract using Lamport library
/// @dev Deploy for on-chain verification without Safe integration
contract LamportVerifier {
    using Lamport for *;

    /// @notice Current public key hash
    bytes32 public pkh;

    /// @notice Whether initialized
    bool public initialized;

    event Initialized(bytes32 indexed pkh);
    event KeyRotated(bytes32 indexed oldPkh, bytes32 indexed newPkh);
    event Verified(bytes32 indexed message, bool valid);

    error AlreadyInitialized();
    error NotInitialized();
    error InvalidPKH();
    error InvalidSignature();

    /// @notice Initialize with first PKH
    /// @param firstPKH Hash of initial public key
    function init(bytes32 firstPKH) external {
        if (initialized) revert AlreadyInitialized();
        require(firstPKH != bytes32(0), "zero PKH");
        pkh = firstPKH;
        initialized = true;
        emit Initialized(firstPKH);
    }

    /// @notice Verify signature matches stored PKH
    /// @param bits Message to verify
    /// @param sig Signature (256 preimages)
    /// @param pub Public key (must hash to stored PKH)
    /// @return valid True if valid
    function verify(uint256 bits, bytes32[256] calldata sig, bytes32[2][256] calldata pub)
        external
        view
        returns (bool valid)
    {
        if (!initialized) revert NotInitialized();
        if (Lamport.computePKHCalldata(pub) != pkh) return false;
        return Lamport.verify(bits, sig, pub);
    }

    /// @notice Verify and rotate to next key
    /// @param bits Message to verify
    /// @param sig Signature
    /// @param pub Current public key
    /// @param nextPKH Next public key hash
    function verifyAndRotate(
        uint256 bits,
        bytes32[256] calldata sig,
        bytes32[2][256] calldata pub,
        bytes32 nextPKH
    ) external {
        if (!initialized) revert NotInitialized();
        if (Lamport.computePKHCalldata(pub) != pkh) revert InvalidPKH();
        if (!Lamport.verify(bits, sig, pub)) revert InvalidSignature();

        bytes32 oldPkh = pkh;
        pkh = nextPKH;
        emit KeyRotated(oldPkh, nextPKH);
    }

    /// @notice Compute PKH from public key
    function computePKH(bytes32[2][256] calldata pub) external pure returns (bytes32) {
        return Lamport.computePKHCalldata(pub);
    }

    /// @notice Compute domain-separated message
    function computeMessage(bytes32 txHash, bytes32 nextPKH) external view returns (uint256) {
        return Lamport.computeMessage(txHash, nextPKH, address(this), block.chainid);
    }
}
