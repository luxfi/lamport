// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.31;

/// @title LamportLib
/// @notice Library for Lamport one-time signature verification
/// @author Lux Network Team
/// @dev Provides quantum-resistant signature verification using only keccak256
///
/// SECURITY MODEL:
/// - Each Lamport key can only sign ONE message (one-time property)
/// - Security based on keccak256 preimage resistance (quantum-safe)
/// - 256-bit message → 256 revealed preimages
///
/// See: LP-4105 (Lamport OTS for Lux Safe)
library LamportLib {
    /// @notice Verify a Lamport signature (uint256 bits format, calldata)
    /// @dev Standard verification method for external calls
    /// @param bits The 256-bit message to verify (as uint256)
    /// @param sig Array of 256 preimages (the revealed private key halves)
    /// @param pub 256x2 array of public key hashes
    /// @return valid True if signature is valid
    function verify_u256(
        uint256 bits,
        bytes[256] calldata sig,
        bytes32[2][256] calldata pub
    ) internal pure returns (bool valid) {
        unchecked {
            for (uint256 i; i < 256; i++) {
                // Select pub[i][0] if bit is 0, pub[i][1] if bit is 1
                // Bit ordering: MSB first (bit 0 = leftmost)
                uint256 bit = ((bits & (1 << (255 - i))) > 0) ? 1 : 0;

                // Verify keccak256(sig[i]) == pub[i][bit]
                if (keccak256(sig[i]) != pub[i][bit]) {
                    return false;
                }
            }
            return true;
        }
    }

    /// @notice Verify a Lamport signature (uint256 bits format, memory)
    /// @dev Memory version for internal use and testing
    /// @param bits The 256-bit message to verify (as uint256)
    /// @param sig Array of 256 preimages (the revealed private key halves)
    /// @param pub 256x2 array of public key hashes
    /// @return valid True if signature is valid
    function verify_u256_mem(
        uint256 bits,
        bytes[256] memory sig,
        bytes32[2][256] memory pub
    ) internal pure returns (bool valid) {
        unchecked {
            for (uint256 i; i < 256; i++) {
                uint256 bit = ((bits & (1 << (255 - i))) > 0) ? 1 : 0;
                if (keccak256(sig[i]) != pub[i][bit]) {
                    return false;
                }
            }
            return true;
        }
    }

    /// @notice Verify a Lamport signature (bytes32 message format)
    /// @param message The 32-byte message hash to verify
    /// @param signature Array of 256 bytes32 values (revealed preimages)
    /// @param publicKey 256x2 array of bytes32 (public key hashes)
    /// @return valid True if signature is valid
    /// @dev Uses abi.encodePacked for raw bytes32 hashing (NOT abi.encode!)
    function verify(
        bytes32 message,
        bytes32[] memory signature,
        bytes32[2][256] memory publicKey
    ) internal pure returns (bool valid) {
        require(signature.length == 256, "LamportLib: invalid signature length");

        uint256 bits = uint256(message);
        for (uint256 i = 0; i < 256; i++) {
            uint256 bit = (bits >> (255 - i)) & 1;
            // CRITICAL: Use abi.encodePacked, NOT abi.encode
            // abi.encode adds a 32-byte length prefix which breaks verification
            if (keccak256(abi.encodePacked(signature[i])) != publicKey[i][bit]) {
                return false;
            }
        }
        return true;
    }

    /// @notice Compute public key hash from public key array
    /// @param publicKey 256x2 array of bytes32 (the public key hashes)
    /// @return pkh The keccak256 hash of the packed public key
    function computePKH(
        bytes32[2][256] memory publicKey
    ) internal pure returns (bytes32 pkh) {
        return keccak256(abi.encodePacked(publicKey));
    }

    /// @notice Compute domain-separated message for threshold signing
    /// @dev Matches the Go implementation in threshold/config.go
    /// @param safeTxHash The Safe transaction hash
    /// @param nextPKH Hash of next public key (for rotation)
    /// @param module The module address (prevents cross-contract replay)
    /// @param chainId The chain ID (prevents cross-chain replay)
    /// @return m The domain-separated message to sign (256 bits)
    function computeThresholdMessage(
        bytes32 safeTxHash,
        bytes32 nextPKH,
        address module,
        uint256 chainId
    ) internal pure returns (uint256 m) {
        return uint256(keccak256(abi.encodePacked(
            safeTxHash,
            nextPKH,
            module,
            chainId
        )));
    }

    /// @notice Extract a single bit from a bytes32 value
    /// @param data The 32-byte value
    /// @param index Bit index (0 = MSB of first byte)
    /// @return bit The bit value (0 or 1)
    function getBit(bytes32 data, uint256 index) internal pure returns (uint256 bit) {
        require(index < 256, "LamportLib: bit index out of range");
        return (uint256(data) >> (255 - index)) & 1;
    }
}
