// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.31;

/// @title LamportBase
/// @notice Abstract base contract for Lamport signature verification
/// @author Lux Network Team
/// @dev Provides core Lamport functionality with initialization and modifier pattern
///
/// SECURITY MODEL:
/// - Each Lamport key can only sign ONE message (one-time property)
/// - Security based on keccak256 preimage resistance (quantum-safe)
/// - Key rotation via nextPKH commitment pattern
///
/// See: LP-4105 (Lamport OTS for Lux Safe)
abstract contract LamportBase {
    // ═══════════════════════════════════════════════════════════════════════
    // State
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Whether the contract has been initialized with a PKH
    bool public initialized;

    /// @notice Current Lamport public key hash
    bytes32 public pkh;

    // ═══════════════════════════════════════════════════════════════════════
    // Events
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Emitted when contract is initialized
    event LamportInitialized(bytes32 indexed initialPkh);

    /// @notice Emitted when key is rotated
    event LamportKeyRotated(bytes32 indexed oldPkh, bytes32 indexed newPkh);

    // ═══════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Error when trying to initialize twice
    error AlreadyInitialized();

    /// @notice Error when not yet initialized
    error NotInitialized();

    /// @notice Error when public key hash doesn't match
    error InvalidPublicKeyHash();

    /// @notice Error when signature verification fails
    error InvalidLamportSignature();

    // ═══════════════════════════════════════════════════════════════════════
    // Initialization
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Initialize with first Lamport public key hash
    /// @param firstPKH Hash of the initial Lamport public key
    function init(bytes32 firstPKH) public virtual {
        if (initialized) revert AlreadyInitialized();
        pkh = firstPKH;
        initialized = true;
        emit LamportInitialized(firstPKH);
    }

    /// @notice Get the current public key hash
    /// @return Current pkh
    function getPKH() public view returns (bytes32) {
        return pkh;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Core Verification
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Verify a Lamport signature (256-bit message)
    /// @dev Most gas-efficient verification method
    /// @param bits The 256-bit message to verify (as uint256)
    /// @param sig Array of 256 preimages (revealed private key halves)
    /// @param pub 256x2 array of public key hashes
    /// @return valid True if signature is valid
    function verify_u256(
        uint256 bits,
        bytes[256] calldata sig,
        bytes32[2][256] calldata pub
    ) public pure returns (bool valid) {
        unchecked {
            for (uint256 i; i < 256; i++) {
                if (
                    pub[i][((bits & (1 << (255 - i))) > 0) ? 1 : 0] !=
                    keccak256(sig[i])
                ) return false;
            }
            return true;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Modifier
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Modifier to verify Lamport signature and rotate key
    /// @dev Validates signature, then updates pkh to nextPKH
    /// @param currentPub Current public key (must hash to stored pkh)
    /// @param sig Lamport signature (256 preimages)
    /// @param nextPKH Hash of next public key (for rotation)
    /// @param prepacked Additional data to include in message (context-specific)
    modifier onlyLamportOwner(
        bytes32[2][256] calldata currentPub,
        bytes[256] calldata sig,
        bytes32 nextPKH,
        bytes memory prepacked
    ) {
        // 1. Must be initialized
        if (!initialized) revert NotInitialized();

        // 2. Verify current public key matches stored hash
        if (keccak256(abi.encodePacked(currentPub)) != pkh) {
            revert InvalidPublicKeyHash();
        }

        // 3. Compute message: hash of (prepacked data + nextPKH)
        uint256 message = uint256(keccak256(abi.encodePacked(prepacked, nextPKH)));

        // 4. Verify Lamport signature
        if (!verify_u256(message, sig, currentPub)) {
            revert InvalidLamportSignature();
        }

        // 5. Rotate to next key
        bytes32 oldPkh = pkh;
        pkh = nextPKH;
        emit LamportKeyRotated(oldPkh, nextPKH);

        _;
    }
}
