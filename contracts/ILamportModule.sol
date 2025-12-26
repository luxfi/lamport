// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.31;

/// @title ILamportModule
/// @notice Interface for Lamport signature Safe modules
/// @author Lux Network Team
interface ILamportModule {
    // ═══════════════════════════════════════════════════════════════════════
    // Events
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Emitted when Lamport key is rotated
    event LamportKeyRotated(bytes32 indexed oldPkh, bytes32 indexed newPkh);

    /// @notice Emitted when a transaction is executed with Lamport signature
    event LamportExecuted(
        bytes32 indexed safeTxHash,
        bytes32 indexed nextPkh,
        uint256 nonce
    );

    /// @notice Emitted when module is initialized
    event LamportInitialized(bytes32 indexed initialPkh);

    // ═══════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Error when module is not initialized
    error NotInitialized();

    /// @notice Error when module is already initialized
    error AlreadyInitialized();

    /// @notice Error when caller is not the Safe
    error OnlySafe();

    /// @notice Error when public key doesn't match stored hash
    error InvalidPublicKey();

    /// @notice Error when Lamport signature is invalid
    error InvalidLamportSignature();

    // ═══════════════════════════════════════════════════════════════════════
    // View Functions
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Get the Safe address this module is attached to
    function safe() external view returns (address);

    /// @notice Get current public key hash
    function pkh() external view returns (bytes32);

    /// @notice Check if module is initialized
    function initialized() external view returns (bool);

    /// @notice Get current Lamport nonce
    function lamportNonce() external view returns (uint256);

    /// @notice Compute the message hash that should be signed
    /// @param to Destination address
    /// @param value ETH value
    /// @param data Call data
    /// @param operation Operation type (0=Call, 1=DelegateCall)
    /// @param nextPKH Next public key hash
    /// @return m The message hash to sign (256 bits)
    function computeMessageHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        bytes32 nextPKH
    ) external view returns (uint256 m);

    // ═══════════════════════════════════════════════════════════════════════
    // Mutating Functions
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Initialize with first Lamport public key hash
    /// @param initialPkh Hash of initial Lamport public key
    function init(bytes32 initialPkh) external;

    /// @notice Execute Safe transaction with Lamport signature
    /// @param to Destination address
    /// @param value ETH value in wei
    /// @param data Call data
    /// @param operation 0 = Call, 1 = DelegateCall
    /// @param sig Lamport signature (bytes[256])
    /// @param currentPub Current public key (bytes32[2][256])
    /// @param nextPKH Hash of next public key (for rotation)
    /// @return success True if execution succeeded
    function execWithLamport(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        bytes[256] calldata sig,
        bytes32[2][256] calldata currentPub,
        bytes32 nextPKH
    ) external returns (bool success);
}
