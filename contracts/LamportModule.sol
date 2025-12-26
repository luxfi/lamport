// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.31;

import {LamportLib} from "./LamportLib.sol";
import {ILamportModule} from "./ILamportModule.sol";

/// @title ISafe
/// @notice Minimal Safe interface for module operations
interface ISafe {
    enum Operation { Call, DelegateCall }

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Operation operation
    ) external returns (bool success);

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);
}

/// @title LamportModule
/// @notice Safe module for threshold Lamport signature execution
/// @author Lux Network Team
/// @dev Threshold lives OFF-CHAIN (T-Chain MPC network jointly controls ONE Lamport key).
///      On-chain verifies a normal Lamport signature - no changes to verification logic.
///
/// SECURITY MODEL:
/// - Threshold property (t-of-n) enforced by T-Chain MPC network
/// - On-chain sees ONE standard Lamport signature
/// - Works on ANY EVM chain (no precompiles needed)
/// - Domain separation prevents replay attacks
///
/// ATTACK MITIGATIONS:
/// - Canonical digest: safeTxHash computed ON-CHAIN (never accept from coordinator)
/// - Domain separation: address(this) + block.chainid in message
/// - One-time keys: pkh = nextPKH rotation after each signature
/// - Init guard: only Safe can initialize
///
/// See: LP-4105 (Lamport OTS for Lux Safe)
contract LamportModule is ILamportModule {
    // ═══════════════════════════════════════════════════════════════════════
    // State
    // ═══════════════════════════════════════════════════════════════════════

    /// @inheritdoc ILamportModule
    address public immutable safe;

    /// @inheritdoc ILamportModule
    bytes32 public pkh;

    /// @inheritdoc ILamportModule
    bool public initialized;

    /// @inheritdoc ILamportModule
    uint256 public lamportNonce;

    // ═══════════════════════════════════════════════════════════════════════
    // Modifiers
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Restricts function to only be called by the Safe
    modifier onlySafe() {
        if (msg.sender != safe) revert OnlySafe();
        _;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Constructor
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Constructor
    /// @param _safe The Safe address this module is attached to
    constructor(address _safe) {
        require(_safe != address(0), "LamportModule: zero address");
        safe = _safe;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Initialization
    // ═══════════════════════════════════════════════════════════════════════

    /// @inheritdoc ILamportModule
    function init(bytes32 initialPkh) external onlySafe {
        if (initialized) revert AlreadyInitialized();
        require(initialPkh != bytes32(0), "LamportModule: zero PKH");
        pkh = initialPkh;
        initialized = true;
        emit LamportInitialized(initialPkh);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Execution
    // ═══════════════════════════════════════════════════════════════════════

    /// @inheritdoc ILamportModule
    function execWithLamport(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        bytes[256] calldata sig,
        bytes32[2][256] calldata currentPub,
        bytes32 nextPKH
    ) external returns (bool success) {
        if (!initialized) revert NotInitialized();

        // ═══════════════════════════════════════════════════════════════
        // STEP 1: Verify current public key matches stored hash
        // ═══════════════════════════════════════════════════════════════
        bytes32 actualPKH = LamportLib.computePKH(currentPub);
        if (actualPKH != pkh) {
            revert InvalidPublicKey();
        }

        // ═══════════════════════════════════════════════════════════════
        // STEP 2: Compute safeTxHash ON-CHAIN (SECURITY CRITICAL)
        // NEVER accept prepacked hash from coordinator!
        // ═══════════════════════════════════════════════════════════════
        bytes32 safeTxHash = ISafe(safe).getTransactionHash(
            to,
            value,
            data,
            operation,
            0,              // safeTxGas (0 for module execution)
            0,              // baseGas
            0,              // gasPrice
            address(0),     // gasToken
            payable(0),     // refundReceiver
            lamportNonce
        );

        // ═══════════════════════════════════════════════════════════════
        // STEP 3: Domain-separated message (prevents replay)
        // ═══════════════════════════════════════════════════════════════
        uint256 m = LamportLib.computeThresholdMessage(
            safeTxHash,
            nextPKH,
            address(this),   // Prevent cross-contract replay
            block.chainid    // Prevent cross-chain replay
        );

        // ═══════════════════════════════════════════════════════════════
        // STEP 4: Verify Lamport signature
        // ═══════════════════════════════════════════════════════════════
        if (!LamportLib.verify_u256(m, sig, currentPub)) {
            revert InvalidLamportSignature();
        }

        // ═══════════════════════════════════════════════════════════════
        // STEP 5: Rotate to next key (one-time property)
        // ═══════════════════════════════════════════════════════════════
        bytes32 oldPkh = pkh;
        pkh = nextPKH;
        lamportNonce++;

        emit LamportKeyRotated(oldPkh, nextPKH);
        emit LamportExecuted(safeTxHash, nextPKH, lamportNonce - 1);

        // ═══════════════════════════════════════════════════════════════
        // STEP 6: Execute via Safe
        // ═══════════════════════════════════════════════════════════════
        success = ISafe(safe).execTransactionFromModule(
            to,
            value,
            data,
            ISafe.Operation(operation)
        );
    }

    /// @notice Execute with Call operation (convenience function)
    /// @param to Destination address
    /// @param value ETH value
    /// @param data Call data
    /// @param sig Lamport signature
    /// @param currentPub Current public key
    /// @param nextPKH Next public key hash
    /// @return success True if execution succeeded
    function exec(
        address to,
        uint256 value,
        bytes calldata data,
        bytes[256] calldata sig,
        bytes32[2][256] calldata currentPub,
        bytes32 nextPKH
    ) external returns (bool success) {
        return this.execWithLamport(
            to,
            value,
            data,
            0, // Call operation
            sig,
            currentPub,
            nextPKH
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // View Functions
    // ═══════════════════════════════════════════════════════════════════════

    /// @inheritdoc ILamportModule
    function computeMessageHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        bytes32 nextPKH
    ) external view returns (uint256 m) {
        bytes32 safeTxHash = ISafe(safe).getTransactionHash(
            to,
            value,
            data,
            operation,
            0, 0, 0,
            address(0),
            payable(0),
            lamportNonce
        );

        m = LamportLib.computeThresholdMessage(
            safeTxHash,
            nextPKH,
            address(this),
            block.chainid
        );
    }

    /// @notice Get current PKH (alias for pkh())
    function getPKH() external view returns (bytes32) {
        return pkh;
    }

    /// @notice Check if module is initialized (alias)
    function isInitialized() external view returns (bool) {
        return initialized;
    }
}
