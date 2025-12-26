// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.31;

import {Lamport} from "./Lamport.sol";

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

/// @title LamportSafe
/// @notice Safe module adaptor for Lamport signature execution
/// @author Lux Network Team
/// @dev Enables Safe transactions with quantum-resistant Lamport signatures.
///      Supports both single-signer and threshold (MPC) modes.
///
/// SECURITY:
/// - Domain separation: address(this) + chainId in message
/// - Canonical digest: safeTxHash computed on-chain
/// - Atomic key rotation after each signature
///
/// See: LP-4105 (Lamport OTS for Lux Safe)
contract LamportSafe {
    // =========================================================================
    // State
    // =========================================================================

    /// @notice Safe this module is attached to
    address public immutable safe;

    /// @notice Current Lamport public key hash
    bytes32 public pkh;

    /// @notice Whether module is initialized
    bool public initialized;

    /// @notice Transaction nonce
    uint256 public nonce;

    // =========================================================================
    // Events
    // =========================================================================

    event Initialized(bytes32 indexed pkh);
    event KeyRotated(bytes32 indexed oldPkh, bytes32 indexed newPkh);
    event Executed(bytes32 indexed txHash, uint256 nonce);

    // =========================================================================
    // Errors
    // =========================================================================

    error NotInitialized();
    error AlreadyInitialized();
    error OnlySafe();
    error InvalidPKH();
    error InvalidSignature();
    error ZeroAddress();
    error ZeroPKH();

    // =========================================================================
    // Modifiers
    // =========================================================================

    modifier onlySafe() {
        if (msg.sender != safe) revert OnlySafe();
        _;
    }

    modifier whenInitialized() {
        if (!initialized) revert NotInitialized();
        _;
    }

    // =========================================================================
    // Constructor
    // =========================================================================

    /// @param _safe Safe address this module is attached to
    constructor(address _safe) {
        if (_safe == address(0)) revert ZeroAddress();
        safe = _safe;
    }

    // =========================================================================
    // Initialization
    // =========================================================================

    /// @notice Initialize module with first public key hash
    /// @param firstPKH Hash of initial Lamport public key
    function init(bytes32 firstPKH) external onlySafe {
        if (initialized) revert AlreadyInitialized();
        if (firstPKH == bytes32(0)) revert ZeroPKH();

        pkh = firstPKH;
        initialized = true;
        emit Initialized(firstPKH);
    }

    // =========================================================================
    // Execution
    // =========================================================================

    /// @notice Execute Safe transaction with Lamport signature
    /// @param to Destination address
    /// @param value ETH value in wei
    /// @param data Call data
    /// @param operation 0=Call, 1=DelegateCall
    /// @param sig Lamport signature (256 preimages)
    /// @param pub Current public key (256x2 hashes)
    /// @param nextPKH Next public key hash for rotation
    /// @return success True if Safe execution succeeded
    function exec(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        bytes32[256] calldata sig,
        bytes32[2][256] calldata pub,
        bytes32 nextPKH
    ) external whenInitialized returns (bool success) {
        // 1. Verify public key matches stored PKH
        bytes32 actualPKH = Lamport.computePKHCalldata(pub);
        if (actualPKH != pkh) revert InvalidPKH();

        // 2. Compute safeTxHash ON-CHAIN (SECURITY CRITICAL)
        bytes32 safeTxHash = ISafe(safe).getTransactionHash(
            to, value, data, operation,
            0, 0, 0, address(0), payable(0), nonce
        );

        // 3. Domain-separated message
        uint256 m = Lamport.computeMessage(
            safeTxHash, nextPKH, address(this), block.chainid
        );

        // 4. Verify Lamport signature
        if (!Lamport.verify(m, sig, pub)) {
            revert InvalidSignature();
        }

        // 5. Rotate key and increment nonce
        bytes32 oldPkh = pkh;
        pkh = nextPKH;
        nonce++;

        emit KeyRotated(oldPkh, nextPKH);
        emit Executed(safeTxHash, nonce - 1);

        // 6. Execute via Safe
        success = ISafe(safe).execTransactionFromModule(
            to, value, data, ISafe.Operation(operation)
        );
    }

    /// @notice Execute Call operation (convenience)
    function execCall(
        address to,
        uint256 value,
        bytes calldata data,
        bytes32[256] calldata sig,
        bytes32[2][256] calldata pub,
        bytes32 nextPKH
    ) external returns (bool) {
        return this.exec(to, value, data, 0, sig, pub, nextPKH);
    }

    /// @notice Execute DelegateCall operation
    function execDelegateCall(
        address to,
        bytes calldata data,
        bytes32[256] calldata sig,
        bytes32[2][256] calldata pub,
        bytes32 nextPKH
    ) external returns (bool) {
        return this.exec(to, 0, data, 1, sig, pub, nextPKH);
    }

    // =========================================================================
    // View Functions
    // =========================================================================

    /// @notice Compute message hash for off-chain signing
    /// @param to Destination address
    /// @param value ETH value
    /// @param data Call data
    /// @param operation Operation type
    /// @param nextPKH Next public key hash
    /// @return m Message to sign (256 bits)
    function computeMessage(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        bytes32 nextPKH
    ) external view returns (uint256 m) {
        bytes32 safeTxHash = ISafe(safe).getTransactionHash(
            to, value, data, operation,
            0, 0, 0, address(0), payable(0), nonce
        );
        return Lamport.computeMessage(safeTxHash, nextPKH, address(this), block.chainid);
    }

    /// @notice Get current state
    /// @return _pkh Current public key hash
    /// @return _nonce Current nonce
    /// @return _initialized Whether initialized
    function getState() external view returns (
        bytes32 _pkh,
        uint256 _nonce,
        bool _initialized
    ) {
        return (pkh, nonce, initialized);
    }
}
