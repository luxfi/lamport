// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.31;

import {Lamport} from "./Lamport.sol";

/// @title ISafe
/// @notice Minimal Safe interface
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

/// @title LamportThreshold
/// @notice Threshold Lamport signatures for Safe multisig
/// @author Lux Network Team
/// @dev T-Chain MPC controls ONE Lamport key off-chain. On-chain sees standard signature.
///
/// SECURITY MODEL:
/// - Threshold (t-of-n) enforced by T-Chain MPC network
/// - On-chain sees ONE standard Lamport signature
/// - Domain separation prevents replay attacks
/// - Atomic key rotation after each signature
///
/// See: LP-4105 (Lamport OTS for Lux Safe)
contract LamportThreshold {
    // =========================================================================
    // State
    // =========================================================================

    address public immutable safe;
    bytes32 public pkh;
    bool public initialized;
    uint256 public nonce;

    // =========================================================================
    // Events
    // =========================================================================

    event Initialized(bytes32 indexed pkh);
    event KeyRotated(bytes32 indexed oldPkh, bytes32 indexed newPkh);
    event Executed(bytes32 indexed txHash, bytes32 indexed nextPkh, uint256 nonce);

    // =========================================================================
    // Errors
    // =========================================================================

    error NotInitialized();
    error AlreadyInitialized();
    error OnlySafe();
    error InvalidPKH();
    error InvalidSignature();

    // =========================================================================
    // Modifiers
    // =========================================================================

    modifier onlySafe() {
        if (msg.sender != safe) revert OnlySafe();
        _;
    }

    // =========================================================================
    // Constructor
    // =========================================================================

    constructor(address _safe) {
        require(_safe != address(0), "zero address");
        safe = _safe;
    }

    // =========================================================================
    // Initialization
    // =========================================================================

    /// @notice Initialize with first PKH
    /// @param firstPKH Hash of initial public key
    function init(bytes32 firstPKH) external onlySafe {
        if (initialized) revert AlreadyInitialized();
        require(firstPKH != bytes32(0), "zero PKH");
        pkh = firstPKH;
        initialized = true;
        emit Initialized(firstPKH);
    }

    // =========================================================================
    // Execution
    // =========================================================================

    /// @notice Execute Safe transaction with threshold Lamport signature
    /// @param to Destination address
    /// @param value ETH value
    /// @param data Call data
    /// @param operation 0=Call, 1=DelegateCall
    /// @param sig Lamport signature (256 preimages)
    /// @param currentPub Current public key
    /// @param nextPKH Next public key hash (for rotation)
    function exec(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        bytes32[256] calldata sig,
        bytes32[2][256] calldata currentPub,
        bytes32 nextPKH
    ) external returns (bool success) {
        if (!initialized) revert NotInitialized();

        // 1. Verify current public key matches stored PKH
        bytes32 actualPKH = Lamport.computePKHCalldata(currentPub);
        if (actualPKH != pkh) revert InvalidPKH();

        // 2. Compute safeTxHash ON-CHAIN (SECURITY CRITICAL)
        bytes32 safeTxHash = ISafe(safe).getTransactionHash(
            to, value, data, operation,
            0, 0, 0, address(0), payable(0), nonce
        );

        // 3. Domain-separated message (prevents replay)
        uint256 m = Lamport.computeMessage(
            safeTxHash, nextPKH, address(this), block.chainid
        );

        // 4. Verify Lamport signature
        if (!Lamport.verify(m, sig, currentPub)) {
            revert InvalidSignature();
        }

        // 5. Rotate to next key
        bytes32 oldPkh = pkh;
        pkh = nextPKH;
        nonce++;

        emit KeyRotated(oldPkh, nextPKH);
        emit Executed(safeTxHash, nextPKH, nonce - 1);

        // 6. Execute via Safe
        success = ISafe(safe).execTransactionFromModule(
            to, value, data, ISafe.Operation(operation)
        );
    }

    /// @notice Convenience function for Call operation
    function execCall(
        address to,
        uint256 value,
        bytes calldata data,
        bytes32[256] calldata sig,
        bytes32[2][256] calldata currentPub,
        bytes32 nextPKH
    ) external returns (bool success) {
        return this.exec(to, value, data, 0, sig, currentPub, nextPKH);
    }

    // =========================================================================
    // View Functions
    // =========================================================================

    /// @notice Compute message hash for off-chain signing
    function computeMessageHash(
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
        m = Lamport.computeMessage(safeTxHash, nextPKH, address(this), block.chainid);
    }

    /// @notice Get current PKH
    function getPKH() external view returns (bytes32) {
        return pkh;
    }

    /// @notice Check if initialized
    function isInitialized() external view returns (bool) {
        return initialized;
    }

    /// @notice Get current nonce
    function getNonce() external view returns (uint256) {
        return nonce;
    }
}

/// @title LamportKeyChain
/// @notice Registry for managing pre-generated Lamport key chains
/// @dev For threshold setups, keys are pre-generated and registered
contract LamportKeyChain {
    // =========================================================================
    // Types
    // =========================================================================

    struct KeyChain {
        bytes32[] pkhs;
        uint256 currentIndex;
        address owner;
        bool active;
    }

    // =========================================================================
    // State
    // =========================================================================

    mapping(bytes32 => KeyChain) public keyChains;
    mapping(address => bytes32[]) public ownerChains;
    mapping(bytes32 => bool) public usedPKHs;
    uint256 public chainCount;

    // =========================================================================
    // Events
    // =========================================================================

    event ChainRegistered(bytes32 indexed chainId, address indexed owner, uint256 keyCount);
    event KeyUsed(bytes32 indexed chainId, bytes32 indexed pkh, uint256 index);
    event ChainDeactivated(bytes32 indexed chainId);

    // =========================================================================
    // Errors
    // =========================================================================

    error ChainNotFound();
    error NotChainOwner();
    error ChainNotActive();
    error ChainExhausted();
    error PKHAlreadyUsed();
    error InvalidPKH();
    error EmptyKeyArray();

    // =========================================================================
    // Registration
    // =========================================================================

    /// @notice Register a new key chain
    function registerKeyChain(bytes32[] calldata pkhs) external returns (bytes32 chainId) {
        if (pkhs.length == 0) revert EmptyKeyArray();

        for (uint256 i = 0; i < pkhs.length; i++) {
            if (pkhs[i] == bytes32(0)) revert InvalidPKH();
            if (usedPKHs[pkhs[i]]) revert PKHAlreadyUsed();
        }

        chainId = keccak256(abi.encodePacked(msg.sender, chainCount++, block.timestamp));

        KeyChain storage chain = keyChains[chainId];
        chain.pkhs = pkhs;
        chain.currentIndex = 0;
        chain.owner = msg.sender;
        chain.active = true;

        ownerChains[msg.sender].push(chainId);
        emit ChainRegistered(chainId, msg.sender, pkhs.length);
    }

    /// @notice Get current PKH for chain
    function getCurrentPKH(bytes32 chainId) external view returns (bytes32) {
        KeyChain storage chain = keyChains[chainId];
        if (!chain.active) revert ChainNotActive();
        if (chain.currentIndex >= chain.pkhs.length) revert ChainExhausted();
        return chain.pkhs[chain.currentIndex];
    }

    /// @notice Get next PKH for rotation commitment
    function getNextPKH(bytes32 chainId) external view returns (bytes32) {
        KeyChain storage chain = keyChains[chainId];
        if (!chain.active) revert ChainNotActive();

        uint256 nextIndex = chain.currentIndex + 1;
        if (nextIndex >= chain.pkhs.length) return bytes32(0);
        return chain.pkhs[nextIndex];
    }

    /// @notice Mark current key as used and advance
    function advanceKey(bytes32 chainId) external {
        KeyChain storage chain = keyChains[chainId];
        if (chain.owner != msg.sender) revert NotChainOwner();
        if (!chain.active) revert ChainNotActive();
        if (chain.currentIndex >= chain.pkhs.length) revert ChainExhausted();

        bytes32 usedPKH = chain.pkhs[chain.currentIndex];
        usedPKHs[usedPKH] = true;

        emit KeyUsed(chainId, usedPKH, chain.currentIndex);
        chain.currentIndex++;
    }

    /// @notice Get remaining keys
    function getRemainingKeys(bytes32 chainId) external view returns (uint256) {
        KeyChain storage chain = keyChains[chainId];
        if (chain.currentIndex >= chain.pkhs.length) return 0;
        return chain.pkhs.length - chain.currentIndex;
    }

    /// @notice Deactivate chain
    function deactivateChain(bytes32 chainId) external {
        KeyChain storage chain = keyChains[chainId];
        if (chain.owner != msg.sender) revert NotChainOwner();
        chain.active = false;
        emit ChainDeactivated(chainId);
    }

    /// @notice Get owner's chains
    function getOwnerChains(address owner) external view returns (bytes32[] memory) {
        return ownerChains[owner];
    }
}
