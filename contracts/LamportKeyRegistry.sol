// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.31;

import {LamportLib} from "./LamportLib.sol";

/// @title LamportKeyRegistry
/// @notice Registry for managing Lamport key chains
/// @author Lux Network Team
/// @dev Stores PKH chains for entities that need multiple one-time keys
///
/// This contract provides:
/// - Pre-registration of key chains (sequence of PKHs)
/// - Key usage tracking (prevents reuse)
/// - Automatic advancement through key chain
///
/// See: LP-4105 (Lamport OTS for Lux Safe)
contract LamportKeyRegistry {
    // ═══════════════════════════════════════════════════════════════════════
    // Types
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Key chain entry
    struct KeyChain {
        bytes32[] pkhs;          // Array of public key hashes
        uint256 currentIndex;    // Current (unused) key index
        uint256 usedCount;       // Number of keys used
        address owner;           // Owner who can use these keys
        bool active;             // Whether chain is active
    }

    // ═══════════════════════════════════════════════════════════════════════
    // State
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Key chains by ID
    mapping(bytes32 => KeyChain) public keyChains;

    /// @notice Chain IDs owned by address
    mapping(address => bytes32[]) public ownerChains;

    /// @notice Used PKHs (prevent reuse across chains)
    mapping(bytes32 => bool) public usedPKHs;

    /// @notice Chain counter for unique IDs
    uint256 public chainCount;

    // ═══════════════════════════════════════════════════════════════════════
    // Events
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Emitted when a new key chain is registered
    event KeyChainRegistered(
        bytes32 indexed chainId,
        address indexed owner,
        uint256 keyCount
    );

    /// @notice Emitted when a key is used
    event KeyUsed(
        bytes32 indexed chainId,
        bytes32 indexed pkh,
        uint256 index
    );

    /// @notice Emitted when a key chain is deactivated
    event KeyChainDeactivated(bytes32 indexed chainId);

    // ═══════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Chain not found
    error ChainNotFound();

    /// @notice Not chain owner
    error NotChainOwner();

    /// @notice Chain not active
    error ChainNotActive();

    /// @notice Chain exhausted (no more keys)
    error ChainExhausted();

    /// @notice PKH already used
    error PKHAlreadyUsed();

    /// @notice Invalid PKH (zero)
    error InvalidPKH();

    /// @notice Empty key array
    error EmptyKeyArray();

    // ═══════════════════════════════════════════════════════════════════════
    // Registration
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Register a new key chain
    /// @param pkhs Array of public key hashes in order of use
    /// @return chainId The unique chain identifier
    function registerKeyChain(
        bytes32[] calldata pkhs
    ) external returns (bytes32 chainId) {
        if (pkhs.length == 0) revert EmptyKeyArray();

        // Verify no PKHs are already used and none are zero
        for (uint256 i = 0; i < pkhs.length; i++) {
            if (pkhs[i] == bytes32(0)) revert InvalidPKH();
            if (usedPKHs[pkhs[i]]) revert PKHAlreadyUsed();
        }

        // Generate chain ID
        chainId = keccak256(abi.encodePacked(
            msg.sender,
            chainCount++,
            block.timestamp
        ));

        // Create chain
        KeyChain storage chain = keyChains[chainId];
        chain.pkhs = pkhs;
        chain.currentIndex = 0;
        chain.usedCount = 0;
        chain.owner = msg.sender;
        chain.active = true;

        ownerChains[msg.sender].push(chainId);

        emit KeyChainRegistered(chainId, msg.sender, pkhs.length);
    }

    /// @notice Get current PKH for a chain
    /// @param chainId The chain identifier
    /// @return currentPKH The current (unused) PKH
    function getCurrentPKH(
        bytes32 chainId
    ) external view returns (bytes32 currentPKH) {
        KeyChain storage chain = keyChains[chainId];
        if (!chain.active) revert ChainNotActive();
        if (chain.currentIndex >= chain.pkhs.length) revert ChainExhausted();
        return chain.pkhs[chain.currentIndex];
    }

    /// @notice Get next PKH for a chain (for rotation commitment)
    /// @param chainId The chain identifier
    /// @return nextPKH The next PKH (or zero if last key)
    function getNextPKH(
        bytes32 chainId
    ) external view returns (bytes32 nextPKH) {
        KeyChain storage chain = keyChains[chainId];
        if (!chain.active) revert ChainNotActive();

        uint256 nextIndex = chain.currentIndex + 1;
        if (nextIndex >= chain.pkhs.length) {
            return bytes32(0); // No more keys after this
        }
        return chain.pkhs[nextIndex];
    }

    /// @notice Mark current key as used and advance
    /// @param chainId The chain identifier
    /// @dev Only callable by chain owner
    function advanceKey(bytes32 chainId) external {
        KeyChain storage chain = keyChains[chainId];
        if (chain.owner != msg.sender) revert NotChainOwner();
        if (!chain.active) revert ChainNotActive();
        if (chain.currentIndex >= chain.pkhs.length) revert ChainExhausted();

        bytes32 usedPKH = chain.pkhs[chain.currentIndex];
        usedPKHs[usedPKH] = true;

        emit KeyUsed(chainId, usedPKH, chain.currentIndex);

        chain.currentIndex++;
        chain.usedCount++;
    }

    /// @notice Get remaining keys in chain
    /// @param chainId The chain identifier
    /// @return remaining Number of unused keys
    function getRemainingKeys(
        bytes32 chainId
    ) external view returns (uint256 remaining) {
        KeyChain storage chain = keyChains[chainId];
        if (chain.currentIndex >= chain.pkhs.length) return 0;
        return chain.pkhs.length - chain.currentIndex;
    }

    /// @notice Deactivate a key chain
    /// @param chainId The chain identifier
    /// @dev Only callable by chain owner
    function deactivateChain(bytes32 chainId) external {
        KeyChain storage chain = keyChains[chainId];
        if (chain.owner != msg.sender) revert NotChainOwner();
        chain.active = false;
        emit KeyChainDeactivated(chainId);
    }

    /// @notice Get all chain IDs for an owner
    /// @param owner The owner address
    /// @return chainIds Array of chain IDs
    function getOwnerChains(
        address owner
    ) external view returns (bytes32[] memory chainIds) {
        return ownerChains[owner];
    }

    /// @notice Get chain info
    /// @param chainId The chain identifier
    /// @return owner Chain owner
    /// @return currentIndex Current key index
    /// @return totalKeys Total keys in chain
    /// @return usedCount Number of used keys
    /// @return active Whether chain is active
    function getChainInfo(
        bytes32 chainId
    ) external view returns (
        address owner,
        uint256 currentIndex,
        uint256 totalKeys,
        uint256 usedCount,
        bool active
    ) {
        KeyChain storage chain = keyChains[chainId];
        return (
            chain.owner,
            chain.currentIndex,
            chain.pkhs.length,
            chain.usedCount,
            chain.active
        );
    }
}
