/**
 * TypeScript types for Lamport OTS contracts
 */

import type { Address, Hex } from 'viem'

// ============================================================================
// Contract Types
// ============================================================================

/** LamportVerifier contract state */
export interface LamportVerifierState {
  pkh: Hex
  initialized: boolean
}

/** LamportSafe contract state */
export interface LamportSafeState {
  safe: Address
  pkh: Hex
  initialized: boolean
  nonce: bigint
}

/** LamportThreshold contract state */
export interface LamportThresholdState {
  safe: Address
  pkh: Hex
  initialized: boolean
  nonce: bigint
}

/** KeyChain entry in LamportKeyChain contract */
export interface KeyChainEntry {
  pkhs: Hex[]
  currentIndex: bigint
  owner: Address
  active: boolean
}

// ============================================================================
// Transaction Types
// ============================================================================

/** Safe operation type */
export enum SafeOperation {
  Call = 0,
  DelegateCall = 1,
}

/** Parameters for LamportSafe.exec() */
export interface LamportSafeExecParams {
  to: Address
  value: bigint
  data: Hex
  operation: SafeOperation
  sig: Hex[]           // bytes32[256]
  pub: [Hex, Hex][]    // bytes32[2][256]
  nextPKH: Hex
}

/** Parameters for LamportThreshold.exec() */
export interface LamportThresholdExecParams {
  to: Address
  value: bigint
  data: Hex
  operation: SafeOperation
  sig: Hex[]           // bytes32[256]
  currentPub: [Hex, Hex][]  // bytes32[2][256]
  nextPKH: Hex
}

// ============================================================================
// Event Types
// ============================================================================

/** Initialized event */
export interface InitializedEvent {
  pkh: Hex
}

/** KeyRotated event */
export interface KeyRotatedEvent {
  oldPkh: Hex
  newPkh: Hex
}

/** Executed event (LamportSafe) */
export interface ExecutedEvent {
  txHash: Hex
  nonce: bigint
}

/** Executed event (LamportThreshold) */
export interface ThresholdExecutedEvent {
  txHash: Hex
  nextPkh: Hex
  nonce: bigint
}

/** ChainRegistered event */
export interface ChainRegisteredEvent {
  chainId: Hex
  owner: Address
  keyCount: bigint
}

/** KeyUsed event */
export interface KeyUsedEvent {
  chainId: Hex
  pkh: Hex
  index: bigint
}

// ============================================================================
// Error Types
// ============================================================================

export const LamportErrors = {
  NotInitialized: 'NotInitialized',
  AlreadyInitialized: 'AlreadyInitialized',
  OnlySafe: 'OnlySafe',
  InvalidPKH: 'InvalidPKH',
  InvalidSignature: 'InvalidSignature',
  ZeroAddress: 'ZeroAddress',
  ZeroPKH: 'ZeroPKH',
  ChainNotFound: 'ChainNotFound',
  NotChainOwner: 'NotChainOwner',
  ChainNotActive: 'ChainNotActive',
  ChainExhausted: 'ChainExhausted',
  PKHAlreadyUsed: 'PKHAlreadyUsed',
  InvalidPKHError: 'InvalidPKH',
  EmptyKeyArray: 'EmptyKeyArray',
} as const

export type LamportError = keyof typeof LamportErrors
