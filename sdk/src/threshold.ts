/**
 * Threshold Lamport Signatures
 *
 * T-of-N threshold signing where the MPC network controls
 * a single Lamport key. On-chain sees a standard signature.
 *
 * Architecture:
 * - Off-chain: T-Chain MPC network performs threshold key generation
 * - Off-chain: T-of-N signers coordinate to produce signature
 * - On-chain: Standard Lamport verification (no threshold logic)
 *
 * Key Management:
 * - Pre-generate key chains for predictable rotation
 * - LamportKeyChain contract tracks key usage
 * - Atomic rotation after each signature
 */

import { keccak256, encodePacked, type Hex, type Address } from 'viem'
import {
  type LamportKeyPair,
  type LamportKeyChain,
  type LamportSignature,
  type LamportPublicKey,
  generateKeyPair,
  sign,
  computeMessage,
} from './index'

// ============================================================================
// Types
// ============================================================================

/** Threshold configuration */
export interface ThresholdConfig {
  /** Threshold (minimum signers required) */
  threshold: number
  /** Total number of signers */
  total: number
  /** Signer identifiers */
  signers: string[]
}

/** Partial signature from one signer */
export interface PartialSignature {
  signerId: string
  /** Partial preimages for assigned bits */
  partials: Map<number, Hex>
}

/** Signing session state */
export interface SigningSession {
  sessionId: Hex
  message: bigint
  config: ThresholdConfig
  partials: PartialSignature[]
  complete: boolean
}

/** Key share for distributed key generation */
export interface KeyShare {
  signerId: string
  /** Share of private key bits */
  privateShares: Map<number, [Hex, Hex]>
  /** Full public key (same for all signers) */
  publicKey: LamportPublicKey
  pkh: Hex
}

// ============================================================================
// Distributed Key Generation (DKG)
// ============================================================================

/**
 * Generate key shares for threshold signing
 *
 * In production, this would use a proper DKG protocol.
 * This simplified version assigns bit ranges to signers.
 *
 * @param config - Threshold configuration
 * @param masterEntropy - Optional entropy for deterministic generation
 * @returns Key shares for each signer
 */
export function generateKeyShares(
  config: ThresholdConfig,
  masterEntropy?: Hex
): KeyShare[] {
  const { threshold, total, signers } = config

  if (threshold > total || threshold < 1) {
    throw new Error('Invalid threshold configuration')
  }

  if (signers.length !== total) {
    throw new Error('Signer count mismatch')
  }

  // Generate the full key pair
  const entropy = masterEntropy || (`0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex')}` as Hex)
  const fullKeyPair = generateKeyPair(entropy)

  // Assign bit ranges to signers
  // Each signer gets 256/total bits, with overlap for threshold
  const bitsPerSigner = Math.ceil(256 / threshold)

  const shares: KeyShare[] = signers.map((signerId, idx) => {
    const privateShares = new Map<number, [Hex, Hex]>()

    // Assign bits with overlap based on threshold
    const startBit = (idx * 256) / total
    const endBit = Math.min(256, startBit + bitsPerSigner)

    for (let i = Math.floor(startBit); i < endBit; i++) {
      privateShares.set(i, fullKeyPair.privateKey[i])
    }

    return {
      signerId,
      privateShares,
      publicKey: fullKeyPair.publicKey,
      pkh: fullKeyPair.pkh,
    }
  })

  return shares
}

// ============================================================================
// Threshold Signing
// ============================================================================

/**
 * Create a new signing session
 *
 * @param message - Message to sign
 * @param config - Threshold configuration
 * @returns New signing session
 */
export function createSigningSession(
  message: bigint,
  config: ThresholdConfig
): SigningSession {
  const sessionId = keccak256(
    encodePacked(
      ['uint256', 'uint256', 'uint256'],
      [message, BigInt(Date.now()), BigInt(Math.random() * 1e18)]
    )
  )

  return {
    sessionId,
    message,
    config,
    partials: [],
    complete: false,
  }
}

/**
 * Generate partial signature from a key share
 *
 * @param session - Signing session
 * @param share - Signer's key share
 * @returns Partial signature
 */
export function signPartial(
  session: SigningSession,
  share: KeyShare
): PartialSignature {
  const partials = new Map<number, Hex>()
  const { message } = session

  for (const [bitIndex, [priv0, priv1]] of share.privateShares) {
    const bitPos = 255n - BigInt(bitIndex)
    const bit = Number((message >> bitPos) & 1n)
    partials.set(bitIndex, bit === 0 ? priv0 : priv1)
  }

  return {
    signerId: share.signerId,
    partials,
  }
}

/**
 * Add partial signature to session
 *
 * @param session - Signing session
 * @param partial - Partial signature to add
 * @returns Updated session
 */
export function addPartialSignature(
  session: SigningSession,
  partial: PartialSignature
): SigningSession {
  // Check if we already have this signer's partial
  if (session.partials.some(p => p.signerId === partial.signerId)) {
    throw new Error('Duplicate partial signature')
  }

  const newPartials = [...session.partials, partial]

  // Check if we have enough partials
  const coveredBits = new Set<number>()
  for (const p of newPartials) {
    for (const bitIndex of p.partials.keys()) {
      coveredBits.add(bitIndex)
    }
  }

  const complete = coveredBits.size === 256

  return {
    ...session,
    partials: newPartials,
    complete,
  }
}

/**
 * Combine partial signatures into full signature
 *
 * @param session - Completed signing session
 * @returns Full Lamport signature
 */
export function combineSignatures(session: SigningSession): LamportSignature {
  if (!session.complete) {
    throw new Error('Session not complete')
  }

  const signature: Hex[] = new Array(256)

  // Collect all partials
  for (const partial of session.partials) {
    for (const [bitIndex, preimage] of partial.partials) {
      if (signature[bitIndex] === undefined) {
        signature[bitIndex] = preimage
      }
    }
  }

  // Verify all bits are covered
  for (let i = 0; i < 256; i++) {
    if (signature[i] === undefined) {
      throw new Error(`Missing signature for bit ${i}`)
    }
  }

  return signature
}

// ============================================================================
// Key Chain Management
// ============================================================================

/**
 * Generate a pre-signed key chain for threshold use
 *
 * @param count - Number of key pairs to generate
 * @param config - Threshold configuration
 * @param masterEntropy - Optional master entropy
 * @returns Key chain with shares for each signer
 */
export function generateThresholdKeyChain(
  count: number,
  config: ThresholdConfig,
  masterEntropy?: Hex
): {
  pkhs: Hex[]
  sharesPerKey: KeyShare[][]
} {
  const pkhs: Hex[] = []
  const sharesPerKey: KeyShare[][] = []

  for (let i = 0; i < count; i++) {
    const entropy = masterEntropy
      ? keccak256(encodePacked(['bytes32', 'uint256'], [masterEntropy, BigInt(i)]))
      : undefined

    const shares = generateKeyShares(config, entropy)
    pkhs.push(shares[0].pkh)
    sharesPerKey.push(shares)
  }

  return { pkhs, sharesPerKey }
}

// ============================================================================
// Safe Integration
// ============================================================================

/**
 * Prepare threshold signature for LamportThreshold contract
 *
 * @param txHash - Safe transaction hash
 * @param nextPKH - Next PKH for rotation
 * @param moduleAddress - LamportThreshold module address
 * @param chainId - Chain ID
 * @param shares - Key shares for current key
 * @returns Transaction data
 */
export async function prepareThresholdSafeTransaction(
  txHash: Hex,
  nextPKH: Hex,
  moduleAddress: Address,
  chainId: bigint,
  shares: KeyShare[]
): Promise<{
  message: bigint
  session: SigningSession
  publicKey: LamportPublicKey
}> {
  const message = computeMessage(txHash, nextPKH, moduleAddress, chainId)

  const config: ThresholdConfig = {
    threshold: shares.length,
    total: shares.length,
    signers: shares.map(s => s.signerId),
  }

  const session = createSigningSession(message, config)
  const publicKey = shares[0].publicKey

  return { message, session, publicKey }
}

// ============================================================================
// Utilities
// ============================================================================

/**
 * Verify threshold configuration is valid
 */
export function validateThresholdConfig(config: ThresholdConfig): boolean {
  const { threshold, total, signers } = config

  if (threshold < 1 || threshold > total) {
    return false
  }

  if (signers.length !== total) {
    return false
  }

  if (new Set(signers).size !== signers.length) {
    return false // Duplicate signers
  }

  return true
}

/**
 * Calculate security level of threshold setup
 *
 * @param threshold - Minimum signers required
 * @param total - Total signers
 * @returns Security analysis
 */
export function analyzeThresholdSecurity(
  threshold: number,
  total: number
): {
  compromiseResistance: number
  availabilityTolerance: number
  securityLevel: 'low' | 'medium' | 'high'
} {
  // How many signers can be compromised
  const compromiseResistance = threshold - 1

  // How many signers can be unavailable
  const availabilityTolerance = total - threshold

  let securityLevel: 'low' | 'medium' | 'high'
  if (threshold >= Math.ceil(total * 2 / 3)) {
    securityLevel = 'high'
  } else if (threshold >= Math.ceil(total / 2)) {
    securityLevel = 'medium'
  } else {
    securityLevel = 'low'
  }

  return {
    compromiseResistance,
    availabilityTolerance,
    securityLevel,
  }
}
