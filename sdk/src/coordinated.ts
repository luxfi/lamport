/**
 * Coordinated Lamport Signing (NOT Threshold Cryptography)
 *
 * ⚠️  SECURITY WARNING ⚠️
 * This module implements COORDINATED signing, NOT true threshold cryptography.
 *
 * WHAT THIS IS:
 * - Multiple parties each hold a PORTION of the private key (exclusive bit ranges)
 * - ALL parties must cooperate to produce a valid signature
 * - This is essentially n-of-n custody with key partitioning
 *
 * WHAT THIS IS NOT:
 * - NOT t-of-n threshold: Any single party compromise leaks their bit range
 * - NOT Byzantine-fault-tolerant: Collusion below n can sign certain messages
 * - NOT suitable for scenarios requiring true threshold security
 *
 * FOR TRUE THRESHOLD LAMPORT:
 * Each of the 512 secrets (256 bits × 2 sides) must be t-of-n Shamir shared.
 * See `threshold.ts` for the proper implementation (requires more infrastructure).
 *
 * USE CASES FOR COORDINATED SIGNING:
 * - All-party consent required (corporate treasury)
 * - Key ceremony with trusted parties
 * - Backup/recovery with known trusted set
 *
 * @module coordinated
 */

import { keccak256, encodePacked, type Hex, type Address } from 'viem'
import {
  type LamportKeyPair,
  type LamportSignature,
  type LamportPublicKey,
  generateKeyPair,
  computeMessage,
} from './index'

// ============================================================================
// Types
// ============================================================================

/** Coordinated signing configuration (n-of-n) */
export interface CoordinatedConfig {
  /** Total number of parties (all must participate) */
  parties: number
  /** Party identifiers */
  partyIds: string[]
}

/** Key portion for one party */
export interface KeyPortion {
  partyId: string
  /** Bit indices this party controls */
  bitIndices: number[]
  /** Private key portions: Map<bitIndex, [priv0, priv1]> */
  secrets: Map<number, [Hex, Hex]>
  /** Full public key (same for all parties) */
  publicKey: LamportPublicKey
  pkh: Hex
}

/** Partial signature from one party */
export interface PartialSig {
  partyId: string
  /** Revealed preimages: Map<bitIndex, preimage> */
  preimages: Map<number, Hex>
}

/** Signing session */
export interface CoordinatedSession {
  sessionId: Hex
  message: bigint
  config: CoordinatedConfig
  partials: PartialSig[]
  complete: boolean
}

// ============================================================================
// Key Distribution (Partitioned Custody)
// ============================================================================

/**
 * Distribute key portions to parties (n-of-n partitioned custody)
 *
 * ⚠️  This is NOT threshold crypto - each party gets exclusive bits.
 *
 * @param config - Coordinated signing configuration
 * @param entropy - Optional deterministic entropy
 * @returns Key portions for each party
 */
export function distributeKeyPortions(
  config: CoordinatedConfig,
  entropy?: Hex
): KeyPortion[] {
  const { parties, partyIds } = config

  if (partyIds.length !== parties) {
    throw new Error('Party count mismatch')
  }

  if (parties < 1 || parties > 256) {
    throw new Error('Invalid party count (1-256)')
  }

  // Generate full key pair
  const fullKeyPair = generateKeyPair(entropy)

  // Calculate bits per party (ceiling division)
  const bitsPerParty = Math.ceil(256 / parties)

  // Distribute exclusive bit ranges
  const portions: KeyPortion[] = partyIds.map((partyId, idx) => {
    const secrets = new Map<number, [Hex, Hex]>()
    const bitIndices: number[] = []

    const startBit = idx * bitsPerParty
    const endBit = Math.min(256, (idx + 1) * bitsPerParty)

    for (let i = startBit; i < endBit; i++) {
      secrets.set(i, fullKeyPair.privateKey[i])
      bitIndices.push(i)
    }

    return {
      partyId,
      bitIndices,
      secrets,
      publicKey: fullKeyPair.publicKey,
      pkh: fullKeyPair.pkh,
    }
  })

  return portions
}

// ============================================================================
// Coordinated Signing
// ============================================================================

/**
 * Create a signing session
 */
export function createSession(
  message: bigint,
  config: CoordinatedConfig
): CoordinatedSession {
  const sessionId = keccak256(
    encodePacked(
      ['uint256', 'uint256', 'uint256'],
      [message, BigInt(Date.now()), BigInt(Math.floor(Math.random() * 1e18))]
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
 * Generate partial signature from a party's key portion
 */
export function signPortion(
  session: CoordinatedSession,
  portion: KeyPortion
): PartialSig {
  const preimages = new Map<number, Hex>()
  const { message } = session

  for (const [bitIndex, [priv0, priv1]] of portion.secrets) {
    const bitPos = 255n - BigInt(bitIndex)
    const bit = Number((message >> bitPos) & 1n)
    preimages.set(bitIndex, bit === 0 ? priv0 : priv1)
  }

  return {
    partyId: portion.partyId,
    preimages,
  }
}

/**
 * Add partial signature to session
 */
export function addPartial(
  session: CoordinatedSession,
  partial: PartialSig
): CoordinatedSession {
  if (session.partials.some(p => p.partyId === partial.partyId)) {
    throw new Error('Duplicate partial from party')
  }

  const newPartials = [...session.partials, partial]

  // Check coverage
  const coveredBits = new Set<number>()
  for (const p of newPartials) {
    for (const bitIndex of p.preimages.keys()) {
      coveredBits.add(bitIndex)
    }
  }

  return {
    ...session,
    partials: newPartials,
    complete: coveredBits.size === 256,
  }
}

/**
 * Combine partials into full signature
 */
export function combinePartials(session: CoordinatedSession): LamportSignature {
  if (!session.complete) {
    throw new Error('Session incomplete - not all parties have signed')
  }

  const signature: Hex[] = new Array(256)

  for (const partial of session.partials) {
    for (const [bitIndex, preimage] of partial.preimages) {
      signature[bitIndex] = preimage
    }
  }

  // Verify completeness
  for (let i = 0; i < 256; i++) {
    if (!signature[i]) {
      throw new Error(`Missing preimage for bit ${i}`)
    }
  }

  return signature
}

// ============================================================================
// Safe Integration
// ============================================================================

/**
 * Prepare coordinated signature for LamportSafe/LamportThreshold contract
 */
export function prepareCoordinatedTransaction(
  txHash: Hex,
  nextPKH: Hex,
  moduleAddress: Address,
  chainId: bigint,
  portions: KeyPortion[]
): {
  message: bigint
  session: CoordinatedSession
  publicKey: LamportPublicKey
} {
  const message = computeMessage(txHash, nextPKH, moduleAddress, chainId)

  const config: CoordinatedConfig = {
    parties: portions.length,
    partyIds: portions.map(p => p.partyId),
  }

  const session = createSession(message, config)

  return {
    message,
    session,
    publicKey: portions[0].publicKey,
  }
}

// ============================================================================
// Security Analysis
// ============================================================================

/**
 * Analyze security properties of coordinated setup
 *
 * ⚠️  This is NOT threshold security analysis
 */
export function analyzeCoordinatedSecurity(parties: number): {
  model: 'n-of-n'
  compromiseImpact: string
  recommendation: string
} {
  const bitsPerParty = Math.ceil(256 / parties)

  return {
    model: 'n-of-n',
    compromiseImpact: `1 compromised party leaks ${bitsPerParty} bits (${((bitsPerParty / 256) * 100).toFixed(1)}% of key)`,
    recommendation: parties < 3
      ? 'Consider adding more parties to reduce per-party exposure'
      : 'For true threshold security, use Shamir-based threshold.ts',
  }
}
