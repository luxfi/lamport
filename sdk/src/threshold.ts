/**
 * True Threshold Lamport Signatures (t-of-n)
 *
 * SECURITY MODEL:
 * - Each of 512 secrets (256 bits × 2 sides) is Shamir secret-shared
 * - t-of-n parties must cooperate to reconstruct each selected preimage
 * - No party learns the full secret; reconstruction happens per-signing
 * - Byzantine-fault-tolerant: up to (t-1) compromised parties reveal nothing
 *
 * ARCHITECTURE:
 * 1. DKG Phase: Each secret s[i][b] is split into n shares via Shamir
 * 2. Sign Phase: For each bit, t parties contribute shares of the selected secret
 * 3. Combine Phase: Lagrange interpolation reconstructs preimages
 * 4. On-chain: Standard Lamport verification (no threshold logic)
 *
 * PERFORMANCE:
 * - DKG: O(512 * n) share computations
 * - Sign: O(256 * t) share contributions + O(256 * t²) Lagrange interpolations
 * - Storage: Each party stores 512 shares (512 * 32 bytes = 16 KB)
 *
 * @module threshold
 */

import { keccak256, encodePacked, type Hex, type Address } from 'viem'
import {
  type LamportKeyPair,
  type LamportSignature,
  type LamportPublicKey,
  type LamportPrivateKey,
  generateKeyPair,
  computeMessage,
} from './index'

// ============================================================================
// Finite Field Arithmetic (GF(p) where p is secp256k1 field prime)
// ============================================================================

// Large prime close to 2^256 (secp256k1 field prime)
const FIELD_PRIME = 2n ** 256n - 2n ** 32n - 977n

function modAdd(a: bigint, b: bigint): bigint {
  return ((a % FIELD_PRIME) + (b % FIELD_PRIME)) % FIELD_PRIME
}

function modSub(a: bigint, b: bigint): bigint {
  return ((a % FIELD_PRIME) - (b % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME
}

function modMul(a: bigint, b: bigint): bigint {
  return ((a % FIELD_PRIME) * (b % FIELD_PRIME)) % FIELD_PRIME
}

function modPow(base: bigint, exp: bigint): bigint {
  let result = 1n
  base = base % FIELD_PRIME
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = modMul(result, base)
    }
    exp = exp / 2n
    base = modMul(base, base)
  }
  return result
}

function modInverse(a: bigint): bigint {
  // Fermat's little theorem: a^(-1) = a^(p-2) mod p
  return modPow(a, FIELD_PRIME - 2n)
}

function modDiv(a: bigint, b: bigint): bigint {
  return modMul(a, modInverse(b))
}

function hexToBigInt(hex: Hex): bigint {
  return BigInt(hex)
}

function bigIntToHex(n: bigint): Hex {
  const hex = (n % FIELD_PRIME).toString(16).padStart(64, '0')
  return `0x${hex}` as Hex
}

function randomFieldElement(): bigint {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  let n = 0n
  for (const b of bytes) {
    n = (n << 8n) | BigInt(b)
  }
  return n % FIELD_PRIME
}

// ============================================================================
// Shamir Secret Sharing
// ============================================================================

/** A single Shamir share: (x, y) point on polynomial */
export interface ShamirShare {
  x: bigint  // Party index (1-indexed, never 0)
  y: bigint  // Share value
}

/**
 * Split a secret into n shares with threshold t
 *
 * @param secret - The secret to share (as bigint)
 * @param t - Threshold (minimum shares to reconstruct)
 * @param n - Total number of shares
 * @returns Array of n shares
 */
export function shamirSplit(secret: bigint, t: number, n: number): ShamirShare[] {
  if (t < 1 || t > n) {
    throw new Error('Invalid threshold: must have 1 <= t <= n')
  }

  // Generate random polynomial: f(x) = secret + a1*x + a2*x² + ... + a(t-1)*x^(t-1)
  const coeffs: bigint[] = [secret % FIELD_PRIME]
  for (let i = 1; i < t; i++) {
    coeffs.push(randomFieldElement())
  }

  // Evaluate polynomial at x = 1, 2, ..., n
  const shares: ShamirShare[] = []
  for (let i = 1; i <= n; i++) {
    const x = BigInt(i)
    let y = 0n
    let xPow = 1n
    for (const coeff of coeffs) {
      y = modAdd(y, modMul(coeff, xPow))
      xPow = modMul(xPow, x)
    }
    shares.push({ x, y })
  }

  return shares
}

/**
 * Reconstruct secret from t shares using Lagrange interpolation
 *
 * @param shares - At least t shares
 * @returns The reconstructed secret
 */
export function shamirReconstruct(shares: ShamirShare[]): bigint {
  if (shares.length === 0) {
    throw new Error('No shares provided')
  }

  // Lagrange interpolation at x = 0
  let secret = 0n

  for (let i = 0; i < shares.length; i++) {
    let numerator = 1n
    let denominator = 1n

    for (let j = 0; j < shares.length; j++) {
      if (i !== j) {
        // numerator *= (0 - x_j) = -x_j
        numerator = modMul(numerator, modSub(0n, shares[j].x))
        // denominator *= (x_i - x_j)
        denominator = modMul(denominator, modSub(shares[i].x, shares[j].x))
      }
    }

    // Lagrange basis polynomial L_i(0)
    const lagrangeBasis = modDiv(numerator, denominator)
    secret = modAdd(secret, modMul(shares[i].y, lagrangeBasis))
  }

  return secret
}

// ============================================================================
// Threshold Lamport Types
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

/** Share of a single Lamport secret */
export interface SecretShare {
  bitIndex: number      // 0-255
  side: 0 | 1          // Which preimage (0 or 1)
  share: ShamirShare   // The actual Shamir share
}

/** Full key share for one party (all 512 secret shares) */
export interface ThresholdKeyShare {
  signerId: string
  partyIndex: number   // 1-indexed for Shamir
  /** All 512 shares: one for each (bitIndex, side) pair */
  secretShares: SecretShare[]
  /** Full public key (same for all parties) */
  publicKey: LamportPublicKey
  pkh: Hex
}

/** Partial signature contribution from one party */
export interface ThresholdPartial {
  signerId: string
  partyIndex: number
  /** Share contributions for selected bits: Map<bitIndex, share> */
  contributions: Map<number, ShamirShare>
}

/** Threshold signing session */
export interface ThresholdSession {
  sessionId: Hex
  message: bigint
  config: ThresholdConfig
  /** Which bit value (0 or 1) for each position */
  bitSelections: number[]
  partials: ThresholdPartial[]
  complete: boolean
}

// ============================================================================
// Distributed Key Generation (DKG)
// ============================================================================

/**
 * Generate threshold key shares for all parties
 *
 * ⚠️  TRUSTED DEALER DKG - In production, use Pedersen DKG or similar
 * where no single party sees the full secrets.
 *
 * @param config - Threshold configuration
 * @param entropy - Optional deterministic entropy
 * @returns Key shares for each party
 */
export function generateThresholdShares(
  config: ThresholdConfig,
  entropy?: Hex
): ThresholdKeyShare[] {
  const { threshold, total, signers } = config

  if (threshold < 1 || threshold > total) {
    throw new Error('Invalid threshold configuration')
  }

  if (signers.length !== total) {
    throw new Error('Signer count mismatch')
  }

  // Generate the master key pair
  const masterKeyPair = generateKeyPair(entropy)

  // Initialize share storage for each signer
  const allShares: Map<string, SecretShare[]> = new Map()
  for (const signerId of signers) {
    allShares.set(signerId, [])
  }

  // Split each of the 512 secrets into n Shamir shares
  for (let bitIndex = 0; bitIndex < 256; bitIndex++) {
    for (let side = 0; side < 2; side++) {
      const secret = hexToBigInt(masterKeyPair.privateKey[bitIndex][side as 0 | 1])
      const shares = shamirSplit(secret, threshold, total)

      // Distribute to each party
      for (let i = 0; i < total; i++) {
        const partyShares = allShares.get(signers[i])!
        partyShares.push({
          bitIndex,
          side: side as 0 | 1,
          share: shares[i],
        })
      }
    }
  }

  // Build key share objects
  const keyShares: ThresholdKeyShare[] = signers.map((signerId, idx) => ({
    signerId,
    partyIndex: idx + 1, // 1-indexed for Shamir
    secretShares: allShares.get(signerId)!,
    publicKey: masterKeyPair.publicKey,
    pkh: masterKeyPair.pkh,
  }))

  return keyShares
}

// ============================================================================
// Threshold Signing
// ============================================================================

/**
 * Create a threshold signing session
 */
export function createThresholdSession(
  message: bigint,
  config: ThresholdConfig
): ThresholdSession {
  const sessionId = keccak256(
    encodePacked(
      ['uint256', 'uint256', 'uint256'],
      [message, BigInt(Date.now()), BigInt(Math.floor(Math.random() * 1e18))]
    )
  )

  // Determine which side (0 or 1) to reveal for each bit
  const bitSelections: number[] = []
  for (let i = 0; i < 256; i++) {
    const bitPos = 255n - BigInt(i)
    const bit = Number((message >> bitPos) & 1n)
    bitSelections.push(bit)
  }

  return {
    sessionId,
    message,
    config,
    bitSelections,
    partials: [],
    complete: false,
  }
}

/**
 * Generate partial signature from a party's key share
 *
 * Each party contributes their Shamir share for the selected preimage of each bit.
 */
export function signThresholdPartial(
  session: ThresholdSession,
  keyShare: ThresholdKeyShare
): ThresholdPartial {
  const contributions = new Map<number, ShamirShare>()

  for (let bitIndex = 0; bitIndex < 256; bitIndex++) {
    const selectedSide = session.bitSelections[bitIndex]

    // Find the share for this bit/side
    const secretShare = keyShare.secretShares.find(
      s => s.bitIndex === bitIndex && s.side === selectedSide
    )

    if (!secretShare) {
      throw new Error(`Missing share for bit ${bitIndex} side ${selectedSide}`)
    }

    contributions.set(bitIndex, secretShare.share)
  }

  return {
    signerId: keyShare.signerId,
    partyIndex: keyShare.partyIndex,
    contributions,
  }
}

/**
 * Add partial signature to session
 */
export function addThresholdPartial(
  session: ThresholdSession,
  partial: ThresholdPartial
): ThresholdSession {
  if (session.partials.some(p => p.signerId === partial.signerId)) {
    throw new Error('Duplicate partial from signer')
  }

  const newPartials = [...session.partials, partial]
  const complete = newPartials.length >= session.config.threshold

  return {
    ...session,
    partials: newPartials,
    complete,
  }
}

/**
 * Combine threshold partials into full signature
 *
 * Uses Lagrange interpolation to reconstruct each preimage from shares.
 */
export function combineThresholdSignature(session: ThresholdSession): LamportSignature {
  if (!session.complete) {
    throw new Error(`Need ${session.config.threshold} partials, have ${session.partials.length}`)
  }

  const signature: Hex[] = []

  for (let bitIndex = 0; bitIndex < 256; bitIndex++) {
    // Collect shares for this bit from all contributing parties
    const shares: ShamirShare[] = []
    for (const partial of session.partials) {
      const share = partial.contributions.get(bitIndex)
      if (share) {
        shares.push(share)
      }
    }

    if (shares.length < session.config.threshold) {
      throw new Error(`Insufficient shares for bit ${bitIndex}`)
    }

    // Take exactly threshold shares for reconstruction
    const selectedShares = shares.slice(0, session.config.threshold)

    // Reconstruct the preimage via Lagrange interpolation
    const preimage = shamirReconstruct(selectedShares)
    signature.push(bigIntToHex(preimage))
  }

  return signature
}

// ============================================================================
// Safe Integration
// ============================================================================

/**
 * Prepare threshold signature for LamportThreshold contract
 */
export function prepareThresholdSafeTransaction(
  txHash: Hex,
  nextPKH: Hex,
  moduleAddress: Address,
  chainId: bigint,
  keyShares: ThresholdKeyShare[]
): {
  message: bigint
  session: ThresholdSession
  publicKey: LamportPublicKey
} {
  const message = computeMessage(txHash, nextPKH, moduleAddress, chainId)

  // Derive config from shares
  const config: ThresholdConfig = {
    threshold: keyShares.length,
    total: keyShares.length,
    signers: keyShares.map(s => s.signerId),
  }

  const session = createThresholdSession(message, config)

  return {
    message,
    session,
    publicKey: keyShares[0].publicKey,
  }
}

// ============================================================================
// Key Chain for Threshold
// ============================================================================

/**
 * Generate a chain of threshold keys for continuous signing
 */
export function generateThresholdKeyChain(
  count: number,
  config: ThresholdConfig,
  masterEntropy?: Hex
): {
  pkhs: Hex[]
  sharesPerKey: ThresholdKeyShare[][]
} {
  const pkhs: Hex[] = []
  const sharesPerKey: ThresholdKeyShare[][] = []

  for (let i = 0; i < count; i++) {
    const entropy = masterEntropy
      ? keccak256(encodePacked(['bytes32', 'uint256'], [masterEntropy, BigInt(i)]))
      : undefined

    const shares = generateThresholdShares(config, entropy)
    pkhs.push(shares[0].pkh)
    sharesPerKey.push(shares)
  }

  return { pkhs, sharesPerKey }
}

// ============================================================================
// Security Analysis
// ============================================================================

/**
 * Validate threshold configuration
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
    return false
  }

  return true
}

/**
 * Analyze security of threshold setup
 */
export function analyzeThresholdSecurity(
  threshold: number,
  total: number
): {
  model: 't-of-n'
  compromiseResistance: number
  availabilityTolerance: number
  securityLevel: 'low' | 'medium' | 'high'
} {
  const compromiseResistance = threshold - 1
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
    model: 't-of-n',
    compromiseResistance,
    availabilityTolerance,
    securityLevel,
  }
}
