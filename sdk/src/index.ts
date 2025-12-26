/**
 * @luxfi/lamport - Lamport One-Time Signatures SDK
 *
 * Post-quantum secure signatures using only keccak256.
 * Each key can only sign ONE message (one-time property).
 *
 * @example
 * ```ts
 * import { generateKeyPair, sign, verify, LamportSafe } from '@luxfi/lamport'
 *
 * // Generate a key pair
 * const { privateKey, publicKey, pkh } = generateKeyPair()
 *
 * // Sign a message
 * const message = keccak256(toBytes('Hello'))
 * const signature = sign(message, privateKey)
 *
 * // Verify
 * const valid = verify(message, signature, publicKey)
 * ```
 */

import { keccak256, toBytes, encodePacked, type Hex, type Address } from 'viem'

// Re-export ABIs
export * from './abis'

// Re-export types
export * from './types'

// Re-export threshold module (true t-of-n Shamir-based)
export * from './threshold'

// Re-export coordinated module (n-of-n partitioned custody)
export * from './coordinated'

// ============================================================================
// Types
// ============================================================================

/** 256x2 array of 32-byte private key components */
export type LamportPrivateKey = [Hex, Hex][]

/** 256x2 array of 32-byte public key hashes */
export type LamportPublicKey = [Hex, Hex][]

/** Array of 256 32-byte signature preimages */
export type LamportSignature = Hex[]

/** Key pair with PKH for on-chain registration */
export interface LamportKeyPair {
  privateKey: LamportPrivateKey
  publicKey: LamportPublicKey
  pkh: Hex
}

/** Pre-generated key chain for threshold signing */
export interface LamportKeyChain {
  keyPairs: LamportKeyPair[]
  currentIndex: number
}

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Generate a random 32-byte value
 */
function randomBytes32(): Hex {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return `0x${Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')}` as Hex
}

/**
 * Generate a Lamport key pair
 *
 * @param entropy - Optional entropy for deterministic generation
 * @returns Key pair with private key, public key, and PKH
 *
 * @example
 * ```ts
 * const keyPair = generateKeyPair()
 * console.log('PKH:', keyPair.pkh)
 * ```
 */
export function generateKeyPair(entropy?: Hex): LamportKeyPair {
  const privateKey: LamportPrivateKey = []
  const publicKey: LamportPublicKey = []

  for (let i = 0; i < 256; i++) {
    let priv0: Hex, priv1: Hex

    if (entropy) {
      // Deterministic generation from entropy
      priv0 = keccak256(encodePacked(['bytes32', 'uint256', 'uint8'], [entropy, BigInt(i), 0]))
      priv1 = keccak256(encodePacked(['bytes32', 'uint256', 'uint8'], [entropy, BigInt(i), 1]))
    } else {
      // Random generation
      priv0 = randomBytes32()
      priv1 = randomBytes32()
    }

    const pub0 = keccak256(priv0)
    const pub1 = keccak256(priv1)

    privateKey.push([priv0, priv1])
    publicKey.push([pub0, pub1])
  }

  const pkh = computePKH(publicKey)

  return { privateKey, publicKey, pkh }
}

/**
 * Generate multiple key pairs for a key chain
 *
 * @param count - Number of key pairs to generate
 * @param masterEntropy - Optional master entropy for deterministic generation
 * @returns Key chain with pre-generated key pairs
 */
export function generateKeyChain(count: number, masterEntropy?: Hex): LamportKeyChain {
  const keyPairs: LamportKeyPair[] = []

  for (let i = 0; i < count; i++) {
    const entropy = masterEntropy
      ? keccak256(encodePacked(['bytes32', 'uint256'], [masterEntropy, BigInt(i)]))
      : undefined
    keyPairs.push(generateKeyPair(entropy))
  }

  return { keyPairs, currentIndex: 0 }
}

// ============================================================================
// Signing
// ============================================================================

/**
 * Sign a 256-bit message with a Lamport private key
 *
 * WARNING: Each private key can only be used ONCE!
 *
 * @param message - 32-byte message hash (as uint256)
 * @param privateKey - Lamport private key
 * @returns 256-element signature array
 *
 * @example
 * ```ts
 * const message = keccak256(toBytes('Hello'))
 * const signature = sign(message, privateKey)
 * ```
 */
export function sign(message: Hex | bigint, privateKey: LamportPrivateKey): LamportSignature {
  const bits = typeof message === 'bigint' ? message : BigInt(message)
  const signature: LamportSignature = []

  for (let i = 0; i < 256; i++) {
    const bitPos = 255n - BigInt(i)
    const bit = Number((bits >> bitPos) & 1n)
    signature.push(privateKey[i][bit])
  }

  return signature
}

/**
 * Sign a message and return the next PKH for rotation
 *
 * @param message - Message to sign
 * @param currentKey - Current key pair
 * @param nextKey - Next key pair for rotation
 * @returns Signature and next PKH
 */
export function signWithRotation(
  message: Hex | bigint,
  currentKey: LamportKeyPair,
  nextKey: LamportKeyPair
): { signature: LamportSignature; nextPKH: Hex } {
  return {
    signature: sign(message, currentKey.privateKey),
    nextPKH: nextKey.pkh,
  }
}

// ============================================================================
// Verification
// ============================================================================

/**
 * Verify a Lamport signature
 *
 * @param message - 32-byte message hash
 * @param signature - 256-element signature array
 * @param publicKey - Lamport public key
 * @returns True if signature is valid
 *
 * @example
 * ```ts
 * const valid = verify(message, signature, publicKey)
 * ```
 */
export function verify(
  message: Hex | bigint,
  signature: LamportSignature,
  publicKey: LamportPublicKey
): boolean {
  if (signature.length !== 256 || publicKey.length !== 256) {
    return false
  }

  const bits = typeof message === 'bigint' ? message : BigInt(message)

  for (let i = 0; i < 256; i++) {
    const bitPos = 255n - BigInt(i)
    const bit = Number((bits >> bitPos) & 1n)
    const hash = keccak256(signature[i])

    if (hash !== publicKey[i][bit]) {
      return false
    }
  }

  return true
}

// ============================================================================
// Key Operations
// ============================================================================

/**
 * Compute public key hash (PKH) from public key
 *
 * @param publicKey - Lamport public key
 * @returns keccak256 hash of packed public key
 */
export function computePKH(publicKey: LamportPublicKey): Hex {
  // Flatten and pack the public key
  const packed = publicKey.flatMap(([a, b]) => [a, b])
  return keccak256(encodePacked(['bytes32[]'], [packed]))
}

/**
 * Compute domain-separated message for Safe signing
 *
 * @param txHash - Transaction hash
 * @param nextPKH - Next public key hash for rotation
 * @param module - Module address
 * @param chainId - Chain ID
 * @returns Domain-separated message as uint256
 */
export function computeMessage(
  txHash: Hex,
  nextPKH: Hex,
  module: Address,
  chainId: bigint
): bigint {
  const hash = keccak256(
    encodePacked(
      ['bytes32', 'bytes32', 'address', 'uint256'],
      [txHash, nextPKH, module, chainId]
    )
  )
  return BigInt(hash)
}

/**
 * Get bit at index from a 256-bit value
 *
 * @param data - 32-byte value
 * @param index - Bit index (0 = MSB)
 * @returns 0 or 1
 */
export function getBit(data: Hex | bigint, index: number): number {
  if (index < 0 || index >= 256) {
    throw new Error('Index out of range')
  }
  const bits = typeof data === 'bigint' ? data : BigInt(data)
  return Number((bits >> BigInt(255 - index)) & 1n)
}

// ============================================================================
// Contract Helpers
// ============================================================================

/**
 * Format signature for contract call
 *
 * @param signature - Lamport signature
 * @returns Formatted as bytes32[256]
 */
export function formatSignatureForContract(signature: LamportSignature): Hex[] {
  if (signature.length !== 256) {
    throw new Error('Invalid signature length')
  }
  return signature
}

/**
 * Format public key for contract call
 *
 * @param publicKey - Lamport public key
 * @returns Formatted as bytes32[2][256]
 */
export function formatPublicKeyForContract(publicKey: LamportPublicKey): [Hex, Hex][] {
  if (publicKey.length !== 256) {
    throw new Error('Invalid public key length')
  }
  return publicKey
}

// ============================================================================
// Safe Module Integration
// ============================================================================

export interface SafeTransactionParams {
  to: Address
  value: bigint
  data: Hex
  operation: 0 | 1 // 0 = Call, 1 = DelegateCall
}

/**
 * Prepare a Safe transaction with Lamport signature
 *
 * @param params - Transaction parameters
 * @param keyPair - Current Lamport key pair
 * @param nextKeyPair - Next key pair for rotation
 * @param moduleAddress - LamportSafe module address
 * @param chainId - Chain ID
 * @param safeTxHash - Pre-computed Safe transaction hash
 * @returns Transaction data for LamportSafe.exec()
 */
export function prepareSafeTransaction(
  params: SafeTransactionParams,
  keyPair: LamportKeyPair,
  nextKeyPair: LamportKeyPair,
  moduleAddress: Address,
  chainId: bigint,
  safeTxHash: Hex
): {
  params: SafeTransactionParams
  signature: LamportSignature
  publicKey: LamportPublicKey
  nextPKH: Hex
  message: bigint
} {
  const message = computeMessage(safeTxHash, nextKeyPair.pkh, moduleAddress, chainId)
  const signature = sign(message, keyPair.privateKey)

  return {
    params,
    signature,
    publicKey: keyPair.publicKey,
    nextPKH: nextKeyPair.pkh,
    message,
  }
}

// ============================================================================
// Utilities
// ============================================================================

/**
 * Serialize key pair to JSON-safe format
 */
export function serializeKeyPair(keyPair: LamportKeyPair): string {
  return JSON.stringify({
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    pkh: keyPair.pkh,
  })
}

/**
 * Deserialize key pair from JSON
 */
export function deserializeKeyPair(json: string): LamportKeyPair {
  const data = JSON.parse(json)
  return {
    privateKey: data.privateKey as LamportPrivateKey,
    publicKey: data.publicKey as LamportPublicKey,
    pkh: data.pkh as Hex,
  }
}

/**
 * Estimate gas for Lamport verification
 *
 * @returns Approximate gas costs
 */
export function estimateGas(): {
  verifyMemory: number
  verifyCalldata: number
  verifyOptimized: number
  verifyConstantTime: number
} {
  return {
    verifyMemory: 1_200_000,    // Memory-based (Lamport.verifyMem)
    verifyCalldata: 450_000,    // Calldata-based (Lamport.verify)
    verifyOptimized: 164_000,   // Assembly optimized
    verifyConstantTime: 145_000, // Constant-time assembly
  }
}
