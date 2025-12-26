/**
 * Contract ABIs for Lamport OTS contracts
 */

import LamportAbi from '../abis/Lamport.json'
import LamportVerifierAbi from '../abis/LamportVerifier.json'
import LamportOptimizedAbi from '../abis/LamportOptimized.json'
import LamportSafeAbi from '../abis/LamportSafe.json'
import LamportThresholdAbi from '../abis/LamportThreshold.json'
import LamportKeyChainAbi from '../abis/LamportKeyChain.json'

export const abis = {
  Lamport: LamportAbi,
  LamportVerifier: LamportVerifierAbi,
  LamportOptimized: LamportOptimizedAbi,
  LamportSafe: LamportSafeAbi,
  LamportThreshold: LamportThresholdAbi,
  LamportKeyChain: LamportKeyChainAbi,
} as const

export {
  LamportAbi,
  LamportVerifierAbi,
  LamportOptimizedAbi,
  LamportSafeAbi,
  LamportThresholdAbi,
  LamportKeyChainAbi,
}
