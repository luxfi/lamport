// Lamport CLI - Post-Quantum One-Time Signatures
//
// Usage:
//   lamport keygen                     Generate a new key pair
//   lamport sign <key> <message>       Sign a message
//   lamport verify <pub> <sig> <msg>   Verify a signature
//   lamport chain <n>                  Generate a key chain of n keys
//   lamport benchmark                  Run performance benchmarks
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/luxfi/lamport/primitives"
	"github.com/luxfi/lamport/threshold"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "keygen":
		cmdKeygen()
	case "sign":
		cmdSign()
	case "verify":
		cmdVerify()
	case "chain":
		cmdChain()
	case "benchmark":
		cmdBenchmark()
	case "threshold":
		cmdThreshold()
	case "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Lamport OTS - Post-Quantum One-Time Signatures

Usage:
  lamport <command> [arguments]

Commands:
  keygen              Generate a new key pair
  sign                Sign a message (requires private key)
  verify              Verify a signature
  chain <n>           Generate a key chain of n keys
  threshold <t> <n>   Demo threshold signing (t-of-n)
  benchmark           Run performance benchmarks
  help                Show this help

Examples:
  lamport keygen
  lamport chain 10
  lamport threshold 3 5
  lamport benchmark

For production use, see the Go library at github.com/luxfi/lamport`)
}

func cmdKeygen() {
	fmt.Println("Generating Lamport key pair...")

	start := time.Now()
	kp, err := primitives.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	elapsed := time.Since(start)

	pkh := kp.Public.Hash()

	fmt.Printf("\nKey generated in %v\n", elapsed)
	fmt.Printf("\nPublic Key Hash (PKH): 0x%s\n", hex.EncodeToString(pkh[:]))
	fmt.Printf("Public Key Size: %d bytes\n", primitives.PublicKeySize)
	fmt.Printf("Private Key Size: %d bytes\n", primitives.PrivateKeySize)
	fmt.Printf("\n⚠️  WARNING: This key can only be used ONCE!\n")
}

func cmdSign() {
	fmt.Println("Sign command - for demo purposes only")
	fmt.Println("In production, use the Go library directly.")

	// Demo signing
	kp, _ := primitives.GenerateKeyPair()
	message := primitives.Keccak256([]byte("Demo message"))
	sig, _ := primitives.Sign(kp.Private, message)

	fmt.Printf("\nMessage: 0x%s\n", hex.EncodeToString(message[:]))
	fmt.Printf("Signature size: %d bytes\n", len(sig.Bytes()))
	fmt.Printf("Verification: %v\n", primitives.Verify(kp.Public, message, sig))
}

func cmdVerify() {
	fmt.Println("Verify command - for demo purposes only")
	fmt.Println("In production, use the Go library or Solidity verifier.")
}

func cmdChain() {
	n := 10
	if len(os.Args) > 2 {
		var err error
		n, err = strconv.Atoi(os.Args[2])
		if err != nil || n < 1 {
			fmt.Println("Invalid chain size. Using default: 10")
			n = 10
		}
	}

	fmt.Printf("Generating key chain with %d keys...\n", n)

	start := time.Now()
	chain, err := primitives.NewKeyChain(n)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	elapsed := time.Since(start)

	fmt.Printf("\nChain generated in %v\n", elapsed)
	fmt.Printf("Average per key: %v\n", elapsed/time.Duration(n))

	// Print first few PKHs
	fmt.Println("\nFirst 5 PKHs:")
	for i := 0; i < 5 && i < n; i++ {
		pkh := chain.Keys[i].Public.Hash()
		fmt.Printf("  [%d] 0x%s\n", i, hex.EncodeToString(pkh[:]))
	}

	// Demo signing through chain
	fmt.Println("\nDemo: Signing 3 messages through chain...")
	for i := 0; i < 3 && chain.Remaining() > 0; i++ {
		message := primitives.Keccak256([]byte(fmt.Sprintf("Message %d", i)))
		sig, nextPKH, err := primitives.SignWithKeyChain(chain, message)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			break
		}
		fmt.Printf("  Signed message %d, nextPKH: 0x%s...\n", i, hex.EncodeToString(nextPKH[:8]))
		_ = sig
	}

	fmt.Printf("\nRemaining keys: %d\n", chain.Remaining())
}

func cmdThreshold() {
	t := 3
	n := 5
	if len(os.Args) > 3 {
		t, _ = strconv.Atoi(os.Args[2])
		n, _ = strconv.Atoi(os.Args[3])
	}

	fmt.Printf("Demo: %d-of-%d Threshold Lamport Signing\n\n", t, n)

	// Generate shares
	fmt.Printf("1. Generating %d shares...\n", n)
	start := time.Now()
	shares, pub, err := threshold.GenerateShares(n)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   Done in %v\n", time.Since(start))

	pkh := pub.Hash()
	fmt.Printf("   PKH: 0x%s\n\n", hex.EncodeToString(pkh[:]))

	// Setup threshold config
	var moduleAddr [20]byte
	rand.Read(moduleAddr[:])
	config, _ := threshold.NewConfig(t, n, "coordinator", 96369, moduleAddr)

	// Simulate signing
	var safeTxHash, nextPKH [32]byte
	rand.Read(safeTxHash[:])
	rand.Read(nextPKH[:])

	message := config.ComputeMessage(safeTxHash, nextPKH)
	fmt.Printf("2. Message to sign: 0x%s...\n\n", hex.EncodeToString(message[:8]))

	// Phase 1: Collect commitments
	fmt.Printf("3. Phase 1: Collecting digest commitments...\n")
	coordinator := threshold.NewCoordinator(config, pub, safeTxHash, nextPKH)
	for i := 0; i < t; i++ {
		shares[i].PartyID = fmt.Sprintf("party-%d", i)
		partyConfig, _ := threshold.NewConfig(t, n, shares[i].PartyID, 96369, moduleAddr)
		commitment := partyConfig.CreateDigestCommitment(safeTxHash)
		ready, _ := coordinator.AddCommitment(commitment, safeTxHash)
		fmt.Printf("   Party %d committed\n", i)
		if ready {
			fmt.Printf("   -> Ready to collect partials!\n")
		}
	}

	// Phase 2: Collect partials
	fmt.Printf("\n4. Phase 2: Collecting partial signatures...\n")
	start = time.Now()
	var finalSig *primitives.Signature
	for i := 0; i < t; i++ {
		partial := threshold.CreatePartialSignature(shares[i], message)
		sig, _ := coordinator.AddPartial(partial)
		fmt.Printf("   Party %d signed\n", i)
		if sig != nil {
			finalSig = sig
			fmt.Printf("   -> Signature complete!\n")
		}
	}
	signTime := time.Since(start)

	// Verify
	fmt.Printf("\n5. Verifying aggregated signature...\n")
	start = time.Now()
	valid := primitives.Verify(pub, message, finalSig)
	verifyTime := time.Since(start)

	fmt.Printf("   Valid: %v\n", valid)
	fmt.Printf("\nTiming:\n")
	fmt.Printf("   Sign (aggregate %d partials): %v\n", t, signTime)
	fmt.Printf("   Verify: %v\n", verifyTime)
}

func cmdBenchmark() {
	fmt.Println("Lamport OTS Benchmarks")
	fmt.Println("======================")
	fmt.Println()

	// KeyGen
	iterations := 100
	start := time.Now()
	var kp *primitives.KeyPair
	for i := 0; i < iterations; i++ {
		kp, _ = primitives.GenerateKeyPair()
	}
	keygenTime := time.Since(start) / time.Duration(iterations)
	fmt.Printf("KeyGen:     %v per operation\n", keygenTime)

	// Sign
	message := primitives.Keccak256([]byte("Benchmark message"))
	start = time.Now()
	var sig *primitives.Signature
	for i := 0; i < iterations; i++ {
		kp, _ = primitives.GenerateKeyPair()
		sig, _ = primitives.Sign(kp.Private, message)
	}
	signTime := time.Since(start) / time.Duration(iterations)
	fmt.Printf("Sign:       %v per operation\n", signTime)

	// Verify
	kp, _ = primitives.GenerateKeyPair()
	sig = primitives.SignUnsafe(kp.Private, message)
	start = time.Now()
	for i := 0; i < iterations; i++ {
		primitives.Verify(kp.Public, message, sig)
	}
	verifyTime := time.Since(start) / time.Duration(iterations)
	fmt.Printf("Verify:     %v per operation\n", verifyTime)

	// PKH
	start = time.Now()
	for i := 0; i < iterations; i++ {
		_ = kp.Public.Hash()
	}
	pkhTime := time.Since(start) / time.Duration(iterations)
	fmt.Printf("PKH:        %v per operation\n", pkhTime)

	// Threshold (3-of-5)
	shares, pub, _ := threshold.GenerateShares(5)
	var moduleAddr [20]byte
	config, _ := threshold.NewConfig(3, 5, "bench", 1, moduleAddr)
	var safeTxHash, nextPKH [32]byte
	msg := config.ComputeMessage(safeTxHash, nextPKH)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		partials := make([]*threshold.PartialSignature, 3)
		for j := 0; j < 3; j++ {
			partials[j] = threshold.CreatePartialSignature(shares[j], msg)
		}
		_, _ = threshold.Aggregate(partials)
	}
	thresholdTime := time.Since(start) / time.Duration(iterations)
	fmt.Printf("Threshold:  %v per operation (3-of-5)\n", thresholdTime)

	fmt.Printf("\nSizes:\n")
	fmt.Printf("Private Key: %d bytes (%.1f KB)\n", primitives.PrivateKeySize, float64(primitives.PrivateKeySize)/1024)
	fmt.Printf("Public Key:  %d bytes (%.1f KB)\n", primitives.PublicKeySize, float64(primitives.PublicKeySize)/1024)
	fmt.Printf("Signature:   %d bytes (%.1f KB)\n", primitives.SignatureSize, float64(primitives.SignatureSize)/1024)
	fmt.Printf("PKH:         %d bytes\n", primitives.PublicKeyHashSize)

	_ = pub
}
