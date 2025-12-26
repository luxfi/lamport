package primitives

// Verify checks a Lamport signature against a public key and message.
//
// For each bit i of the message:
//   - If bit i is 0, check keccak256(sig[i]) == pub[i][0]
//   - If bit i is 1, check keccak256(sig[i]) == pub[i][1]
//
// Returns true if all 256 preimages hash to the correct public key values.
// NOTE: This function returns early on mismatch. For side-channel resistance,
// use VerifyConstantTime instead.
func Verify(pub *PublicKey, message [32]byte, sig *Signature) bool {
	for i := 0; i < KeyBits; i++ {
		bit := GetBit(message, i)
		expectedHash := pub.Hashes[i][bit]
		actualHash := Keccak256(sig.Preimages[i][:])

		if actualHash != expectedHash {
			return false
		}
	}
	return true
}

// VerifyConstantTime checks a Lamport signature in constant time.
// Unlike Verify, this function always checks all 256 preimages regardless
// of mismatches, preventing timing side-channel attacks.
//
// Use this when the verification result could be observed by an attacker
// (e.g., through timing analysis).
func VerifyConstantTime(pub *PublicKey, message [32]byte, sig *Signature) bool {
	var mismatch byte // Accumulate mismatches without branching

	for i := 0; i < KeyBits; i++ {
		bit := GetBit(message, i)
		expectedHash := pub.Hashes[i][bit]
		actualHash := Keccak256(sig.Preimages[i][:])

		// XOR each byte and OR into mismatch accumulator
		for j := 0; j < HashSize; j++ {
			mismatch |= expectedHash[j] ^ actualHash[j]
		}
	}

	// mismatch == 0 iff all hashes matched
	return mismatch == 0
}

// VerifyBytes verifies a signature against message bytes.
func VerifyBytes(pub *PublicKey, message []byte, sig *Signature) bool {
	if len(message) != 32 {
		return false
	}
	var msg [32]byte
	copy(msg[:], message)
	return Verify(pub, msg, sig)
}

// VerifyU256 verifies a Lamport signature using uint256 bit representation.
// This matches the Solidity verify_u256 function exactly.
//
// Parameters:
//   - bits: The 256-bit message as a big-endian byte array
//   - sig: Array of 256 preimages
//   - pub: 256x2 array of public key hashes
//
// Returns true if signature is valid.
func VerifyU256(bits [32]byte, sig [KeyBits][PreimageSize]byte, pub [KeyBits][2][HashSize]byte) bool {
	for i := 0; i < KeyBits; i++ {
		// Select pub[i][0] if bit is 0, pub[i][1] if bit is 1
		// Bit ordering: bit 0 is MSB (position 255-i in Solidity's (1 << (255 - i)))
		bit := GetBit(bits, i)

		actualHash := Keccak256(sig[i][:])
		if actualHash != pub[i][bit] {
			return false
		}
	}
	return true
}

// VerifyWithPKH verifies a signature and checks that the public key hashes to expectedPKH.
// This is useful for on-chain verification where only the PKH is stored.
func VerifyWithPKH(pub *PublicKey, message [32]byte, sig *Signature, expectedPKH [32]byte) bool {
	// First check PKH matches
	actualPKH := pub.Hash()
	if actualPKH != expectedPKH {
		return false
	}

	// Then verify signature
	return Verify(pub, message, sig)
}

// VerifyThresholdMessage verifies a threshold Lamport signature with domain separation.
func VerifyThresholdMessage(
	pub *PublicKey,
	sig *Signature,
	safeTxHash [32]byte,
	nextPKH [32]byte,
	moduleAddress [20]byte,
	chainID uint64,
	expectedPKH [32]byte,
) bool {
	// Check PKH
	if pub.Hash() != expectedPKH {
		return false
	}

	// Compute domain-separated message
	message := ComputeThresholdMessage(safeTxHash, nextPKH, moduleAddress, chainID)

	// Verify signature
	return Verify(pub, message, sig)
}

// BatchVerify verifies multiple signatures in parallel.
// Returns a slice of booleans indicating which signatures are valid.
func BatchVerify(pubs []*PublicKey, messages [][32]byte, sigs []*Signature) []bool {
	n := len(pubs)
	if len(messages) != n || len(sigs) != n {
		results := make([]bool, n)
		return results // All false
	}

	results := make([]bool, n)
	for i := 0; i < n; i++ {
		results[i] = Verify(pubs[i], messages[i], sigs[i])
	}
	return results
}
