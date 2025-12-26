package primitives

// Sign creates a Lamport signature for a 32-byte message.
//
// SECURITY: This function should only be called ONCE per private key.
// The key is marked as used after signing to prevent accidental reuse.
//
// The signature reveals one preimage for each bit of the message:
//   - If bit i is 0, reveal preimage[i][0]
//   - If bit i is 1, reveal preimage[i][1]
func Sign(priv *PrivateKey, message [32]byte) (*Signature, error) {
	if priv.Used {
		return nil, ErrKeyAlreadyUsed
	}

	sig := &Signature{}

	for i := 0; i < KeyBits; i++ {
		bit := GetBit(message, i)
		sig.Preimages[i] = priv.Preimages[i][bit]
	}

	// Mark key as used
	priv.Used = true

	return sig, nil
}

// SignBytes signs a 32-byte message slice.
func SignBytes(priv *PrivateKey, message []byte) (*Signature, error) {
	if len(message) != 32 {
		return nil, ErrInvalidMessage
	}
	var msg [32]byte
	copy(msg[:], message)
	return Sign(priv, msg)
}

// signUnsafe signs without marking the key as used.
// INTERNAL: Only accessible within this package for testing.
func signUnsafe(priv *PrivateKey, message [32]byte) *Signature {
	sig := &Signature{}

	for i := 0; i < KeyBits; i++ {
		bit := GetBit(message, i)
		sig.Preimages[i] = priv.Preimages[i][bit]
	}

	return sig
}

// SignWithKeyChain signs a message using the current key in the chain
// and automatically advances to the next key.
func SignWithKeyChain(chain *KeyChain, message [32]byte) (*Signature, [32]byte, error) {
	kp, err := chain.Current()
	if err != nil {
		return nil, [32]byte{}, err
	}

	sig, err := Sign(kp.Private, message)
	if err != nil {
		return nil, [32]byte{}, err
	}

	// Get next PKH before advancing (if available)
	var nextPKH [32]byte
	if chain.CurrentIndex+1 < len(chain.Keys) {
		nextPKH = chain.Keys[chain.CurrentIndex+1].Public.Hash()
	}

	// Advance to next key
	if err := chain.Advance(); err != nil {
		return nil, [32]byte{}, err
	}

	return sig, nextPKH, nil
}

// SignThresholdMessage signs a domain-separated threshold message.
// This is the format used for T-Chain MPC Lamport signing.
func SignThresholdMessage(
	priv *PrivateKey,
	safeTxHash [32]byte,
	nextPKH [32]byte,
	moduleAddress [20]byte,
	chainID uint64,
) (*Signature, error) {
	// Compute the domain-separated message
	message := ComputeThresholdMessage(safeTxHash, nextPKH, moduleAddress, chainID)
	return Sign(priv, message)
}
