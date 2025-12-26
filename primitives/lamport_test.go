package primitives

import (
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if kp.Private == nil {
		t.Error("Private key is nil")
	}
	if kp.Public == nil {
		t.Error("Public key is nil")
	}
	if kp.Private.Used {
		t.Error("New key should not be marked as used")
	}

	// Verify public key is hash of private key preimages
	for i := 0; i < KeyBits; i++ {
		for bit := 0; bit < 2; bit++ {
			expected := Keccak256(kp.Private.Preimages[i][bit][:])
			if kp.Public.Hashes[i][bit] != expected {
				t.Errorf("Public key hash mismatch at position %d, bit %d", i, bit)
			}
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Create a test message
	message := Keccak256([]byte("Hello, quantum-safe world!"))

	// Sign the message
	sig, err := Sign(kp.Private, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify the signature
	if !Verify(kp.Public, message, sig) {
		t.Error("Valid signature failed verification")
	}

	// Key should be marked as used
	if !kp.Private.Used {
		t.Error("Key should be marked as used after signing")
	}

	// Attempting to sign again should fail
	_, err = Sign(kp.Private, message)
	if err != ErrKeyAlreadyUsed {
		t.Errorf("Expected ErrKeyAlreadyUsed, got %v", err)
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := Keccak256([]byte("Test message"))
	sig, _ := Sign(kp.Private, message)

	// Modify the signature
	sig.Preimages[0][0] ^= 0xFF

	// Verification should fail
	if Verify(kp.Public, message, sig) {
		t.Error("Modified signature should fail verification")
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message1 := Keccak256([]byte("Message 1"))
	message2 := Keccak256([]byte("Message 2"))

	sig, _ := Sign(kp.Private, message1)

	// Verification with wrong message should fail
	if Verify(kp.Public, message2, sig) {
		t.Error("Signature for different message should fail verification")
	}
}

func TestPublicKeySerialization(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Serialize
	data := kp.Public.Bytes()
	if len(data) != PublicKeySize {
		t.Errorf("Expected %d bytes, got %d", PublicKeySize, len(data))
	}

	// Deserialize
	pub2 := &PublicKey{}
	if err := pub2.FromBytes(data); err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}

	// Compare
	for i := 0; i < KeyBits; i++ {
		for bit := 0; bit < 2; bit++ {
			if kp.Public.Hashes[i][bit] != pub2.Hashes[i][bit] {
				t.Errorf("Deserialized public key mismatch at position %d, bit %d", i, bit)
			}
		}
	}
}

func TestSignatureSerialization(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := Keccak256([]byte("Test"))
	sig, _ := Sign(kp.Private, message)

	// Serialize
	data := sig.Bytes()
	if len(data) != SignatureSize {
		t.Errorf("Expected %d bytes, got %d", SignatureSize, len(data))
	}

	// Deserialize
	sig2 := &Signature{}
	if err := sig2.FromBytes(data); err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}

	// Compare
	for i := 0; i < KeyBits; i++ {
		if sig.Preimages[i] != sig2.Preimages[i] {
			t.Errorf("Deserialized signature mismatch at position %d", i)
		}
	}

	// Verify deserialized signature works
	if !Verify(kp.Public, message, sig2) {
		t.Error("Deserialized signature should verify")
	}
}

func TestPublicKeyHash(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pkh := kp.Public.Hash()
	if len(pkh) != PublicKeyHashSize {
		t.Errorf("Expected %d bytes, got %d", PublicKeyHashSize, len(pkh))
	}

	// Same public key should produce same hash
	pkh2 := kp.Public.Hash()
	if pkh != pkh2 {
		t.Error("Same public key should produce same hash")
	}

	// Different public key should produce different hash
	kp2, _ := GenerateKeyPair()
	pkh3 := kp2.Public.Hash()
	if pkh == pkh3 {
		t.Error("Different public keys should produce different hashes")
	}
}

func TestKeyChain(t *testing.T) {
	chain, err := NewKeyChain(5)
	if err != nil {
		t.Fatalf("NewKeyChain failed: %v", err)
	}

	if chain.Remaining() != 5 {
		t.Errorf("Expected 5 remaining, got %d", chain.Remaining())
	}

	// Get current key
	kp1, err := chain.Current()
	if err != nil {
		t.Fatalf("Current failed: %v", err)
	}

	// Get next PKH
	nextPKH, err := chain.NextPKH()
	if err != nil {
		t.Fatalf("NextPKH failed: %v", err)
	}

	// Sign with current key
	message := Keccak256([]byte("Test"))
	sig, _, err := SignWithKeyChain(chain, message)
	if err != nil {
		t.Fatalf("SignWithKeyChain failed: %v", err)
	}

	// Verify signature
	if !Verify(kp1.Public, message, sig) {
		t.Error("Signature should verify")
	}

	// Chain should have advanced
	if chain.Remaining() != 4 {
		t.Errorf("Expected 4 remaining, got %d", chain.Remaining())
	}

	// Current key should now be different
	kp2, _ := chain.Current()
	if kp2.Public.Hash() != nextPKH {
		t.Error("Current key should match previous nextPKH")
	}

	// Use remaining keys
	for i := 0; i < 4; i++ {
		msg := Keccak256([]byte{byte(i)})
		_, _, err := SignWithKeyChain(chain, msg)
		if err != nil {
			t.Fatalf("SignWithKeyChain failed on iteration %d: %v", i, err)
		}
	}

	// Chain should be exhausted
	if chain.Remaining() != 0 {
		t.Errorf("Expected 0 remaining, got %d", chain.Remaining())
	}

	// Further signing should fail
	_, _, err = SignWithKeyChain(chain, message)
	if err != ErrKeyChainExhausted {
		t.Errorf("Expected ErrKeyChainExhausted, got %v", err)
	}
}

func TestGetBit(t *testing.T) {
	// Test with known values
	var msg [32]byte
	msg[0] = 0x80 // 10000000 in binary

	if GetBit(msg, 0) != 1 {
		t.Error("Bit 0 should be 1")
	}
	if GetBit(msg, 1) != 0 {
		t.Error("Bit 1 should be 0")
	}

	msg[0] = 0xFF // 11111111 in binary
	for i := 0; i < 8; i++ {
		if GetBit(msg, i) != 1 {
			t.Errorf("Bit %d should be 1", i)
		}
	}
}

func TestComputeThresholdMessage(t *testing.T) {
	var safeTxHash [32]byte
	var nextPKH [32]byte
	var moduleAddress [20]byte
	chainID := uint64(96369)

	// Fill with test data
	for i := range safeTxHash {
		safeTxHash[i] = byte(i)
	}
	for i := range nextPKH {
		nextPKH[i] = byte(i + 32)
	}
	for i := range moduleAddress {
		moduleAddress[i] = byte(i + 64)
	}

	msg := ComputeThresholdMessage(safeTxHash, nextPKH, moduleAddress, chainID)

	// Message should be deterministic
	msg2 := ComputeThresholdMessage(safeTxHash, nextPKH, moduleAddress, chainID)
	if msg != msg2 {
		t.Error("Same inputs should produce same message")
	}

	// Different chainID should produce different message
	msg3 := ComputeThresholdMessage(safeTxHash, nextPKH, moduleAddress, chainID+1)
	if msg == msg3 {
		t.Error("Different chainID should produce different message")
	}
}

func TestVerifyU256(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := Keccak256([]byte("Test U256"))
	sig := SignUnsafe(kp.Private, message)

	// Convert to U256 format
	var sigArray [KeyBits][PreimageSize]byte
	copy(sigArray[:], sig.Preimages[:])

	// Verify using U256 format
	if !VerifyU256(message, sigArray, kp.Public.Hashes) {
		t.Error("VerifyU256 should succeed for valid signature")
	}

	// Modify and verify failure
	sigArray[0][0] ^= 0xFF
	if VerifyU256(message, sigArray, kp.Public.Hashes) {
		t.Error("VerifyU256 should fail for modified signature")
	}
}

func TestToCalldata(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := Keccak256([]byte("Calldata test"))
	sig := SignUnsafe(kp.Private, message)

	// Test signature calldata
	calldata := sig.ToCalldata()
	if len(calldata) != KeyBits {
		t.Errorf("Expected %d elements, got %d", KeyBits, len(calldata))
	}
	for i, data := range calldata {
		if len(data) != PreimageSize {
			t.Errorf("Element %d has wrong size: %d", i, len(data))
		}
	}

	// Test public key calldata
	pubCalldata := kp.Public.ToCalldata()
	if len(pubCalldata) != KeyBits {
		t.Errorf("Expected %d elements, got %d", KeyBits, len(pubCalldata))
	}
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKeyPair()
	}
}

func BenchmarkSign(b *testing.B) {
	message := Keccak256([]byte("Benchmark"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kp, _ := GenerateKeyPair()
		_, _ = Sign(kp.Private, message)
	}
}

func BenchmarkVerify(b *testing.B) {
	kp, _ := GenerateKeyPair()
	message := Keccak256([]byte("Benchmark"))
	sig := SignUnsafe(kp.Private, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(kp.Public, message, sig)
	}
}

func BenchmarkPublicKeyHash(b *testing.B) {
	kp, _ := GenerateKeyPair()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = kp.Public.Hash()
	}
}

// Fuzz test for sign/verify
func FuzzSignVerify(f *testing.F) {
	f.Add([]byte("seed1"))
	f.Add([]byte("seed2"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		kp, err := GenerateKeyPair()
		if err != nil {
			return
		}

		message := Keccak256(data)
		sig, err := Sign(kp.Private, message)
		if err != nil {
			return
		}

		if !Verify(kp.Public, message, sig) {
			t.Error("Valid signature failed verification")
		}
	})
}
