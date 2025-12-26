// Package primitives provides core Lamport one-time signature types and operations.
//
// Lamport signatures are hash-based and provide quantum resistance using only
// Keccak-256 - no special cryptographic assumptions beyond hash function security.
//
// SECURITY: Each Lamport key pair MUST only be used to sign ONE message.
// Signing two messages with the same key reveals half of the private key,
// potentially allowing forgery.
//
// See: LP-4105 (Lamport OTS for Lux Safe)
package primitives

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/sha3"
)

const (
	// KeyBits is the number of bits in the message (256 for keccak256 output)
	KeyBits = 256

	// PreimageSize is the size of each private key preimage (32 bytes)
	PreimageSize = 32

	// HashSize is the size of keccak256 output (32 bytes)
	HashSize = 32

	// PrivateKeySize is the total size of a Lamport private key
	// 256 bits * 2 sides * 32 bytes = 16,384 bytes
	PrivateKeySize = KeyBits * 2 * PreimageSize

	// PublicKeySize is the total size of a Lamport public key
	// 256 bits * 2 sides * 32 bytes = 16,384 bytes
	PublicKeySize = KeyBits * 2 * HashSize

	// SignatureSize is the size of a Lamport signature
	// 256 revealed preimages * 32 bytes = 8,192 bytes
	SignatureSize = KeyBits * PreimageSize

	// PublicKeyHashSize is 32 bytes (keccak256 of public key)
	PublicKeyHashSize = 32
)

var (
	// ErrInvalidPublicKey indicates the public key format is invalid
	ErrInvalidPublicKey = errors.New("lamport: invalid public key")

	// ErrInvalidSignature indicates the signature format is invalid
	ErrInvalidSignature = errors.New("lamport: invalid signature")

	// ErrKeyAlreadyUsed indicates an attempt to reuse a one-time key
	ErrKeyAlreadyUsed = errors.New("lamport: key already used (one-time property violated)")

	// ErrVerificationFailed indicates signature verification failed
	ErrVerificationFailed = errors.New("lamport: signature verification failed")

	// ErrInvalidMessage indicates the message format is invalid
	ErrInvalidMessage = errors.New("lamport: invalid message (must be 32 bytes)")

	// ErrKeyChainExhausted indicates no more keys available in chain
	ErrKeyChainExhausted = errors.New("lamport: key chain exhausted")
)

// PrivateKey represents a Lamport private key.
// It consists of 256 pairs of 32-byte preimages.
// SECURITY: This key MUST only be used to sign ONE message.
type PrivateKey struct {
	// Preimages is [256][2][32]byte - preimage[i][bit] for each bit position
	Preimages [KeyBits][2][PreimageSize]byte

	// Used tracks whether this key has been used (one-time property)
	Used bool
}

// PublicKey represents a Lamport public key.
// It consists of 256 pairs of 32-byte hashes (keccak256 of preimages).
type PublicKey struct {
	// Hashes is [256][2][32]byte - hash[i][bit] for each bit position
	Hashes [KeyBits][2][HashSize]byte
}

// Signature represents a Lamport signature.
// It consists of 256 revealed preimages (one for each bit of the message).
type Signature struct {
	// Preimages is [256][32]byte - the revealed preimage for each bit
	Preimages [KeyBits][PreimageSize]byte
}

// KeyPair holds a Lamport key pair for convenience.
type KeyPair struct {
	Private *PrivateKey
	Public  *PublicKey
}

// KeyChain manages a chain of one-time Lamport keys for continuous operation.
// As each key is used, the next key in the chain becomes active.
type KeyChain struct {
	// Keys is the list of available key pairs
	Keys []*KeyPair

	// CurrentIndex is the index of the current (unused) key
	CurrentIndex int

	// UsedCount tracks how many keys have been used
	UsedCount int
}

// Keccak256 computes the Keccak-256 hash of data.
func Keccak256(data []byte) [HashSize]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var result [HashSize]byte
	h.Sum(result[:0])
	return result
}

// Keccak256Multi computes keccak256 of multiple byte slices.
func Keccak256Multi(parts ...[]byte) [HashSize]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var result [HashSize]byte
	h.Sum(result[:0])
	return result
}

// Bytes serializes the public key to bytes.
func (pk *PublicKey) Bytes() []byte {
	out := make([]byte, PublicKeySize)
	for i := 0; i < KeyBits; i++ {
		copy(out[i*64:i*64+32], pk.Hashes[i][0][:])
		copy(out[i*64+32:i*64+64], pk.Hashes[i][1][:])
	}
	return out
}

// Hash returns the keccak256 hash of the public key (PKH).
// This is used on-chain to store a compact representation.
func (pk *PublicKey) Hash() [PublicKeyHashSize]byte {
	return Keccak256(pk.Bytes())
}

// FromBytes deserializes a public key from bytes.
func (pk *PublicKey) FromBytes(data []byte) error {
	if len(data) != PublicKeySize {
		return ErrInvalidPublicKey
	}
	for i := 0; i < KeyBits; i++ {
		copy(pk.Hashes[i][0][:], data[i*64:i*64+32])
		copy(pk.Hashes[i][1][:], data[i*64+32:i*64+64])
	}
	return nil
}

// Bytes serializes the signature to bytes.
func (sig *Signature) Bytes() []byte {
	out := make([]byte, SignatureSize)
	for i := 0; i < KeyBits; i++ {
		copy(out[i*32:(i+1)*32], sig.Preimages[i][:])
	}
	return out
}

// FromBytes deserializes a signature from bytes.
func (sig *Signature) FromBytes(data []byte) error {
	if len(data) != SignatureSize {
		return ErrInvalidSignature
	}
	for i := 0; i < KeyBits; i++ {
		copy(sig.Preimages[i][:], data[i*32:(i+1)*32])
	}
	return nil
}

// ToCalldata converts the signature to Solidity-compatible calldata format.
// Returns bytes[256] for use with verify_u256.
func (sig *Signature) ToCalldata() [][]byte {
	result := make([][]byte, KeyBits)
	for i := 0; i < KeyBits; i++ {
		preimage := make([]byte, PreimageSize)
		copy(preimage, sig.Preimages[i][:])
		result[i] = preimage
	}
	return result
}

// ToCalldata converts public key to bytes32[2][256] for Solidity.
func (pk *PublicKey) ToCalldata() [KeyBits][2][HashSize]byte {
	return pk.Hashes
}

// ComputeDomainSeparator computes the domain separator for threshold signing.
func ComputeDomainSeparator(moduleAddress [20]byte, chainID uint64) [32]byte {
	var buf [52]byte // 20 + 32 for chainID as uint256
	copy(buf[:20], moduleAddress[:])
	binary.BigEndian.PutUint64(buf[44:52], chainID) // Right-aligned like Solidity uint256
	return Keccak256(buf[:])
}

// ComputeThresholdMessage computes the final message for threshold signing.
// This matches the Solidity: keccak256(abi.encodePacked(safeTxHash, nextPKH, address(this), block.chainid))
func ComputeThresholdMessage(safeTxHash, nextPKH [32]byte, moduleAddress [20]byte, chainID uint64) [32]byte {
	var buf [116]byte // 32 + 32 + 20 + 32 (chainid as uint256)
	copy(buf[0:32], safeTxHash[:])
	copy(buf[32:64], nextPKH[:])
	copy(buf[64:84], moduleAddress[:])
	binary.BigEndian.PutUint64(buf[108:116], chainID)
	return Keccak256(buf[:])
}

// GenerateKeyPair generates a new Lamport key pair using crypto/rand.
func GenerateKeyPair() (*KeyPair, error) {
	return GenerateKeyPairFromReader(rand.Reader)
}

// GenerateKeyPairFromReader generates a new Lamport key pair from the given random source.
func GenerateKeyPairFromReader(random io.Reader) (*KeyPair, error) {
	priv := &PrivateKey{}
	pub := &PublicKey{}

	// Generate random preimages and compute public key hashes
	for i := 0; i < KeyBits; i++ {
		for bit := 0; bit < 2; bit++ {
			if _, err := io.ReadFull(random, priv.Preimages[i][bit][:]); err != nil {
				return nil, err
			}
			pub.Hashes[i][bit] = Keccak256(priv.Preimages[i][bit][:])
		}
	}

	return &KeyPair{Private: priv, Public: pub}, nil
}

// NewKeyChain creates a new key chain with the specified number of keys.
func NewKeyChain(numKeys int) (*KeyChain, error) {
	if numKeys <= 0 {
		return nil, errors.New("lamport: numKeys must be positive")
	}

	chain := &KeyChain{
		Keys:         make([]*KeyPair, numKeys),
		CurrentIndex: 0,
		UsedCount:    0,
	}

	for i := 0; i < numKeys; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		chain.Keys[i] = kp
	}

	return chain, nil
}

// Current returns the current (unused) key pair.
func (kc *KeyChain) Current() (*KeyPair, error) {
	if kc.CurrentIndex >= len(kc.Keys) {
		return nil, ErrKeyChainExhausted
	}
	return kc.Keys[kc.CurrentIndex], nil
}

// NextPKH returns the hash of the next public key (for key rotation).
func (kc *KeyChain) NextPKH() ([32]byte, error) {
	nextIdx := kc.CurrentIndex + 1
	if nextIdx >= len(kc.Keys) {
		return [32]byte{}, errors.New("lamport: no next key available")
	}
	return kc.Keys[nextIdx].Public.Hash(), nil
}

// Advance marks the current key as used and advances to the next.
func (kc *KeyChain) Advance() error {
	if kc.CurrentIndex >= len(kc.Keys) {
		return ErrKeyChainExhausted
	}
	kc.Keys[kc.CurrentIndex].Private.Used = true
	kc.CurrentIndex++
	kc.UsedCount++
	return nil
}

// Remaining returns the number of unused keys remaining.
func (kc *KeyChain) Remaining() int {
	return len(kc.Keys) - kc.CurrentIndex
}

// GetBit returns the bit at position i (0-255) of a 32-byte message.
// Bit 0 is the most significant bit of the first byte.
func GetBit(message [32]byte, i int) int {
	byteIdx := i / 8
	bitIdx := 7 - (i % 8)
	return int((message[byteIdx] >> bitIdx) & 1)
}
