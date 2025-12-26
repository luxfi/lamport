// Package precompile provides the EVM precompile interface for Lamport signatures.
//
// The Lamport precompile enables gas-efficient on-chain verification for
// Lux-native chains. For remote chains, use the pure Solidity verifier.
//
// Precompile Address: 0x0200000000000000000000000000000000000006
//
// Input format (ABI-encoded):
//   - message: bytes32 (32 bytes)
//   - signature: bytes[256] (256 * 32 = 8192 bytes)
//   - publicKey: bytes32[2][256] (256 * 2 * 32 = 16384 bytes)
//
// Output: bool (32 bytes, ABI-encoded)
//
// Gas cost: 3000 base + 50 per hash check = ~15,800 gas
// (vs ~100,000+ gas for pure Solidity verification)
package precompile

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/lamport/primitives"
)

const (
	// PrecompileAddress is the address of the Lamport precompile
	PrecompileAddress = "0x0200000000000000000000000000000000000006"

	// GasBase is the base gas cost
	GasBase = 3000

	// GasPerHash is the gas cost per keccak256 hash verification
	GasPerHash = 50

	// TotalGas is the total gas for verification (256 hashes)
	TotalGas = GasBase + (primitives.KeyBits * GasPerHash) // 15,800

	// InputSizeMessage is the size of the message input (32 bytes)
	InputSizeMessage = 32

	// InputSizeSignature is the size of the signature input
	InputSizeSignature = primitives.SignatureSize // 8192

	// InputSizePublicKey is the size of the public key input
	InputSizePublicKey = primitives.PublicKeySize // 16384

	// MinInputSize is the minimum valid input size
	MinInputSize = InputSizeMessage + InputSizeSignature + InputSizePublicKey // 24608
)

var (
	// ErrInvalidInput indicates the input format is invalid
	ErrInvalidInput = errors.New("lamport precompile: invalid input")

	// ErrOutOfGas indicates insufficient gas for verification
	ErrOutOfGas = errors.New("lamport precompile: out of gas")
)

// PrecompileContract implements the Lamport verification precompile.
type PrecompileContract struct{}

// RequiredGas returns the gas required for the input.
func (c *PrecompileContract) RequiredGas(input []byte) uint64 {
	if len(input) < MinInputSize {
		return 0 // Invalid input, will fail in Run
	}
	return TotalGas
}

// Run executes the Lamport verification precompile.
//
// Input format:
//   [0:32]     - message (bytes32)
//   [32:8224]  - signature (bytes[256], each element is 32 bytes)
//   [8224:24608] - publicKey (bytes32[2][256])
//
// Returns:
//   - 32 bytes: ABI-encoded bool (1 = valid, 0 = invalid)
func (c *PrecompileContract) Run(input []byte) ([]byte, error) {
	if len(input) < MinInputSize {
		return nil, ErrInvalidInput
	}

	// Parse message (bytes32)
	var message [32]byte
	copy(message[:], input[0:32])

	// Parse signature (bytes[256])
	var sig primitives.Signature
	for i := 0; i < primitives.KeyBits; i++ {
		offset := 32 + (i * 32)
		copy(sig.Preimages[i][:], input[offset:offset+32])
	}

	// Parse public key (bytes32[2][256])
	var pub primitives.PublicKey
	pubOffset := 32 + primitives.SignatureSize
	for i := 0; i < primitives.KeyBits; i++ {
		offset0 := pubOffset + (i * 64)
		offset1 := offset0 + 32
		copy(pub.Hashes[i][0][:], input[offset0:offset0+32])
		copy(pub.Hashes[i][1][:], input[offset1:offset1+32])
	}

	// Verify signature
	valid := primitives.Verify(&pub, message, &sig)

	// Return ABI-encoded bool
	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}
	return result, nil
}

// EncodeInput encodes the verification inputs for the precompile.
func EncodeInput(message [32]byte, sig *primitives.Signature, pub *primitives.PublicKey) []byte {
	input := make([]byte, MinInputSize)

	// Encode message
	copy(input[0:32], message[:])

	// Encode signature
	for i := 0; i < primitives.KeyBits; i++ {
		copy(input[32+(i*32):32+(i*32)+32], sig.Preimages[i][:])
	}

	// Encode public key
	pubOffset := 32 + primitives.SignatureSize
	for i := 0; i < primitives.KeyBits; i++ {
		copy(input[pubOffset+(i*64):pubOffset+(i*64)+32], pub.Hashes[i][0][:])
		copy(input[pubOffset+(i*64)+32:pubOffset+(i*64)+64], pub.Hashes[i][1][:])
	}

	return input
}

// DecodeOutput decodes the precompile output to a boolean.
func DecodeOutput(output []byte) bool {
	if len(output) < 32 {
		return false
	}
	return output[31] == 1
}

// ABIEncodedSignature converts a signature to ABI-encoded format.
// This is useful for generating calldata for Solidity contracts.
func ABIEncodedSignature(sig *primitives.Signature) []byte {
	// ABI-encoded dynamic array: offset (32) + length (32) + data (256 * 32)
	// For simplicity, we just encode the raw preimages
	return sig.Bytes()
}

// ABIEncodedPublicKey converts a public key to ABI-encoded format.
func ABIEncodedPublicKey(pub *primitives.PublicKey) []byte {
	return pub.Bytes()
}

// PrecompileAddressBytes returns the precompile address as bytes.
func PrecompileAddressBytes() [20]byte {
	var addr [20]byte
	addr[1] = 0x02 // 0x0200...006
	addr[19] = 0x06
	return addr
}

// GasEstimate returns the estimated gas for verification.
func GasEstimate() uint64 {
	return TotalGas
}

// InputBuilder helps construct precompile input.
type InputBuilder struct {
	data []byte
}

// NewInputBuilder creates a new input builder.
func NewInputBuilder() *InputBuilder {
	return &InputBuilder{
		data: make([]byte, 0, MinInputSize),
	}
}

// SetMessage sets the message (bytes32).
func (b *InputBuilder) SetMessage(message [32]byte) *InputBuilder {
	if len(b.data) < 32 {
		b.data = append(b.data, make([]byte, 32-len(b.data))...)
	}
	copy(b.data[0:32], message[:])
	return b
}

// SetSignature sets the signature.
func (b *InputBuilder) SetSignature(sig *primitives.Signature) *InputBuilder {
	if len(b.data) < 32+primitives.SignatureSize {
		b.data = append(b.data, make([]byte, 32+primitives.SignatureSize-len(b.data))...)
	}
	for i := 0; i < primitives.KeyBits; i++ {
		copy(b.data[32+(i*32):], sig.Preimages[i][:])
	}
	return b
}

// SetPublicKey sets the public key.
func (b *InputBuilder) SetPublicKey(pub *primitives.PublicKey) *InputBuilder {
	if len(b.data) < MinInputSize {
		b.data = append(b.data, make([]byte, MinInputSize-len(b.data))...)
	}
	offset := 32 + primitives.SignatureSize
	for i := 0; i < primitives.KeyBits; i++ {
		copy(b.data[offset+(i*64):], pub.Hashes[i][0][:])
		copy(b.data[offset+(i*64)+32:], pub.Hashes[i][1][:])
	}
	return b
}

// Build returns the constructed input.
func (b *InputBuilder) Build() []byte {
	return b.data
}

// Uint256 helper for Solidity compatibility
func uint256ToBytes(n uint64) []byte {
	result := make([]byte, 32)
	binary.BigEndian.PutUint64(result[24:32], n)
	return result
}
