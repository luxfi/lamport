// Package threshold provides T-Chain MPC integration for Lamport signatures.
//
// The key insight is that threshold control lives OFF-CHAIN in the T-Chain MPC network.
// On-chain sees ONE standard Lamport signature - works on ANY EVM chain without precompiles!
//
// SECURITY MODEL:
//   - Threshold property (t-of-n) enforced by T-Chain MPC network
//   - Each MPC node holds shares of ONE Lamport private key
//   - Partial signatures aggregated to form complete Lamport signature
//   - On-chain verifies normal keccak256 hashes
//
// ATTACK MITIGATIONS:
//   - Canonical digest: Every node computes safeTxHash locally
//   - 1-round digest agreement: Broadcast H(safeTxHash) BEFORE revealing material
//   - Domain separation: chainId + moduleAddress prevent replay
//   - One-time keys: nextPKH rotation after each signature
//
// See: LP-4105 (Lamport OTS for Lux Safe)
package threshold

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/luxfi/lamport/primitives"
)

// Config holds configuration for threshold MPC Lamport signing.
type Config struct {
	// Threshold is the minimum number of parties needed to sign (t in t-of-n)
	Threshold int

	// TotalParties is the total number of parties (n in t-of-n)
	TotalParties int

	// PartyID is this party's identifier
	PartyID string

	// ChainID for domain separation (prevents cross-chain replay)
	ChainID uint64

	// ModuleAddress for domain separation (prevents cross-contract replay)
	ModuleAddress [20]byte
}

// Share represents a party's share of a Lamport private key.
// In threshold Lamport, each party holds shares of the preimages.
type Share struct {
	// PartyID identifies which party owns this share
	PartyID string

	// PreimageShares holds this party's shares for each bit position
	// For simple additive sharing: sum of all shares = actual preimage
	PreimageShares [primitives.KeyBits][2][primitives.PreimageSize]byte

	// Index is this party's index (1 to n)
	Index int
}

// PartialSignature is a party's contribution to the threshold signature.
type PartialSignature struct {
	// PartyID identifies which party created this partial
	PartyID string

	// Index is the party's index
	Index int

	// PreimagePartials contains the revealed partial preimages
	// Only the bits corresponding to the message are populated
	PreimagePartials [primitives.KeyBits][primitives.PreimageSize]byte

	// BitMask indicates which bits were included (for verification)
	BitMask [32]byte
}

// DigestCommitment is used for 1-round digest agreement.
// Each party broadcasts H(safeTxHash) BEFORE revealing any signing material.
type DigestCommitment struct {
	PartyID    string
	Commitment [32]byte // H(safeTxHash || partyID)
}

var (
	// ErrInvalidThreshold indicates invalid threshold parameters
	ErrInvalidThreshold = errors.New("threshold: invalid threshold (must be 1 <= t <= n)")

	// ErrNotEnoughParties indicates insufficient parties for threshold
	ErrNotEnoughParties = errors.New("threshold: not enough parties to meet threshold")

	// ErrDigestMismatch indicates parties disagreed on the message
	ErrDigestMismatch = errors.New("threshold: digest mismatch - parties disagree on message")

	// ErrInvalidPartial indicates a partial signature failed verification
	ErrInvalidPartial = errors.New("threshold: invalid partial signature")
)

// NewConfig creates a new threshold configuration.
func NewConfig(threshold, totalParties int, partyID string, chainID uint64, moduleAddr [20]byte) (*Config, error) {
	if threshold < 1 || threshold > totalParties {
		return nil, ErrInvalidThreshold
	}
	return &Config{
		Threshold:     threshold,
		TotalParties:  totalParties,
		PartyID:       partyID,
		ChainID:       chainID,
		ModuleAddress: moduleAddr,
	}, nil
}

// ComputeMessage computes the domain-separated message for threshold signing.
// This MUST be computed locally by each party - never accept from coordinator!
func (c *Config) ComputeMessage(safeTxHash, nextPKH [32]byte) [32]byte {
	return primitives.ComputeThresholdMessage(safeTxHash, nextPKH, c.ModuleAddress, c.ChainID)
}

// CreateDigestCommitment creates a commitment to the safeTxHash.
// This is broadcast in round 1 before any signing material is revealed.
func (c *Config) CreateDigestCommitment(safeTxHash [32]byte) DigestCommitment {
	// Commitment = H(safeTxHash || partyID)
	h := primitives.Keccak256Multi(safeTxHash[:], []byte(c.PartyID))
	return DigestCommitment{
		PartyID:    c.PartyID,
		Commitment: h,
	}
}

// VerifyDigestCommitment verifies another party's commitment matches the expected digest.
func VerifyDigestCommitment(commitment DigestCommitment, safeTxHash [32]byte) bool {
	expected := primitives.Keccak256Multi(safeTxHash[:], []byte(commitment.PartyID))
	return commitment.Commitment == expected
}

// GenerateShares generates n shares of a Lamport private key for threshold signing.
// This uses simple additive secret sharing.
//
// For Shamir-style sharing with t-of-n, use GenerateSharesShamir.
func GenerateShares(n int) ([]*Share, *primitives.PublicKey, error) {
	return GenerateSharesFromReader(n, rand.Reader)
}

// GenerateSharesFromReader generates shares using a specific random source.
func GenerateSharesFromReader(n int, random io.Reader) ([]*Share, *primitives.PublicKey, error) {
	shares := make([]*Share, n)
	pub := &primitives.PublicKey{}

	// For each bit position
	for i := 0; i < primitives.KeyBits; i++ {
		for bit := 0; bit < 2; bit++ {
			// Generate n-1 random shares
			var actualPreimage [primitives.PreimageSize]byte
			if _, err := io.ReadFull(random, actualPreimage[:]); err != nil {
				return nil, nil, err
			}

			// Compute public key hash
			pub.Hashes[i][bit] = primitives.Keccak256(actualPreimage[:])

			// Create shares: n-1 random, last one = preimage - sum(others)
			var sum [primitives.PreimageSize]byte
			for j := 0; j < n-1; j++ {
				if shares[j] == nil {
					shares[j] = &Share{Index: j + 1}
				}
				if _, err := io.ReadFull(random, shares[j].PreimageShares[i][bit][:]); err != nil {
					return nil, nil, err
				}
				// Add to sum
				for k := 0; k < primitives.PreimageSize; k++ {
					sum[k] ^= shares[j].PreimageShares[i][bit][k]
				}
			}

			// Last share = preimage XOR sum(others)
			if shares[n-1] == nil {
				shares[n-1] = &Share{Index: n}
			}
			for k := 0; k < primitives.PreimageSize; k++ {
				shares[n-1].PreimageShares[i][bit][k] = actualPreimage[k] ^ sum[k]
			}
		}
	}

	return shares, pub, nil
}

// ReconstructPreimage reconstructs a preimage from shares (for the needed bits only).
// In the MPC protocol, this happens in the aggregation phase.
func ReconstructPreimage(shares []*Share, bitIndex int, bitValue int) [primitives.PreimageSize]byte {
	var result [primitives.PreimageSize]byte
	for _, share := range shares {
		for k := 0; k < primitives.PreimageSize; k++ {
			result[k] ^= share.PreimageShares[bitIndex][bitValue][k]
		}
	}
	return result
}
