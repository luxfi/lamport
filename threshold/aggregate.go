package threshold

import (
	"errors"

	"github.com/luxfi/lamport/primitives"
)

// Aggregate combines partial signatures into a complete Lamport signature.
//
// For additive secret sharing:
//   finalPreimage[i] = XOR(partial[0].preimage[i], partial[1].preimage[i], ...)
//
// SECURITY: All partials must be for the same message.
func Aggregate(partials []*PartialSignature) (*primitives.Signature, error) {
	if len(partials) == 0 {
		return nil, ErrNotEnoughParties
	}

	// Verify all partials are for the same message
	expectedMask := partials[0].BitMask
	for _, p := range partials[1:] {
		if p.BitMask != expectedMask {
			return nil, ErrDigestMismatch
		}
	}

	sig := &primitives.Signature{}

	// Combine partials using XOR (additive sharing)
	for i := 0; i < primitives.KeyBits; i++ {
		for _, partial := range partials {
			for k := 0; k < primitives.PreimageSize; k++ {
				sig.Preimages[i][k] ^= partial.PreimagePartials[i][k]
			}
		}
	}

	return sig, nil
}

// AggregateAndVerify combines partials and verifies against the public key.
func AggregateAndVerify(
	partials []*PartialSignature,
	pub *primitives.PublicKey,
	message [32]byte,
) (*primitives.Signature, error) {
	sig, err := Aggregate(partials)
	if err != nil {
		return nil, err
	}

	if !primitives.Verify(pub, message, sig) {
		return nil, ErrInvalidPartial
	}

	return sig, nil
}

// AggregateThreshold performs full threshold aggregation with verification.
//
// This is the coordinator's workflow:
//  1. Collect partial signatures from t parties
//  2. Verify all parties agreed on the same message (via BitMask)
//  3. Aggregate partials into complete signature
//  4. Verify signature against public key
func AggregateThreshold(
	config *Config,
	partials []*PartialSignature,
	pub *primitives.PublicKey,
	safeTxHash [32]byte,
	nextPKH [32]byte,
) (*primitives.Signature, error) {
	if len(partials) < config.Threshold {
		return nil, ErrNotEnoughParties
	}

	// Compute expected message
	message := config.ComputeMessage(safeTxHash, nextPKH)

	// Verify all partials are for the correct message
	for _, p := range partials {
		if p.BitMask != message {
			return nil, ErrDigestMismatch
		}
	}

	return AggregateAndVerify(partials, pub, message)
}

// Coordinator manages the threshold signing protocol.
type Coordinator struct {
	config   *Config
	partials []*PartialSignature
	pub      *primitives.PublicKey
	message  [32]byte

	// Phase tracking
	commitments []DigestCommitment
	phase       int // 0: collecting commitments, 1: collecting partials, 2: done
}

// NewCoordinator creates a new signing coordinator.
func NewCoordinator(config *Config, pub *primitives.PublicKey, safeTxHash, nextPKH [32]byte) *Coordinator {
	return &Coordinator{
		config:      config,
		pub:         pub,
		message:     config.ComputeMessage(safeTxHash, nextPKH),
		commitments: make([]DigestCommitment, 0, config.TotalParties),
		partials:    make([]*PartialSignature, 0, config.Threshold),
		phase:       0,
	}
}

// AddCommitment adds a digest commitment (phase 1).
// Returns true if we have enough commitments to proceed.
func (c *Coordinator) AddCommitment(commitment DigestCommitment, safeTxHash [32]byte) (bool, error) {
	if c.phase != 0 {
		return false, errors.New("threshold: not in commitment phase")
	}

	// Verify commitment
	if !VerifyDigestCommitment(commitment, safeTxHash) {
		return false, ErrDigestMismatch
	}

	c.commitments = append(c.commitments, commitment)

	// Need at least threshold commitments to proceed
	if len(c.commitments) >= c.config.Threshold {
		c.phase = 1
		return true, nil
	}

	return false, nil
}

// AddPartial adds a partial signature (phase 2).
// Returns the completed signature if we have enough, nil otherwise.
func (c *Coordinator) AddPartial(partial *PartialSignature) (*primitives.Signature, error) {
	if c.phase != 1 {
		return nil, errors.New("threshold: not in partial collection phase")
	}

	// Verify partial is for correct message
	if partial.BitMask != c.message {
		return nil, ErrDigestMismatch
	}

	c.partials = append(c.partials, partial)

	// Check if we have enough partials
	if len(c.partials) >= c.config.Threshold {
		sig, err := AggregateAndVerify(c.partials, c.pub, c.message)
		if err != nil {
			return nil, err
		}
		c.phase = 2
		return sig, nil
	}

	return nil, nil
}

// Message returns the expected message hash.
func (c *Coordinator) Message() [32]byte {
	return c.message
}

// Phase returns the current protocol phase.
func (c *Coordinator) Phase() int {
	return c.phase
}
