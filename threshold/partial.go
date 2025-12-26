package threshold

import (
	"github.com/luxfi/lamport/primitives"
)

// CreatePartialSignature creates this party's partial signature.
//
// SECURITY: This should only be called AFTER verifying all digest commitments match.
//
// Each party reveals their share of the preimage for bits corresponding to the message:
//   - If message bit i is 0, reveal share of preimage[i][0]
//   - If message bit i is 1, reveal share of preimage[i][1]
func CreatePartialSignature(share *Share, message [32]byte) *PartialSignature {
	partial := &PartialSignature{
		PartyID: share.PartyID,
		Index:   share.Index,
		BitMask: message,
	}

	for i := 0; i < primitives.KeyBits; i++ {
		bit := primitives.GetBit(message, i)
		partial.PreimagePartials[i] = share.PreimageShares[i][bit]
	}

	return partial
}

// CreatePartialForThreshold creates a partial signature for threshold signing.
// This is the full workflow: compute message → create partial.
func CreatePartialForThreshold(
	config *Config,
	share *Share,
	safeTxHash [32]byte,
	nextPKH [32]byte,
) *PartialSignature {
	message := config.ComputeMessage(safeTxHash, nextPKH)
	return CreatePartialSignature(share, message)
}

// VerifyPartialCommitment verifies a partial signature's structure.
// This doesn't verify cryptographic correctness (that requires aggregation).
func VerifyPartialCommitment(partial *PartialSignature, expectedMessage [32]byte) bool {
	return partial.BitMask == expectedMessage
}

// RevealedBits extracts which bits were signed from a partial signature.
func (p *PartialSignature) RevealedBits() [32]byte {
	return p.BitMask
}

// GetPartialForBit returns the partial preimage for a specific bit position.
func (p *PartialSignature) GetPartialForBit(i int) [primitives.PreimageSize]byte {
	return p.PreimagePartials[i]
}
