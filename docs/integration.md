# Integration Guide

## Installation

### Foundry (Recommended)

```bash
forge install luxfi/lamport
```

Add to `remappings.txt`:
```
@luxfi/lamport/=lib/lamport/contracts/
```

### Manual Installation

Clone the repository:
```bash
git clone https://github.com/luxfi/lamport.git lib/lamport
cd lib/lamport/contracts && forge install
```

## Basic Usage

### Import the Library

```solidity
import {LamportLib} from "@luxfi/lamport/LamportLib.sol";
```

### Verify a Signature

```solidity
contract MyContract {
    function verifyMessage(
        bytes32 message,
        bytes32[] memory signature,
        bytes32[2][256] memory publicKey
    ) public pure returns (bool) {
        return LamportLib.verify(message, signature, publicKey);
    }
}
```

### Using the Optimized Verifier

```solidity
import {LamportOptimized} from "@luxfi/lamport/LamportOptimized.sol";

contract MyContract {
    LamportOptimized public verifier;

    constructor() {
        verifier = new LamportOptimized();
    }

    function verifyFast(
        uint256 bits,
        bytes32[256] calldata sig,
        bytes32[2][256] calldata pub
    ) external view returns (bool) {
        return verifier.verifyFast(bits, sig, pub);
    }
}
```

## Key Management

### Store Public Key Hash Only

```solidity
contract LamportWallet {
    bytes32 public currentPKH;
    bytes32 public pendingPKH;

    function setPendingKey(bytes32[2][256] calldata newPub) external {
        pendingPKH = LamportLib.computePKH(newPub);
    }

    function executeAndRotate(
        bytes32 txHash,
        bytes32[2][256] calldata currentPub,
        bytes32[] calldata sig,
        bytes32[2][256] calldata nextPub
    ) external {
        // Verify current PKH matches
        require(LamportLib.computePKH(currentPub) == currentPKH);

        // Verify signature
        bytes32 message = keccak256(abi.encodePacked(
            txHash,
            LamportLib.computePKH(nextPub)
        ));
        require(LamportLib.verify(message, sig, currentPub));

        // Rotate key
        currentPKH = LamportLib.computePKH(nextPub);

        // Execute transaction...
    }
}
```

### Domain Separation

Always include context to prevent replay attacks:

```solidity
uint256 message = LamportLib.computeThresholdMessage(
    safeTxHash,     // Transaction data
    nextPKH,        // Next key commitment
    address(this),  // Module address
    block.chainid   // Chain ID
);
```

## Off-Chain Integration

### Key Generation (Go)

```go
package main

import (
    "crypto/rand"
    "github.com/luxfi/lamport/primitives"
)

func main() {
    // Generate key pair
    keypair, err := primitives.GenerateKeypair()
    if err != nil {
        panic(err)
    }

    // Compute public key hash
    pkh := keypair.PublicKeyHash()

    // Sign a message
    message := sha3.Keccak256([]byte("Hello, Lamport!"))
    signature, err := keypair.Sign(message)
    if err != nil {
        panic(err)
    }

    // Verify
    valid := primitives.Verify(message, signature, keypair.Public)
    fmt.Printf("Valid: %v\n", valid)
}
```

### Signature Serialization

```go
// Serialize for Ethereum
func SerializeSignature(sig primitives.Signature) []byte {
    var result []byte
    for i := 0; i < 256; i++ {
        result = append(result, sig[i][:]...)
    }
    return result  // 8192 bytes
}

// Serialize public key
func SerializePublicKey(pub primitives.PublicKey) []byte {
    var result []byte
    for i := 0; i < 256; i++ {
        result = append(result, pub[i][0][:]...)
        result = append(result, pub[i][1][:]...)
    }
    return result  // 16384 bytes
}
```

## Safe Module Integration

### With Gnosis Safe

```solidity
import {Safe} from "@safe-global/safe-smart-account/Safe.sol";
import {LamportLib} from "@luxfi/lamport/LamportLib.sol";

contract LamportSafeModule {
    Safe public safe;
    bytes32 public pkh;

    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        bytes32[2][256] calldata pub,
        bytes32[] calldata sig,
        bytes32[2][256] calldata nextPub
    ) external {
        // Verify PKH
        require(LamportLib.computePKH(pub) == pkh);

        // Compute Safe tx hash
        bytes32 safeTxHash = safe.getTransactionHash(
            to, value, data, 0, 0, 0, 0, address(0), address(0), 0
        );

        // Compute message with domain separation
        uint256 message = LamportLib.computeThresholdMessage(
            safeTxHash,
            LamportLib.computePKH(nextPub),
            address(this),
            block.chainid
        );

        // Verify signature
        require(LamportLib.verify(bytes32(message), sig, pub));

        // Rotate key
        pkh = LamportLib.computePKH(nextPub);

        // Execute via Safe
        safe.execTransactionFromModule(to, value, data, 0);
    }
}
```

## Testing

### Foundry Test Example

```solidity
import "forge-std/Test.sol";
import {LamportLib} from "@luxfi/lamport/LamportLib.sol";

contract MyTest is Test {
    bytes32[2][256] privKey;
    bytes32[2][256] pubKey;

    function setUp() public {
        // Generate deterministic keys for testing
        for (uint256 i = 0; i < 256; i++) {
            privKey[i][0] = keccak256(abi.encode("test", i, 0));
            privKey[i][1] = keccak256(abi.encode("test", i, 1));
            pubKey[i][0] = keccak256(abi.encode(privKey[i][0]));
            pubKey[i][1] = keccak256(abi.encode(privKey[i][1]));
        }
    }

    function sign(bytes32 message) internal view returns (bytes32[] memory) {
        bytes32[] memory sig = new bytes32[](256);
        for (uint256 i = 0; i < 256; i++) {
            uint8 bit = uint8((uint256(message) >> (255 - i)) & 1);
            sig[i] = privKey[i][bit];
        }
        return sig;
    }

    function testVerification() public view {
        bytes32 message = keccak256("test message");
        bytes32[] memory sig = sign(message);
        assertTrue(LamportLib.verify(message, sig, pubKey));
    }
}
```

## Error Handling

```solidity
// Check signature length
require(signature.length == 256, "Invalid signature length");

// Validate PKH before verification
require(LamportLib.computePKH(pub) == storedPKH, "PKH mismatch");

// Verify signature
require(LamportLib.verify(message, signature, publicKey), "Invalid signature");
```
