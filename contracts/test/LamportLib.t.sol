// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../LamportLib.sol";
import "../LamportTest.sol";
import "../LamportBase.sol";

/// @title LamportLibTest
/// @notice Comprehensive Foundry tests for Lamport OTS
/// @dev Merges tests from both lamport repo and standard repo
contract LamportLibTest is Test {
    // ═══════════════════════════════════════════════════════════════════════
    // Test Fixtures
    // ═══════════════════════════════════════════════════════════════════════

    LamportTest public lamportContract;

    // Keys for testing (normally generated off-chain)
    bytes32[2][256] internal privKey;
    bytes32[2][256] internal pubKey;

    function setUp() public {
        lamportContract = new LamportTest();

        // Generate a test key pair
        // In production, this would be done off-chain with secure RNG
        for (uint256 i = 0; i < 256; i++) {
            privKey[i][0] = keccak256(abi.encode("private", i, 0));
            privKey[i][1] = keccak256(abi.encode("private", i, 1));

            pubKey[i][0] = keccak256(abi.encode(privKey[i][0]));
            pubKey[i][1] = keccak256(abi.encode(privKey[i][1]));
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // verify_u256 Tests (bytes[256] format)
    // ═══════════════════════════════════════════════════════════════════════

    function testVerify_ValidSignature() public pure {
        // Create a simple test case where we control the preimages
        bytes32[2][256] memory pub;
        bytes[256] memory sig;

        // Message: all zeros (bit 0 for all positions)
        uint256 bits = 0;

        // For each bit position, create preimage and hash
        for (uint256 i = 0; i < 256; i++) {
            // Preimage for bit 0: just the index
            bytes memory preimage0 = abi.encodePacked(bytes32(uint256(i)));
            // Preimage for bit 1: index + 256
            bytes memory preimage1 = abi.encodePacked(bytes32(uint256(i + 256)));

            pub[i][0] = keccak256(preimage0);
            pub[i][1] = keccak256(preimage1);

            // Since message is all zeros, reveal preimage for bit 0
            sig[i] = preimage0;
        }

        bool valid = LamportLib.verify_u256_mem(bits, sig, pub);
        assertTrue(valid, "Valid signature should verify");
    }

    function testVerify_InvalidSignature() public pure {
        bytes32[2][256] memory pub;
        bytes[256] memory sig;
        uint256 bits = 0;

        for (uint256 i = 0; i < 256; i++) {
            bytes memory preimage0 = abi.encodePacked(bytes32(uint256(i)));
            bytes memory preimage1 = abi.encodePacked(bytes32(uint256(i + 256)));

            pub[i][0] = keccak256(preimage0);
            pub[i][1] = keccak256(preimage1);

            sig[i] = preimage0;
        }

        // Corrupt one preimage
        sig[0] = abi.encodePacked(bytes32(uint256(999)));

        bool valid = LamportLib.verify_u256_mem(bits, sig, pub);
        assertFalse(valid, "Corrupted signature should not verify");
    }

    function testVerify_WrongBit() public pure {
        bytes32[2][256] memory pub;
        bytes[256] memory sig;
        uint256 bits = 0; // All zeros

        for (uint256 i = 0; i < 256; i++) {
            bytes memory preimage0 = abi.encodePacked(bytes32(uint256(i)));
            bytes memory preimage1 = abi.encodePacked(bytes32(uint256(i + 256)));

            pub[i][0] = keccak256(preimage0);
            pub[i][1] = keccak256(preimage1);

            // Reveal wrong preimage (bit 1 instead of bit 0)
            sig[i] = preimage1;
        }

        bool valid = LamportLib.verify_u256_mem(bits, sig, pub);
        assertFalse(valid, "Wrong bit preimage should not verify");
    }

    function testVerify_AllOnes() public pure {
        bytes32[2][256] memory pub;
        bytes[256] memory sig;
        uint256 bits = type(uint256).max; // All ones

        for (uint256 i = 0; i < 256; i++) {
            bytes memory preimage0 = abi.encodePacked(bytes32(uint256(i)));
            bytes memory preimage1 = abi.encodePacked(bytes32(uint256(i + 256)));

            pub[i][0] = keccak256(preimage0);
            pub[i][1] = keccak256(preimage1);

            // All bits are 1, reveal preimage for bit 1
            sig[i] = preimage1;
        }

        bool valid = LamportLib.verify_u256_mem(bits, sig, pub);
        assertTrue(valid, "All-ones message should verify");
    }

    function testVerify_MixedBits() public pure {
        bytes32[2][256] memory pub;
        bytes[256] memory sig;

        // Alternating bits: 0101...
        uint256 bits = 0;
        for (uint256 i = 0; i < 256; i += 2) {
            bits |= (1 << (255 - i - 1)); // Set odd positions to 1
        }

        for (uint256 i = 0; i < 256; i++) {
            bytes memory preimage0 = abi.encodePacked(bytes32(uint256(i)));
            bytes memory preimage1 = abi.encodePacked(bytes32(uint256(i + 256)));

            pub[i][0] = keccak256(preimage0);
            pub[i][1] = keccak256(preimage1);

            // Reveal correct preimage based on bit
            uint256 bit = (bits >> (255 - i)) & 1;
            sig[i] = bit == 0 ? preimage0 : preimage1;
        }

        bool valid = LamportLib.verify_u256_mem(bits, sig, pub);
        assertTrue(valid, "Mixed bits should verify");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // verify Tests (bytes32[] format from standard)
    // ═══════════════════════════════════════════════════════════════════════

    function testLamportSignatureGeneration() public view {
        bytes32 message = keccak256("Test message");
        bytes32[] memory signature = new bytes32[](256);

        // Generate signature
        for (uint256 i = 0; i < 256; i++) {
            uint8 bit = uint8((uint256(message) >> (255 - i)) & 1);
            signature[i] = privKey[i][bit];
        }

        // Verify signature
        bool isValid = LamportLib.verify(message, signature, pubKey);
        assertTrue(isValid);
    }

    function testInvalidSignature() public view {
        bytes32 message = keccak256("Test message");
        bytes32[] memory signature = new bytes32[](256);

        // Generate incorrect signature (use wrong bit)
        for (uint256 i = 0; i < 256; i++) {
            uint8 bit = uint8((uint256(message) >> (255 - i)) & 1);
            // Intentionally use wrong key half
            signature[i] = privKey[i][1 - bit];
        }

        // Verification should fail
        bool isValid = LamportLib.verify(message, signature, pubKey);
        assertFalse(isValid);
    }

    function testDifferentMessage() public view {
        bytes32 message1 = keccak256("Message 1");
        bytes32 message2 = keccak256("Message 2");
        bytes32[] memory signature = new bytes32[](256);

        // Generate signature for message1
        for (uint256 i = 0; i < 256; i++) {
            uint8 bit = uint8((uint256(message1) >> (255 - i)) & 1);
            signature[i] = privKey[i][bit];
        }

        // Verify with message1 - should pass
        assertTrue(LamportLib.verify(message1, signature, pubKey));

        // Verify with message2 - should fail
        assertFalse(LamportLib.verify(message2, signature, pubKey));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // LamportTest Contract Tests
    // ═══════════════════════════════════════════════════════════════════════

    function testLamportContract() public {
        // Set public key in contract
        lamportContract.setPubKey(pubKey);

        // Generate a message and signature
        bytes32 message = keccak256("Contract test message");
        bytes32[] memory signature = new bytes32[](256);

        for (uint256 i = 0; i < 256; i++) {
            uint8 bit = uint8((uint256(message) >> (255 - i)) & 1);
            signature[i] = privKey[i][bit];
        }

        // Call the contract with valid signature
        lamportContract.doSomething(message, signature);

        // Test with invalid signature should revert
        bytes32[] memory badSignature = new bytes32[](256);
        for (uint256 i = 0; i < 256; i++) {
            badSignature[i] = bytes32(0);
        }

        vm.expectRevert();
        lamportContract.doSomething(message, badSignature);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Utility Function Tests
    // ═══════════════════════════════════════════════════════════════════════

    function testComputePKH() public pure {
        bytes32[2][256] memory pub;

        // Fill with deterministic values
        for (uint256 i = 0; i < 256; i++) {
            pub[i][0] = bytes32(uint256(i));
            pub[i][1] = bytes32(uint256(i + 256));
        }

        bytes32 pkh1 = LamportLib.computePKH(pub);
        bytes32 pkh2 = LamportLib.computePKH(pub);

        assertEq(pkh1, pkh2, "Same public key should produce same PKH");
        assertTrue(pkh1 != bytes32(0), "PKH should not be zero");
    }

    function testComputeThresholdMessage() public view {
        bytes32 safeTxHash = bytes32(uint256(1));
        bytes32 nextPKH = bytes32(uint256(2));
        address module = address(this);
        uint256 chainId = block.chainid;

        uint256 m1 = LamportLib.computeThresholdMessage(
            safeTxHash,
            nextPKH,
            module,
            chainId
        );

        uint256 m2 = LamportLib.computeThresholdMessage(
            safeTxHash,
            nextPKH,
            module,
            chainId
        );

        assertEq(m1, m2, "Same inputs should produce same message");

        // Different chainId should produce different message
        uint256 m3 = LamportLib.computeThresholdMessage(
            safeTxHash,
            nextPKH,
            module,
            chainId + 1
        );

        assertTrue(m1 != m3, "Different chainId should produce different message");
    }

    function testGetBit() public pure {
        // 0x80 = 10000000 in binary
        bytes32 data = bytes32(uint256(0x80) << 248);

        assertEq(LamportLib.getBit(data, 0), 1, "Bit 0 should be 1");
        assertEq(LamportLib.getBit(data, 1), 0, "Bit 1 should be 0");

        // All ones
        bytes32 allOnes = bytes32(type(uint256).max);
        for (uint256 i = 0; i < 256; i++) {
            assertEq(LamportLib.getBit(allOnes, i), 1, "All bits should be 1");
        }

        // All zeros
        bytes32 allZeros = bytes32(0);
        for (uint256 i = 0; i < 256; i++) {
            assertEq(LamportLib.getBit(allZeros, i), 0, "All bits should be 0");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Gas Usage Tests
    // ═══════════════════════════════════════════════════════════════════════

    function testGasUsage() public {
        // Set up contract with public key
        lamportContract.setPubKey(pubKey);

        bytes32 message = keccak256("Gas test message");
        bytes32[] memory signature = new bytes32[](256);

        for (uint256 i = 0; i < 256; i++) {
            uint8 bit = uint8((uint256(message) >> (255 - i)) & 1);
            signature[i] = privKey[i][bit];
        }

        // Measure gas for verification
        uint256 gasBefore = gasleft();
        lamportContract.doSomething(message, signature);
        uint256 gasUsed = gasBefore - gasleft();

        // Log gas usage
        emit log_named_uint("Lamport verification gas used", gasUsed);

        // Assert reasonable gas usage (should be under 1M gas)
        assertLt(gasUsed, 1000000);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Fuzz Tests
    // ═══════════════════════════════════════════════════════════════════════

    function testFuzz_VerifyConsistency(uint256 bits) public pure {
        bytes32[2][256] memory pub;
        bytes[256] memory sig;

        for (uint256 i = 0; i < 256; i++) {
            bytes memory preimage0 = abi.encodePacked(bytes32(uint256(i)), bytes32(bits));
            bytes memory preimage1 = abi.encodePacked(bytes32(uint256(i + 256)), bytes32(bits));

            pub[i][0] = keccak256(preimage0);
            pub[i][1] = keccak256(preimage1);

            uint256 bit = (bits >> (255 - i)) & 1;
            sig[i] = bit == 0 ? preimage0 : preimage1;
        }

        bool valid = LamportLib.verify_u256_mem(bits, sig, pub);
        assertTrue(valid, "Fuzz: correctly constructed signature should always verify");
    }

    function testFuzz_MessageAndSignature(bytes32 message) public view {
        // Generate signature for fuzzed message
        bytes32[] memory signature = new bytes32[](256);

        for (uint256 i = 0; i < 256; i++) {
            uint8 bit = uint8((uint256(message) >> (255 - i)) & 1);
            signature[i] = privKey[i][bit];
        }

        // Verification should always pass with correct signature
        assertTrue(LamportLib.verify(message, signature, pubKey));

        // Modify one bit of signature - should fail
        signature[0] = privKey[0][1 - uint8(uint256(message) >> 255 & 1)];
        assertFalse(LamportLib.verify(message, signature, pubKey));
    }
}
