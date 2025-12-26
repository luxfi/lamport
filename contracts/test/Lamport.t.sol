// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../Lamport.sol";
import "../LamportOptimized.sol";

/// @title LamportTestWrapper
/// @notice Wrapper to make internal library calls external for revert testing
contract LamportTestWrapper {
    function verifyDynamic(
        bytes32 message,
        bytes32[] memory signature,
        bytes32[2][256] memory publicKey
    ) external pure returns (bool) {
        return Lamport.verifyDynamic(message, signature, publicKey);
    }

    function getBit(bytes32 data, uint256 index) external pure returns (uint256) {
        return Lamport.getBit(data, index);
    }
}

/// @title LamportTest
/// @notice Tests for pure Solidity Lamport library
contract LamportTest is Test {
    // Test keys
    bytes32[2][256] internal privKey;
    bytes32[2][256] internal pubKey;

    function setUp() public {
        // Generate test key pair
        for (uint256 i = 0; i < 256; i++) {
            privKey[i][0] = keccak256(abi.encode("private", i, 0));
            privKey[i][1] = keccak256(abi.encode("private", i, 1));
            pubKey[i][0] = keccak256(abi.encodePacked(privKey[i][0]));
            pubKey[i][1] = keccak256(abi.encodePacked(privKey[i][1]));
        }
    }

    // =========================================================================
    // verify Tests
    // =========================================================================

    function testVerify_Valid_AllZeros() public view {
        uint256 bits = 0;
        bytes32[256] memory sig = _signMessage(bits);
        assertTrue(Lamport.verifyMem(bits, sig, pubKey));
    }

    function testVerify_Valid_AllOnes() public view {
        uint256 bits = type(uint256).max;
        bytes32[256] memory sig = _signMessage(bits);
        assertTrue(Lamport.verifyMem(bits, sig, pubKey));
    }

    function testVerify_Valid_Mixed() public view {
        uint256 bits = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;
        bytes32[256] memory sig = _signMessage(bits);
        assertTrue(Lamport.verifyMem(bits, sig, pubKey));
    }

    function testVerify_Invalid_Corrupted() public view {
        uint256 bits = 0;
        bytes32[256] memory sig = _signMessage(bits);
        sig[0] = bytes32(uint256(999));
        assertFalse(Lamport.verifyMem(bits, sig, pubKey));
    }

    function testVerify_Invalid_WrongBit() public view {
        uint256 bits = 0;
        bytes32[256] memory sig;
        for (uint256 i = 0; i < 256; i++) {
            sig[i] = privKey[i][1]; // Wrong bit
        }
        assertFalse(Lamport.verifyMem(bits, sig, pubKey));
    }

    // =========================================================================
    // verifyDynamic Tests
    // =========================================================================

    function testVerifyDynamic_Valid() public view {
        bytes32 message = keccak256("test");
        bytes32[] memory sig = new bytes32[](256);
        uint256 bits = uint256(message);

        for (uint256 i = 0; i < 256; i++) {
            uint256 bit = (bits >> (255 - i)) & 1;
            sig[i] = privKey[i][bit];
        }

        assertTrue(Lamport.verifyDynamic(message, sig, pubKey));
    }

    function testVerifyDynamic_Invalid() public view {
        bytes32 message = keccak256("test");
        bytes32[] memory sig = new bytes32[](256);
        uint256 bits = uint256(message);

        for (uint256 i = 0; i < 256; i++) {
            uint256 bit = (bits >> (255 - i)) & 1;
            sig[i] = privKey[i][1 - bit]; // Wrong bit
        }

        assertFalse(Lamport.verifyDynamic(message, sig, pubKey));
    }

    function testVerifyDynamic_WrongLength() public {
        bytes32 message = keccak256("test");
        bytes32[] memory sig = new bytes32[](255); // Wrong length

        // Internal library calls revert, wrap in try/catch
        LamportTestWrapper wrapper = new LamportTestWrapper();
        vm.expectRevert("Lamport: invalid sig length");
        wrapper.verifyDynamic(message, sig, pubKey);
    }

    // =========================================================================
    // computePKH Tests
    // =========================================================================

    function testComputePKH_Deterministic() public view {
        bytes32 pkh1 = Lamport.computePKH(pubKey);
        bytes32 pkh2 = Lamport.computePKH(pubKey);
        assertEq(pkh1, pkh2);
        assertTrue(pkh1 != bytes32(0));
    }

    function testComputePKH_Different() public pure {
        bytes32[2][256] memory pub1;
        bytes32[2][256] memory pub2;

        for (uint256 i = 0; i < 256; i++) {
            pub1[i][0] = bytes32(i);
            pub1[i][1] = bytes32(i + 256);
            pub2[i][0] = bytes32(i + 512);
            pub2[i][1] = bytes32(i + 768);
        }

        assertTrue(Lamport.computePKH(pub1) != Lamport.computePKH(pub2));
    }

    // =========================================================================
    // computeMessage Tests
    // =========================================================================

    function testComputeMessage_DomainSeparation() public view {
        bytes32 txHash = bytes32(uint256(1));
        bytes32 nextPKH = bytes32(uint256(2));

        uint256 m1 = Lamport.computeMessage(txHash, nextPKH, address(this), block.chainid);
        uint256 m2 = Lamport.computeMessage(txHash, nextPKH, address(this), block.chainid + 1);

        assertTrue(m1 != m2, "Different chainId should produce different message");
    }

    function testComputeMessage_Deterministic() public view {
        bytes32 txHash = bytes32(uint256(1));
        bytes32 nextPKH = bytes32(uint256(2));

        uint256 m1 = Lamport.computeMessage(txHash, nextPKH, address(this), block.chainid);
        uint256 m2 = Lamport.computeMessage(txHash, nextPKH, address(this), block.chainid);

        assertEq(m1, m2);
    }

    // =========================================================================
    // getBit Tests
    // =========================================================================

    function testGetBit() public pure {
        bytes32 data = bytes32(uint256(0x80) << 248); // First bit = 1

        assertEq(Lamport.getBit(data, 0), 1);
        assertEq(Lamport.getBit(data, 1), 0);
    }

    function testGetBit_AllOnes() public pure {
        bytes32 data = bytes32(type(uint256).max);
        for (uint256 i = 0; i < 256; i++) {
            assertEq(Lamport.getBit(data, i), 1);
        }
    }

    function testGetBit_AllZeros() public pure {
        bytes32 data = bytes32(0);
        for (uint256 i = 0; i < 256; i++) {
            assertEq(Lamport.getBit(data, i), 0);
        }
    }

    function testGetBit_OutOfRange() public {
        LamportTestWrapper wrapper = new LamportTestWrapper();
        vm.expectRevert("Lamport: index out of range");
        wrapper.getBit(bytes32(0), 256);
    }

    // =========================================================================
    // Fuzz Tests
    // =========================================================================

    function testFuzz_Verify(uint256 bits) public view {
        bytes32[256] memory sig = _signMessage(bits);
        assertTrue(Lamport.verifyMem(bits, sig, pubKey));
    }

    function testFuzz_VerifyDynamic(bytes32 message) public view {
        bytes32[] memory sig = new bytes32[](256);
        uint256 bits = uint256(message);

        for (uint256 i = 0; i < 256; i++) {
            uint256 bit = (bits >> (255 - i)) & 1;
            sig[i] = privKey[i][bit];
        }

        assertTrue(Lamport.verifyDynamic(message, sig, pubKey));
    }

    // =========================================================================
    // Gas Test
    // =========================================================================

    function testGas_Verify() public {
        uint256 bits = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0;
        bytes32[256] memory sig = _signMessage(bits);

        uint256 gasBefore = gasleft();
        Lamport.verifyMem(bits, sig, pubKey);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("Lamport.verifyMem gas", gasUsed);
        // Memory-based verification is ~1.2M gas (expected)
        // Calldata-based verify() would be ~450K gas
        assertLt(gasUsed, 1_500_000);
    }

    // =========================================================================
    // Helper
    // =========================================================================

    function _signMessage(uint256 bits) internal view returns (bytes32[256] memory sig) {
        for (uint256 i = 0; i < 256; i++) {
            uint256 bit = (bits >> (255 - i)) & 1;
            sig[i] = privKey[i][bit];
        }
    }
}

/// @title LamportOptimizedTest
/// @notice Tests for assembly-optimized Lamport verification
contract LamportOptimizedTest is Test {
    LamportOptimized public verifier;

    function setUp() public {
        verifier = new LamportOptimized();
    }

    // =========================================================================
    // verify Tests
    // =========================================================================

    function testVerify_Valid_AllZeros() public view {
        (uint256 bits, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestData(0);
        assertTrue(verifier.verify(bits, sig, pub));
    }

    function testVerify_Valid_AllOnes() public view {
        (uint256 bits, bytes32[256] memory sig, bytes32[2][256] memory pub) =
            _generateTestData(type(uint256).max);
        assertTrue(verifier.verify(bits, sig, pub));
    }

    function testVerify_Invalid() public view {
        (uint256 bits, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestData(0);
        sig[0] = bytes32(uint256(999));
        assertFalse(verifier.verify(bits, sig, pub));
    }

    // =========================================================================
    // verifyUnrolled Tests
    // =========================================================================

    function testUnrolled_Valid_AllZeros() public view {
        (uint256 bits, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestData(0);
        assertTrue(verifier.verifyUnrolled(bits, sig, pub));
    }

    function testUnrolled_Valid_AllOnes() public view {
        (uint256 bits, bytes32[256] memory sig, bytes32[2][256] memory pub) =
            _generateTestData(type(uint256).max);
        assertTrue(verifier.verifyUnrolled(bits, sig, pub));
    }

    function testUnrolled_Valid_Mixed() public view {
        uint256 bits = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;
        (, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestDataWithBits(bits);
        assertTrue(verifier.verifyUnrolled(bits, sig, pub));
    }

    function testUnrolled_Invalid() public view {
        (uint256 bits, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestData(0);
        sig[128] = bytes32(uint256(999));
        assertFalse(verifier.verifyUnrolled(bits, sig, pub));
    }

    // =========================================================================
    // verifyConstantTime Tests
    // =========================================================================

    function testConstantTime_Valid_AllZeros() public view {
        (uint256 bits, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestData(0);
        assertTrue(verifier.verifyConstantTime(bits, sig, pub));
    }

    function testConstantTime_Valid_AllOnes() public view {
        (uint256 bits, bytes32[256] memory sig, bytes32[2][256] memory pub) =
            _generateTestData(type(uint256).max);
        assertTrue(verifier.verifyConstantTime(bits, sig, pub));
    }

    function testConstantTime_Invalid_First() public view {
        (uint256 bits, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestData(0);
        sig[0] = bytes32(uint256(999));
        assertFalse(verifier.verifyConstantTime(bits, sig, pub));
    }

    function testConstantTime_Invalid_Last() public view {
        (uint256 bits, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestData(0);
        sig[255] = bytes32(uint256(999));
        assertFalse(verifier.verifyConstantTime(bits, sig, pub));
    }

    // =========================================================================
    // Consistency Tests
    // =========================================================================

    function testConsistency_AllAgree() public view {
        uint256 bits = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0;
        (, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestDataWithBits(bits);

        assertTrue(verifier.verify(bits, sig, pub));
        assertTrue(verifier.verifyUnrolled(bits, sig, pub));
        assertTrue(verifier.verifyConstantTime(bits, sig, pub));
    }

    function testConsistency_AllReject() public view {
        (uint256 bits, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestData(0);
        sig[100] = bytes32(uint256(999));

        assertFalse(verifier.verify(bits, sig, pub));
        assertFalse(verifier.verifyUnrolled(bits, sig, pub));
        assertFalse(verifier.verifyConstantTime(bits, sig, pub));
    }

    // =========================================================================
    // Fuzz Tests
    // =========================================================================

    function testFuzz_Verify(uint256 bits) public view {
        (, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestDataWithBits(bits);
        assertTrue(verifier.verify(bits, sig, pub));
    }

    function testFuzz_Unrolled(uint256 bits) public view {
        (, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestDataWithBits(bits);
        assertTrue(verifier.verifyUnrolled(bits, sig, pub));
    }

    function testFuzz_ConstantTime(uint256 bits) public view {
        (, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestDataWithBits(bits);
        assertTrue(verifier.verifyConstantTime(bits, sig, pub));
    }

    function testFuzz_AllConsistent(uint256 bits, uint8 corruptIdx) public view {
        (, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestDataWithBits(bits);
        sig[corruptIdx] = bytes32(uint256(999_999));

        bool v1 = verifier.verify(bits, sig, pub);
        bool v2 = verifier.verifyUnrolled(bits, sig, pub);
        bool v3 = verifier.verifyConstantTime(bits, sig, pub);

        assertEq(v1, v2);
        assertEq(v2, v3);
        assertFalse(v1);
    }

    // =========================================================================
    // Gas Tests
    // =========================================================================

    function testGas_Comparison() public {
        uint256 bits = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0;
        (, bytes32[256] memory sig, bytes32[2][256] memory pub) = _generateTestDataWithBits(bits);

        uint256 g1 = gasleft();
        verifier.verify(bits, sig, pub);
        uint256 gasVerify = g1 - gasleft();

        uint256 g2 = gasleft();
        verifier.verifyUnrolled(bits, sig, pub);
        uint256 gasUnrolled = g2 - gasleft();

        uint256 g3 = gasleft();
        verifier.verifyConstantTime(bits, sig, pub);
        uint256 gasConstant = g3 - gasleft();

        emit log_named_uint("verify", gasVerify);
        emit log_named_uint("verifyUnrolled", gasUnrolled);
        emit log_named_uint("verifyConstantTime", gasConstant);

        assertLt(gasVerify, 500_000);
        assertLt(gasUnrolled, 500_000);
        assertLt(gasConstant, 500_000);
    }

    // =========================================================================
    // computePKH Test
    // =========================================================================

    function testComputePKH() public view {
        (,, bytes32[2][256] memory pub) = _generateTestData(0);
        bytes32 pkh = verifier.computePKH(pub);
        assertTrue(pkh != bytes32(0));
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _generateTestData(uint256 bits)
        internal
        pure
        returns (uint256, bytes32[256] memory sig, bytes32[2][256] memory pub)
    {
        return _generateTestDataWithBits(bits);
    }

    function _generateTestDataWithBits(uint256 bits)
        internal
        pure
        returns (uint256, bytes32[256] memory sig, bytes32[2][256] memory pub)
    {
        for (uint256 i = 0; i < 256; i++) {
            bytes32 preimage0 = bytes32(uint256(i));
            bytes32 preimage1 = bytes32(uint256(i + 256));

            pub[i][0] = keccak256(abi.encodePacked(preimage0));
            pub[i][1] = keccak256(abi.encodePacked(preimage1));

            uint256 bit = (bits >> (255 - i)) & 1;
            sig[i] = bit == 0 ? preimage0 : preimage1;
        }
        return (bits, sig, pub);
    }
}

/// @title LamportVerifierTest
/// @notice Tests for LamportVerifier contract
contract LamportVerifierTest is Test {
    LamportVerifier public v;

    function setUp() public {
        v = new LamportVerifier();
    }

    function testInit() public {
        bytes32 pkh = bytes32(uint256(1));
        v.init(pkh);
        assertEq(v.pkh(), pkh);
        assertTrue(v.initialized());
    }

    function testInit_CannotInitTwice() public {
        v.init(bytes32(uint256(1)));
        vm.expectRevert(LamportVerifier.AlreadyInitialized.selector);
        v.init(bytes32(uint256(2)));
    }

    function testVerify_NotInitialized() public {
        bytes32[256] memory sig;
        bytes32[2][256] memory pub;
        vm.expectRevert(LamportVerifier.NotInitialized.selector);
        v.verify(0, sig, pub);
    }
}
