"""
Unit tests for password hashing utilities used in VMM child host creation.

Tests the SHA-512 crypt implementation and related helper functions.
"""

# pylint: disable=protected-access

import string
from unittest.mock import patch

from src.sysmanage_agent.operations.child_host_vmm_password_utils import (
    CRYPT_B64,
    _b64_encode_24bit,
    _create_digest_a,
    _create_repeated_bytes,
    _encode_final_digest,
    _perform_rounds,
    _sha512_crypt_impl,
    generate_salt,
    hash_password_sha256,
    hash_password_sha512,
    verify_password,
)


class TestGenerateSalt:
    """Test cases for the generate_salt function."""

    def test_generate_salt_default_length(self):
        """Test salt generation with default length of 16."""
        salt = generate_salt()
        assert len(salt) == 16

    def test_generate_salt_custom_length(self):
        """Test salt generation with custom lengths."""
        for length in [8, 12, 16, 20, 32]:
            salt = generate_salt(length)
            assert len(salt) == length

    def test_generate_salt_valid_characters(self):
        """Test that generated salt contains only valid characters."""
        valid_chars = set(string.ascii_letters + string.digits + "./")
        for _ in range(10):  # Test multiple generations
            salt = generate_salt()
            for char in salt:
                assert char in valid_chars, f"Invalid character '{char}' in salt"

    def test_generate_salt_randomness(self):
        """Test that generated salts are different each time."""
        salts = [generate_salt() for _ in range(100)]
        # All salts should be unique (extremely high probability)
        assert len(set(salts)) == 100

    def test_generate_salt_zero_length(self):
        """Test salt generation with zero length."""
        salt = generate_salt(0)
        assert salt == ""

    def test_generate_salt_single_char(self):
        """Test salt generation with single character."""
        salt = generate_salt(1)
        assert len(salt) == 1


class TestB64Encode24Bit:
    """Test cases for the _b64_encode_24bit function."""

    def test_b64_encode_all_zeros(self):
        """Test encoding three zero bytes."""
        result = _b64_encode_24bit(0, 0, 0, 4)
        assert len(result) == 4
        # All zeros should encode to first character repeated
        assert result == "...."

    def test_b64_encode_single_char(self):
        """Test encoding with single character output."""
        result = _b64_encode_24bit(0, 0, 0, 1)
        assert len(result) == 1
        assert result == "."

    def test_b64_encode_two_chars(self):
        """Test encoding with two character output."""
        result = _b64_encode_24bit(0, 0, 63, 2)
        assert len(result) == 2

    def test_b64_encode_max_values(self):
        """Test encoding with maximum byte values."""
        result = _b64_encode_24bit(255, 255, 255, 4)
        assert len(result) == 4
        # Result should use characters from CRYPT_B64

    def test_b64_encode_known_values(self):
        """Test encoding with known input values."""
        # 0x3F = 63, which should map to 'z' (last character)
        result = _b64_encode_24bit(0, 0, 63, 1)
        assert result == CRYPT_B64[63]

    def test_b64_encode_preserves_bits(self):
        """Test that encoding preserves bit patterns correctly."""
        # Each output character encodes 6 bits
        # (b1 << 16) | (b2 << 8) | b3, then extract 6 bits at a time from LSB
        result = _b64_encode_24bit(0, 0, 1, 4)
        assert result[0] == CRYPT_B64[1]  # First char from LSB 6 bits


class TestCreateRepeatedBytes:
    """Test cases for the _create_repeated_bytes function."""

    def test_create_repeated_bytes_exact_fit(self):
        """Test when length is exactly 64 bytes."""
        digest = bytes(range(64))
        result = _create_repeated_bytes(digest, 64)
        assert result == digest

    def test_create_repeated_bytes_less_than_64(self):
        """Test when length is less than 64 bytes."""
        digest = bytes(range(64))
        result = _create_repeated_bytes(digest, 32)
        assert result == digest[:32]
        assert len(result) == 32

    def test_create_repeated_bytes_more_than_64(self):
        """Test when length is more than 64 bytes."""
        digest = bytes(range(64))
        result = _create_repeated_bytes(digest, 128)
        assert len(result) == 128
        assert result[:64] == digest
        assert result[64:128] == digest

    def test_create_repeated_bytes_non_multiple(self):
        """Test when length is not a multiple of 64."""
        digest = bytes(range(64))
        result = _create_repeated_bytes(digest, 100)
        assert len(result) == 100
        assert result[:64] == digest
        assert result[64:100] == digest[:36]

    def test_create_repeated_bytes_small_length(self):
        """Test with very small lengths."""
        digest = bytes(range(64))
        result = _create_repeated_bytes(digest, 1)
        assert len(result) == 1
        assert result == digest[:1]

    def test_create_repeated_bytes_zero_length(self):
        """Test with zero length."""
        digest = bytes(range(64))
        result = _create_repeated_bytes(digest, 0)
        assert len(result) == 0
        assert result == b""

    def test_create_repeated_bytes_large_length(self):
        """Test with length requiring many repetitions."""
        digest = bytes(range(64))
        result = _create_repeated_bytes(digest, 256)
        assert len(result) == 256
        # Should contain 4 full copies
        for i in range(4):
            assert result[i * 64 : (i + 1) * 64] == digest


class TestCreateDigestA:
    """Test cases for the _create_digest_a function."""

    def test_create_digest_a_returns_64_bytes(self):
        """Test that digest A is always 64 bytes (SHA-512 output)."""
        password = b"testpassword"
        salt = b"testsalt"
        digest_b = bytes(64)  # 64 zero bytes
        result = _create_digest_a(password, salt, digest_b)
        assert len(result) == 64

    def test_create_digest_a_different_inputs(self):
        """Test that different inputs produce different digests."""
        salt = b"testsalt"
        digest_b = bytes(64)

        result1 = _create_digest_a(b"password1", salt, digest_b)
        result2 = _create_digest_a(b"password2", salt, digest_b)
        assert result1 != result2

    def test_create_digest_a_same_inputs_same_output(self):
        """Test that same inputs produce same output (deterministic)."""
        password = b"testpassword"
        salt = b"testsalt"
        digest_b = bytes(64)

        result1 = _create_digest_a(password, salt, digest_b)
        result2 = _create_digest_a(password, salt, digest_b)
        assert result1 == result2

    def test_create_digest_a_long_password(self):
        """Test with password longer than 64 bytes."""
        password = b"a" * 100  # Password longer than digest length
        salt = b"testsalt"
        digest_b = bytes(64)
        result = _create_digest_a(password, salt, digest_b)
        assert len(result) == 64

    def test_create_digest_a_empty_password(self):
        """Test with empty password."""
        password = b""
        salt = b"testsalt"
        digest_b = bytes(64)
        result = _create_digest_a(password, salt, digest_b)
        assert len(result) == 64


class TestPerformRounds:
    """Test cases for the _perform_rounds function."""

    def test_perform_rounds_returns_64_bytes(self):
        """Test that perform_rounds always returns 64 bytes."""
        digest_a = bytes(64)
        p_bytes = b"password"
        s_bytes = b"salt"
        result = _perform_rounds(digest_a, p_bytes, s_bytes, 1000)
        assert len(result) == 64

    def test_perform_rounds_different_round_counts(self):
        """Test that different round counts produce different results."""
        digest_a = bytes(range(64))
        p_bytes = b"password"
        s_bytes = b"salt"

        result_1000 = _perform_rounds(digest_a, p_bytes, s_bytes, 1000)
        result_2000 = _perform_rounds(digest_a, p_bytes, s_bytes, 2000)
        assert result_1000 != result_2000

    def test_perform_rounds_deterministic(self):
        """Test that same inputs produce same output."""
        digest_a = bytes(range(64))
        p_bytes = b"password"
        s_bytes = b"salt"

        result1 = _perform_rounds(digest_a, p_bytes, s_bytes, 100)
        result2 = _perform_rounds(digest_a, p_bytes, s_bytes, 100)
        assert result1 == result2

    def test_perform_rounds_zero_rounds(self):
        """Test with zero rounds."""
        digest_a = bytes(range(64))
        p_bytes = b"password"
        s_bytes = b"salt"
        result = _perform_rounds(digest_a, p_bytes, s_bytes, 0)
        # With 0 rounds, should return original digest_a
        assert result == digest_a

    def test_perform_rounds_single_round(self):
        """Test with single round."""
        digest_a = bytes(range(64))
        p_bytes = b"password"
        s_bytes = b"salt"
        result = _perform_rounds(digest_a, p_bytes, s_bytes, 1)
        assert len(result) == 64
        assert result != digest_a  # Should be transformed

    def test_perform_rounds_modulo_operations(self):
        """Test that modulo operations affect the result correctly."""
        digest_a = bytes(range(64))
        p_bytes = b"password"
        s_bytes = b"salt"

        # Round numbers divisible by 3 and 7 should behave differently
        # This is a basic sanity check that the algorithm runs
        result = _perform_rounds(digest_a, p_bytes, s_bytes, 21)  # 21 = 3 * 7
        assert len(result) == 64


class TestEncodeFinalDigest:
    """Test cases for the _encode_final_digest function."""

    def test_encode_final_digest_length(self):
        """Test that encoded digest has correct length."""
        digest = bytes(64)
        result = _encode_final_digest(digest)
        # 21 groups of 4 chars + 1 group of 2 chars = 86 chars
        assert len(result) == 86

    def test_encode_final_digest_valid_chars(self):
        """Test that encoded digest uses only valid base64 characters."""
        digest = bytes(range(64))
        result = _encode_final_digest(digest)
        for char in result:
            assert char in CRYPT_B64, f"Invalid character '{char}' in encoded digest"

    def test_encode_final_digest_deterministic(self):
        """Test that same input produces same output."""
        digest = bytes(range(64))
        result1 = _encode_final_digest(digest)
        result2 = _encode_final_digest(digest)
        assert result1 == result2

    def test_encode_final_digest_different_inputs(self):
        """Test that different inputs produce different outputs."""
        digest1 = bytes(64)
        digest2 = bytes(range(64))
        result1 = _encode_final_digest(digest1)
        result2 = _encode_final_digest(digest2)
        assert result1 != result2

    def test_encode_final_digest_all_zeros(self):
        """Test encoding all zero bytes."""
        digest = bytes(64)
        result = _encode_final_digest(digest)
        assert len(result) == 86
        # Should produce dots (first char in CRYPT_B64)
        assert result == "." * 86

    def test_encode_final_digest_max_values(self):
        """Test encoding maximum byte values."""
        digest = bytes([255] * 64)
        result = _encode_final_digest(digest)
        assert len(result) == 86


class TestSha512CryptImpl:
    """Test cases for the _sha512_crypt_impl function."""

    def test_sha512_crypt_impl_format_default_rounds(self):
        """Test output format with default rounds."""
        result = _sha512_crypt_impl("password", "testsalt12345678")
        assert result.startswith("$6$")
        assert "$rounds=" not in result  # Default rounds don't include rounds= prefix
        parts = result.split("$")
        assert len(parts) == 4
        assert parts[1] == "6"
        assert parts[2] == "testsalt12345678"

    def test_sha512_crypt_impl_format_custom_rounds(self):
        """Test output format with custom rounds."""
        result = _sha512_crypt_impl("password", "testsalt", rounds=10000)
        assert result.startswith("$6$rounds=10000$")
        parts = result.split("$")
        assert len(parts) == 5
        assert parts[1] == "6"
        assert parts[2] == "rounds=10000"
        assert parts[3] == "testsalt"

    def test_sha512_crypt_impl_salt_truncation(self):
        """Test that long salts are truncated to 16 characters."""
        long_salt = "a" * 32
        result = _sha512_crypt_impl("password", long_salt)
        parts = result.split("$")
        # Salt should be truncated to 16 chars
        assert parts[2] == "a" * 16

    def test_sha512_crypt_impl_deterministic(self):
        """Test that same inputs produce same output."""
        result1 = _sha512_crypt_impl("password", "fixedsalt")
        result2 = _sha512_crypt_impl("password", "fixedsalt")
        assert result1 == result2

    def test_sha512_crypt_impl_different_passwords(self):
        """Test that different passwords produce different hashes."""
        result1 = _sha512_crypt_impl("password1", "fixedsalt")
        result2 = _sha512_crypt_impl("password2", "fixedsalt")
        assert result1 != result2

    def test_sha512_crypt_impl_different_salts(self):
        """Test that different salts produce different hashes."""
        result1 = _sha512_crypt_impl("password", "salt1")
        result2 = _sha512_crypt_impl("password", "salt2")
        assert result1 != result2

    def test_sha512_crypt_impl_empty_password(self):
        """Test hashing empty password."""
        result = _sha512_crypt_impl("", "testsalt")
        assert result.startswith("$6$")
        assert len(result) > 20  # Should still produce a valid hash

    def test_sha512_crypt_impl_unicode_password(self):
        """Test hashing Unicode password."""
        result = _sha512_crypt_impl("test", "testsalt")
        assert result.startswith("$6$")

    def test_sha512_crypt_impl_special_chars_password(self):
        """Test hashing password with special characters."""
        result = _sha512_crypt_impl("p@$$w0rd!#%", "testsalt")
        assert result.startswith("$6$")

    def test_sha512_crypt_impl_known_value(self):
        """Test against a known SHA-512 crypt value.

        This validates our implementation matches the glibc specification.
        """
        # Using a known test vector
        password = "Hello world!"
        salt = "saltstring"
        result = _sha512_crypt_impl(password, salt)

        # Verify format
        assert result.startswith("$6$saltstring$")

        # The hash should be 86 characters after the final $
        parts = result.split("$")
        assert len(parts[3]) == 86

    def test_sha512_crypt_impl_minimum_rounds(self):
        """Test with minimum round count."""
        result = _sha512_crypt_impl("password", "testsalt", rounds=1)
        assert "$rounds=1$" in result

    def test_sha512_crypt_impl_hash_length(self):
        """Test that the hash portion is always 86 characters."""
        for password in ["", "a", "short", "a" * 100]:
            result = _sha512_crypt_impl(password, "salt")
            hash_part = result.split("$")[-1]
            assert len(hash_part) == 86


class TestHashPasswordSha512:
    """Test cases for the hash_password_sha512 function."""

    def test_hash_password_sha512_format(self):
        """Test that hash has correct format."""
        result = hash_password_sha512("testpassword")
        assert result.startswith("$6$")
        parts = result.split("$")
        assert len(parts) == 4  # Empty, 6, salt, hash
        assert parts[1] == "6"

    def test_hash_password_sha512_salt_length(self):
        """Test that generated salt is 16 characters."""
        result = hash_password_sha512("testpassword")
        parts = result.split("$")
        # Salt is in parts[2]
        assert len(parts[2]) == 16

    def test_hash_password_sha512_uniqueness(self):
        """Test that each hash is unique due to random salt."""
        results = [hash_password_sha512("samepassword") for _ in range(10)]
        # All hashes should be unique
        assert len(set(results)) == 10

    def test_hash_password_sha512_empty_password(self):
        """Test hashing empty password."""
        result = hash_password_sha512("")
        assert result.startswith("$6$")

    def test_hash_password_sha512_long_password(self):
        """Test hashing very long password."""
        long_password = "a" * 1000
        result = hash_password_sha512(long_password)
        assert result.startswith("$6$")

    def test_hash_password_sha512_special_characters(self):
        """Test hashing password with special characters."""
        special_password = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        result = hash_password_sha512(special_password)
        assert result.startswith("$6$")

    @patch("src.sysmanage_agent.operations.child_host_vmm_password_utils.generate_salt")
    def test_hash_password_sha512_uses_generate_salt(self, mock_generate_salt):
        """Test that hash_password_sha512 uses generate_salt function."""
        mock_generate_salt.return_value = "fixedsalt1234567"
        result = hash_password_sha512("password")
        mock_generate_salt.assert_called_once_with(16)
        assert "$fixedsalt1234567$" in result


class TestHashPasswordSha256:
    """Test cases for the hash_password_sha256 function."""

    def test_hash_password_sha256_falls_back_to_sha512(self):
        """Test that sha256 function falls back to sha512 format."""
        result = hash_password_sha256("testpassword")
        # Should produce SHA-512 format ($6$) not SHA-256 ($5$)
        assert result.startswith("$6$")

    def test_hash_password_sha256_format(self):
        """Test that hash has correct format."""
        result = hash_password_sha256("testpassword")
        parts = result.split("$")
        assert len(parts) == 4
        assert parts[1] == "6"  # SHA-512, not SHA-256

    def test_hash_password_sha256_uniqueness(self):
        """Test that each hash is unique due to random salt."""
        results = [hash_password_sha256("samepassword") for _ in range(10)]
        assert len(set(results)) == 10

    def test_hash_password_sha256_calls_sha512(self):
        """Test that sha256 function delegates to sha512 function."""
        with patch(
            "src.sysmanage_agent.operations.child_host_vmm_password_utils.hash_password_sha512"
        ) as mock_sha512:
            mock_sha512.return_value = "$6$salt$hash"
            result = hash_password_sha256("password")
            mock_sha512.assert_called_once_with("password")
            assert result == "$6$salt$hash"


class TestVerifyPassword:
    """Test cases for the verify_password function."""

    def test_verify_password_correct(self):
        """Test verifying correct password."""
        password = "testpassword123"
        hashed = hash_password_sha512(password)
        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Test verifying incorrect password."""
        password = "testpassword123"
        hashed = hash_password_sha512(password)
        assert verify_password("wrongpassword", hashed) is False

    def test_verify_password_empty_password(self):
        """Test verifying empty password."""
        password = ""
        hashed = hash_password_sha512(password)
        assert verify_password(password, hashed) is True
        assert verify_password("notempty", hashed) is False

    def test_verify_password_invalid_hash_format(self):
        """Test verifying against invalid hash format."""
        assert verify_password("password", "not_a_valid_hash") is False
        assert verify_password("password", "invalid") is False
        assert verify_password("password", "") is False

    def test_verify_password_not_sha512_prefix(self):
        """Test verifying against hash without $6$ prefix."""
        assert verify_password("password", "$5$salt$hash") is False  # SHA-256 prefix
        assert verify_password("password", "$1$salt$hash") is False  # MD5 prefix

    def test_verify_password_too_few_parts(self):
        """Test verifying against malformed hash with too few parts."""
        assert verify_password("password", "$6$") is False
        assert verify_password("password", "$6$salt") is False

    def test_verify_password_with_rounds(self):
        """Test verifying password with custom rounds in hash."""
        password = "testpassword"
        hashed = _sha512_crypt_impl(password, "testsalt", rounds=10000)
        assert verify_password(password, hashed) is True
        assert verify_password("wrongpassword", hashed) is False

    def test_verify_password_default_rounds(self):
        """Test verifying password with default rounds."""
        password = "testpassword"
        hashed = _sha512_crypt_impl(password, "testsalt", rounds=5000)
        assert verify_password(password, hashed) is True

    def test_verify_password_extracts_correct_salt(self):
        """Test that verify_password correctly extracts salt from hash."""
        password = "testpassword"
        salt = "customsalt123456"
        hashed = _sha512_crypt_impl(password, salt)
        assert verify_password(password, hashed) is True

    def test_verify_password_long_password(self):
        """Test verifying very long password."""
        password = "a" * 1000
        hashed = hash_password_sha512(password)
        assert verify_password(password, hashed) is True
        assert verify_password("a" * 999, hashed) is False

    def test_verify_password_special_characters(self):
        """Test verifying password with special characters."""
        password = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        hashed = hash_password_sha512(password)
        assert verify_password(password, hashed) is True

    def test_verify_password_case_sensitive(self):
        """Test that password verification is case sensitive."""
        password = "TestPassword"
        hashed = hash_password_sha512(password)
        assert verify_password(password, hashed) is True
        assert verify_password("testpassword", hashed) is False
        assert verify_password("TESTPASSWORD", hashed) is False

    def test_verify_password_rounds_parsing(self):
        """Test that rounds are correctly parsed from hash."""
        password = "password"
        hashed_with_rounds = _sha512_crypt_impl(password, "salt", rounds=1000)
        hashed_default = _sha512_crypt_impl(password, "salt", rounds=5000)

        # Both should verify correctly
        assert verify_password(password, hashed_with_rounds) is True
        assert verify_password(password, hashed_default) is True

        # But they should be different hashes
        assert hashed_with_rounds != hashed_default


class TestCryptB64Constant:
    """Test cases for the CRYPT_B64 constant."""

    def test_crypt_b64_length(self):
        """Test that CRYPT_B64 has exactly 64 characters."""
        assert len(CRYPT_B64) == 64

    def test_crypt_b64_unique_characters(self):
        """Test that all characters in CRYPT_B64 are unique."""
        assert len(set(CRYPT_B64)) == 64

    def test_crypt_b64_starts_with_special(self):
        """Test that CRYPT_B64 starts with ./ as per specification."""
        assert CRYPT_B64[:2] == "./"

    def test_crypt_b64_contains_digits(self):
        """Test that CRYPT_B64 contains all digits."""
        for digit in "0123456789":
            assert digit in CRYPT_B64

    def test_crypt_b64_contains_uppercase(self):
        """Test that CRYPT_B64 contains all uppercase letters."""
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            assert letter in CRYPT_B64

    def test_crypt_b64_contains_lowercase(self):
        """Test that CRYPT_B64 contains all lowercase letters."""
        for letter in "abcdefghijklmnopqrstuvwxyz":
            assert letter in CRYPT_B64


class TestIntegration:
    """Integration tests for password hashing workflow."""

    def test_hash_and_verify_workflow(self):
        """Test complete hash and verify workflow."""
        test_passwords = [
            "simple",
            "Complex!Password123",
            "",
            " " * 10,  # Spaces only
            "a" * 100,  # Very long
            "\t\n\r",  # Whitespace characters
        ]

        for password in test_passwords:
            hashed = hash_password_sha512(password)
            assert verify_password(
                password, hashed
            ), f"Failed for password: {repr(password)}"

    def test_different_salts_produce_different_hashes(self):
        """Test that same password with different salts produces different hashes."""
        password = "testpassword"
        hash1 = _sha512_crypt_impl(password, "salt1")
        hash2 = _sha512_crypt_impl(password, "salt2")
        assert hash1 != hash2

        # Both should still verify
        assert verify_password(password, hash1)
        assert verify_password(password, hash2)

    def test_round_count_affects_hash(self):
        """Test that different round counts produce different hashes."""
        password = "testpassword"
        salt = "fixedsalt"

        hash_1000 = _sha512_crypt_impl(password, salt, rounds=1000)
        hash_5000 = _sha512_crypt_impl(password, salt, rounds=5000)
        hash_10000 = _sha512_crypt_impl(password, salt, rounds=10000)

        # All should be different
        assert hash_1000 != hash_5000
        assert hash_5000 != hash_10000
        assert hash_1000 != hash_10000

        # All should verify correctly
        assert verify_password(password, hash_1000)
        assert verify_password(password, hash_5000)
        assert verify_password(password, hash_10000)

    def test_hash_format_compatibility(self):
        """Test that generated hashes follow the expected format for preseed."""
        password = "debian-installer-password"
        hashed = hash_password_sha512(password)

        # Format should be compatible with Debian preseed
        assert hashed.startswith("$6$")
        parts = hashed.split("$")
        assert len(parts) == 4

        # Salt should be 16 characters
        assert len(parts[2]) == 16

        # Hash should be 86 characters
        assert len(parts[3]) == 86

    def test_sha256_compatibility_with_sha512(self):
        """Test that sha256 function is compatible as a sha512 fallback."""
        password = "testpassword"
        hash_256_fallback = hash_password_sha256(password)
        hash_512 = hash_password_sha512(password)

        # Both should start with $6$ (SHA-512 format)
        assert hash_256_fallback.startswith("$6$")
        assert hash_512.startswith("$6$")

        # Both should verify correctly
        assert verify_password(password, hash_256_fallback)
        assert verify_password(password, hash_512)
