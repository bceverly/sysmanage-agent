"""
Password hashing utilities for VMM child host creation.

This module provides password hashing functions for different operating systems.
Different preseed/autoinstall systems require different hash formats:
- Debian preseed: SHA-512 crypt format ($6$...)
- Alpine: bcrypt or plain text with chpasswd

Note: OpenBSD's crypt() doesn't support SHA-512 ($6$), so we implement it
using hashlib following the specification from glibc.
"""

import hashlib
import secrets
import string


# Base64 alphabet used by SHA-512 crypt (different from standard base64)
CRYPT_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def generate_salt(length: int = 16) -> str:
    """
    Generate a random salt for password hashing.

    Args:
        length: Salt length (default 16)

    Returns:
        Random salt string
    """
    # Use alphanumeric characters plus ./
    alphabet = string.ascii_letters + string.digits + "./"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _b64_encode_24bit(b1: int, b2: int, b3: int, n: int) -> str:
    """Encode 3 bytes into n base64 characters for SHA-512 crypt."""
    packed_value = (b1 << 16) | (b2 << 8) | b3
    result = ""
    for _ in range(n):
        result += CRYPT_B64[packed_value & 0x3F]
        packed_value >>= 6
    return result


def _create_repeated_bytes(digest: bytes, length: int) -> bytes:
    """Create a byte string by repeating digest to fill specified length."""
    result = b""
    remaining = length
    while remaining > 64:
        result += digest
        remaining -= 64
    result += digest[:remaining]
    return result


def _create_digest_a(
    password_bytes: bytes, salt_bytes: bytes, digest_b: bytes
) -> bytes:
    """Create digest A as per SHA-512 crypt specification."""
    a_ctx = hashlib.sha512()  # nosec B324 - SHA-512 crypt KDF, not simple hash
    a_ctx.update(password_bytes)  # nosec B324 - SHA-512 crypt KDF step
    a_ctx.update(salt_bytes)

    # Step 11: Add bytes from B based on password length
    pwd_len = len(password_bytes)
    remaining = pwd_len
    while remaining > 64:
        a_ctx.update(digest_b)
        remaining -= 64
    a_ctx.update(digest_b[:remaining])

    # Step 12: For each bit of password length, add B or password
    i = pwd_len
    while i > 0:
        if i & 1:
            a_ctx.update(digest_b)
        else:
            a_ctx.update(password_bytes)  # nosec B324 - SHA-512 crypt KDF step
        i >>= 1

    return a_ctx.digest()


def _perform_rounds(
    digest_a: bytes, p_bytes: bytes, s_bytes: bytes, rounds: int
) -> bytes:
    """Perform the key stretching rounds of SHA-512 crypt."""
    digest_c = digest_a
    for i in range(rounds):
        c_ctx = hashlib.sha512()

        if i & 1:
            c_ctx.update(p_bytes)
        else:
            c_ctx.update(digest_c)

        if i % 3:
            c_ctx.update(s_bytes)

        if i % 7:
            c_ctx.update(p_bytes)

        if i & 1:
            c_ctx.update(digest_c)
        else:
            c_ctx.update(p_bytes)

        digest_c = c_ctx.digest()

    return digest_c


def _encode_final_digest(digest_c: bytes) -> str:
    """Encode the final digest using SHA-512 crypt base64 encoding."""
    result = ""
    result += _b64_encode_24bit(digest_c[0], digest_c[21], digest_c[42], 4)
    result += _b64_encode_24bit(digest_c[22], digest_c[43], digest_c[1], 4)
    result += _b64_encode_24bit(digest_c[44], digest_c[2], digest_c[23], 4)
    result += _b64_encode_24bit(digest_c[3], digest_c[24], digest_c[45], 4)
    result += _b64_encode_24bit(digest_c[25], digest_c[46], digest_c[4], 4)
    result += _b64_encode_24bit(digest_c[47], digest_c[5], digest_c[26], 4)
    result += _b64_encode_24bit(digest_c[6], digest_c[27], digest_c[48], 4)
    result += _b64_encode_24bit(digest_c[28], digest_c[49], digest_c[7], 4)
    result += _b64_encode_24bit(digest_c[50], digest_c[8], digest_c[29], 4)
    result += _b64_encode_24bit(digest_c[9], digest_c[30], digest_c[51], 4)
    result += _b64_encode_24bit(digest_c[31], digest_c[52], digest_c[10], 4)
    result += _b64_encode_24bit(digest_c[53], digest_c[11], digest_c[32], 4)
    result += _b64_encode_24bit(digest_c[12], digest_c[33], digest_c[54], 4)
    result += _b64_encode_24bit(digest_c[34], digest_c[55], digest_c[13], 4)
    result += _b64_encode_24bit(digest_c[56], digest_c[14], digest_c[35], 4)
    result += _b64_encode_24bit(digest_c[15], digest_c[36], digest_c[57], 4)
    result += _b64_encode_24bit(digest_c[37], digest_c[58], digest_c[16], 4)
    result += _b64_encode_24bit(digest_c[59], digest_c[17], digest_c[38], 4)
    result += _b64_encode_24bit(digest_c[18], digest_c[39], digest_c[60], 4)
    result += _b64_encode_24bit(digest_c[40], digest_c[61], digest_c[19], 4)
    result += _b64_encode_24bit(digest_c[62], digest_c[20], digest_c[41], 4)
    result += _b64_encode_24bit(0, 0, digest_c[63], 2)
    return result


def _sha512_crypt_impl(password: str, salt: str, rounds: int = 5000) -> str:
    """
    Implement SHA-512 crypt algorithm as specified by glibc.

    This is a pure Python implementation that works on OpenBSD
    where the system crypt() doesn't support $6$ hashes.

    SECURITY NOTE: This implements the SHA-512 crypt KDF (key derivation function),
    NOT simple SHA-512 hashing. SHA-512 crypt is the standard password hashing
    algorithm used by Linux systems in /etc/shadow ($6$ format). It includes:
    - Cryptographically random salt (16 chars)
    - 5000 rounds of key stretching by default
    - Complex mixing algorithm specified by glibc

    This is required for Debian preseed compatibility. The passlib/crypt modules
    that would normally provide this are not available on OpenBSD.

    Args:
        password: Plain text password
        salt: Salt string (max 16 chars)
        rounds: Number of rounds (default 5000)

    Returns:
        SHA-512 crypt hash string
    """
    # Truncate salt to 16 characters max
    salt = salt[:16]
    password_bytes = password.encode("utf-8")
    salt_bytes = salt.encode("utf-8")
    pwd_len = len(password_bytes)

    # Step 1-8: Create digest B
    # Note: hashlib.sha512 usage here is part of SHA-512 crypt KDF, not simple hashing
    b_ctx = hashlib.sha512()  # nosec B324 - SHA-512 crypt KDF, not simple hash
    b_ctx.update(password_bytes)  # nosec B324 - SHA-512 crypt KDF step
    b_ctx.update(salt_bytes)
    b_ctx.update(password_bytes)  # nosec B324 - SHA-512 crypt KDF step
    digest_b = b_ctx.digest()

    # Step 9-12: Create digest A
    digest_a = _create_digest_a(password_bytes, salt_bytes, digest_b)

    # Step 13-15: Create digest DP (password repeated)
    dp_ctx = hashlib.sha512()  # nosec B324 - SHA-512 crypt KDF, not simple hash
    for _ in range(pwd_len):
        dp_ctx.update(password_bytes)  # nosec B324 - SHA-512 crypt KDF step
    digest_dp = dp_ctx.digest()

    # Step 16: Create P string
    p_bytes = _create_repeated_bytes(digest_dp, pwd_len)

    # Step 17-19: Create digest DS (salt repeated 16 + A[0] times)
    ds_ctx = hashlib.sha512()
    for _ in range(16 + digest_a[0]):
        ds_ctx.update(salt_bytes)
    digest_ds = ds_ctx.digest()

    # Step 20: Create S string
    s_bytes = _create_repeated_bytes(digest_ds, len(salt_bytes))

    # Step 21: Perform rounds
    digest_c = _perform_rounds(digest_a, p_bytes, s_bytes, rounds)

    # Step 22: Encode final digest
    result = _encode_final_digest(digest_c)

    # Format: $6$salt$hash (or $6$rounds=N$salt$hash if non-default rounds)
    if rounds == 5000:
        return f"$6${salt}${result}"
    return f"$6$rounds={rounds}${salt}${result}"


def hash_password_sha512(password: str) -> str:
    """
    Hash a password using SHA-512 crypt format.

    This format is required by Debian preseed for passwd/user-password-crypted.
    The output format is $6$<salt>$<hash>

    Uses a pure Python implementation that works on OpenBSD where the
    system crypt() doesn't support SHA-512 ($6$) hashes.

    Args:
        password: Plain text password to hash

    Returns:
        SHA-512 crypt formatted password hash
    """
    salt = generate_salt(16)
    return _sha512_crypt_impl(password, salt)


def hash_password_sha256(password: str) -> str:
    """
    Hash a password using SHA-256 crypt format.

    Note: This currently returns a SHA-512 hash as SHA-256 crypt
    is also not supported on OpenBSD and is less common.

    Args:
        password: Plain text password to hash

    Returns:
        SHA-512 crypt formatted password hash (for compatibility)
    """
    # Fall back to SHA-512 since SHA-256 crypt is also unsupported on OpenBSD
    return hash_password_sha512(password)


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against a SHA-512 crypt hash.

    Args:
        password: Plain text password to verify
        hashed: Hashed password to compare against

    Returns:
        True if password matches, False otherwise
    """
    # Parse the hash to extract salt and rounds
    if not hashed.startswith("$6$"):
        return False

    parts = hashed.split("$")
    if len(parts) < 4:
        return False

    if parts[2].startswith("rounds="):
        # Format: $6$rounds=N$salt$hash
        rounds = int(parts[2].split("=")[1])
        salt = parts[3]
    else:
        # Format: $6$salt$hash
        rounds = 5000
        salt = parts[2]

    computed = _sha512_crypt_impl(password, salt, rounds)
    return computed == hashed
