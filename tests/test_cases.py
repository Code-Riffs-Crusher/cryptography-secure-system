"""
Cryptography and System Security — Unified Test Suite
======================================================
Maps directly to every test case in test_cases.txt.

Run from the project root:
    pytest tests/test_cases.py -v

Notes on implementation gaps (marked with pytest.skip):
  - ECC-06  : sign / verify not implemented in ecc.py
  - ELG-04  : sign not implemented in elgamal.py
  - ELG-05  : verify not implemented in elgamal.py
"""

import sys
import os
import concurrent.futures
import pytest

# ── Make sure the project root is on the path ─────────────────────────────────
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto_algorithms.ecc          import (init_curve, find_valid_point,
                                             generate_keys as ecc_generate_keys,
                                             encrypt as ecc_encrypt,
                                             decrypt as ecc_decrypt,
                                             is_on_curve)

from crypto_algorithms.elgamal      import (generate_keys as elg_generate_keys,
                                             encrypt as elg_encrypt,
                                             decrypt as elg_decrypt,
                                             is_prime, is_primitive_root)

from crypto_algorithms.md5          import md5
from crypto_algorithms.sha1         import sha1
from crypto_algorithms.sha256       import sha256
from crypto_algorithms.bcrypt_module import hash_password, verify_password


# ══════════════════════════════════════════════════════════════════════════════
# Shared ECC curve fixture — reused across all ECC tests
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def ecc_setup():
    """Initialise a valid ECC curve, base point, and key pair once per module."""
    p, a, b = init_curve(p=233, a=1, b=1)
    G = find_valid_point(p, a, b)
    private_key, public_key = ecc_generate_keys(G, p, a, b)
    return {"p": p, "a": a, "b": b, "G": G,
            "private_key": private_key, "public_key": public_key}


# ══════════════════════════════════════════════════════════════════════════════
# ECC Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestECC:

    def test_ECC_01_generate_valid_keypair(self, ecc_setup):
        """ECC-01 — Generate a valid ECC key pair on secp-like curve."""
        priv = ecc_setup["private_key"]
        pub  = ecc_setup["public_key"]

        assert priv is not None, "Private key must not be None"
        assert pub  is not None, "Public key must not be None"
        assert isinstance(priv, int), "Private key should be an integer"
        # Public key is a point (tuple) on the curve
        assert is_on_curve(pub, ecc_setup["p"], ecc_setup["a"], ecc_setup["b"]), \
            "Public key point must lie on the curve"

    def test_ECC_02_invalid_curve_parameters(self):
        """ECC-02 — Singular curve (a=0, b=0) must raise ValueError."""
        # 4*0³ + 27*0² = 0  →  discriminant is 0  →  curve is singular
        with pytest.raises(ValueError, match="Invalid ECC curve parameters"):
            init_curve(p=233, a=0, b=0)

    def test_ECC_03_encrypt_produces_ciphertext(self, ecc_setup):
        """ECC-03 — Encrypting 'Hello' should return a non-empty ciphertext list."""
        ct = ecc_encrypt("Hello",
                         ecc_setup["G"],
                         ecc_setup["public_key"],
                         ecc_setup["p"],
                         ecc_setup["a"])

        assert ct is not None,      "Ciphertext must not be None"
        assert len(ct) > 0,         "Ciphertext list must not be empty"
        assert ct != "Hello",       "Ciphertext must differ from plaintext"
        # Each element is a (C1, C2) pair
        for C1, C2 in ct:
            assert isinstance(C2, int), "C2 must be an integer"

    def test_ECC_04_decrypt_restores_plaintext(self, ecc_setup):
        """ECC-04 — Decrypting a valid ciphertext must restore the original message."""
        plaintext = "Hello"
        ct = ecc_encrypt(plaintext,
                         ecc_setup["G"],
                         ecc_setup["public_key"],
                         ecc_setup["p"],
                         ecc_setup["a"])

        result = ecc_decrypt(ct, ecc_setup["private_key"],
                             ecc_setup["p"], ecc_setup["a"])

        assert result == plaintext, f"Expected '{plaintext}', got '{result}'"

    def test_ECC_05_wrong_private_key_fails_decryption(self, ecc_setup):
        """ECC-05 — Using the wrong private key must NOT recover the original plaintext."""
        plaintext = "Hello"
        ct = ecc_encrypt(plaintext,
                         ecc_setup["G"],
                         ecc_setup["public_key"],
                         ecc_setup["p"],
                         ecc_setup["a"])

        # Generate a different private key
        _, wrong_public = ecc_generate_keys(ecc_setup["G"],
                                            ecc_setup["p"],
                                            ecc_setup["a"],
                                            ecc_setup["b"])
        # Derive a different private scalar (reuse wrong_public x-coord as scalar)
        wrong_private = ecc_setup["private_key"] + 1  # guaranteed different

        result = ecc_decrypt(ct, wrong_private,
                             ecc_setup["p"], ecc_setup["a"])

        assert result != plaintext, \
            "Wrong private key should NOT successfully decrypt the ciphertext"

    @pytest.mark.skip(reason="ECC-06: sign/verify not implemented in ecc.py")
    def test_ECC_06_digital_signature_verification(self, ecc_setup):
        """ECC-06 — Digital signature verification (not yet implemented)."""
        pass


# ══════════════════════════════════════════════════════════════════════════════
# MD5 Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestMD5:

    def test_MD5_01_hash_known_input(self):
        """MD5-01 — 'password123' must produce its known MD5 digest."""
        result = md5("password123")
        assert result == "482c811da5d5b4bc6d497ffa98491e38", \
            f"Unexpected MD5 hash: {result}"

    def test_MD5_02_hash_empty_string(self):
        """MD5-02 — Empty string must produce the standard MD5 empty-hash."""
        result = md5("")
        assert result == "d41d8cd98f00b204e9800998ecf8427e", \
            f"Unexpected empty-string MD5 hash: {result}"

    def test_MD5_03_hash_large_input(self):
        """MD5-03 — Hashing a ~1 MB string must complete and return 32 hex chars."""
        large_input = "a" * (1024 * 1024)
        result = md5(large_input)
        assert result is not None
        assert len(result) == 32, \
            f"MD5 digest must be 32 hex characters, got {len(result)}"

    def test_MD5_04_same_input_same_output(self):
        """MD5-04 — Hashing the same text twice must yield identical results."""
        text = "consistent_input"
        assert md5(text) == md5(text), \
            "MD5 must be deterministic for identical inputs"

    def test_MD5_05_different_inputs_different_hashes(self):
        """MD5-05 — 'abc' and 'abcd' must produce different MD5 digests."""
        assert md5("abc") != md5("abcd"), \
            "Different inputs must produce different MD5 hashes"


# ══════════════════════════════════════════════════════════════════════════════
# SHA-1 Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestSHA1:

    def test_SHA1_01_hash_known_text(self):
        """SHA1-01 — 'hello' must produce its known SHA-1 digest."""
        result = sha1("hello")
        assert result == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", \
            f"Unexpected SHA-1 hash: {result}"

    def test_SHA1_02_hash_empty_string(self):
        """SHA1-02 — Empty string must produce the standard SHA-1 empty-hash."""
        result = sha1("")
        assert result == "da39a3ee5e6b4b0d3255bfef95601890afd80709", \
            f"Unexpected empty-string SHA-1 hash: {result}"

    def test_SHA1_03_hash_large_data(self):
        """SHA1-03 — Hashing ~1 MB of bytes must complete and return 40 hex chars."""
        large_data = b"x" * (1024 * 1024)      # sha1() accepts bytes
        result = sha1(large_data)
        assert result is not None
        assert len(result) == 40, \
            f"SHA-1 digest must be 40 hex characters, got {len(result)}"

    def test_SHA1_04_tampered_data_changes_hash(self):
        """SHA1-04 — Any modification to the input must produce a different hash."""
        original = sha1("original content")
        tampered = sha1("original content!")     # one character added
        assert original != tampered, \
            "SHA-1 must produce a different digest for modified data"


# ══════════════════════════════════════════════════════════════════════════════
# SHA-256 Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestSHA256:

    def test_SHA256_01_hash_standard_text(self):
        """SHA256-01 — 'CyberSecurity' must return a valid 64-char hex digest."""
        result = sha256("CyberSecurity")
        assert result is not None
        assert len(result) == 64, \
            f"SHA-256 digest must be 64 hex characters, got {len(result)}"
        assert all(c in "0123456789abcdef" for c in result), \
            "SHA-256 digest must contain only lowercase hex characters"

    def test_SHA256_02_unicode_characters(self):
        """SHA256-02 — Unicode input must produce a valid 64-char digest without error."""
        result = sha256("مرحبا 안녕하세요 🌍")
        assert result is not None
        assert len(result) == 64, \
            f"SHA-256 digest for unicode must be 64 hex characters, got {len(result)}"

    def test_SHA256_03_large_input_hash(self):
        """SHA256-03 — Hashing a large string must complete and return 64 hex chars.
        Note: sha256() in this project accepts strings only (not bytes).
        """
        large_string = "z" * 50_000      # large string; bytes not supported by this impl
        result = sha256(large_string)
        assert result is not None
        assert len(result) == 64, \
            f"SHA-256 digest must be 64 hex characters, got {len(result)}"

    def test_SHA256_04_data_integrity_verification(self):
        """SHA256-04 — Modifying the data must produce a different SHA-256 hash."""
        original = sha256("important data")
        modified = sha256("important data.")     # one character added
        assert original != modified, \
            "SHA-256 must produce a different digest for modified data"


# ══════════════════════════════════════════════════════════════════════════════
# Bcrypt Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestBcrypt:

    def test_BCRYPT_01_hash_password(self):
        """BCRYPT-01 — 'Admin@123' must produce a non-empty bcrypt hash string."""
        hashed = hash_password("Admin@123")
        assert hashed is not None,           "Hash must not be None"
        assert isinstance(hashed, str),      "Hash must be a string"
        assert hashed != "Admin@123",        "Hash must differ from the original password"
        assert hashed.startswith("$2b$") or hashed.startswith("$2a$"), \
            "Hash must be a valid bcrypt string (starts with $2b$ or $2a$)"

    def test_BCRYPT_02_verify_correct_password(self):
        """BCRYPT-02 — Verifying the correct password must return True."""
        hashed = hash_password("Admin@123")
        assert verify_password("Admin@123", hashed) is True, \
            "Correct password must verify successfully"

    def test_BCRYPT_03_verify_wrong_password(self):
        """BCRYPT-03 — Verifying a wrong password must return False."""
        hashed = hash_password("Admin@123")
        assert verify_password("WrongPassword!", hashed) is False, \
            "Wrong password must not verify successfully"

    def test_BCRYPT_04_salt_uniqueness(self):
        """BCRYPT-04 — Hashing the same password twice must produce different hashes."""
        hash1 = hash_password("Admin@123")
        hash2 = hash_password("Admin@123")
        assert hash1 != hash2, \
            "Each bcrypt call must embed a unique salt, producing a different hash"


# ══════════════════════════════════════════════════════════════════════════════
# El Gamal Tests
# ══════════════════════════════════════════════════════════════════════════════

# Safe small prime and known primitive root for fast tests
ELG_P = 467
ELG_G = 2


class TestElGamal:

    def test_ELG_01_generate_keypair(self):
        """ELG-01 — generate_keys with valid prime p and generator g must succeed."""
        assert is_prime(ELG_P),             f"{ELG_P} must be prime"
        assert is_primitive_root(ELG_G, ELG_P), \
            f"{ELG_G} must be a primitive root mod {ELG_P}"

        public_key, private_key = elg_generate_keys(p=ELG_P, g=ELG_G)

        assert public_key  is not None, "Public key must not be None"
        assert private_key is not None, "Private key must not be None"
        assert isinstance(public_key,  int), "Public key must be an integer"
        assert isinstance(private_key, int), "Private key must be an integer"
        assert 2 <= private_key <= ELG_P - 2, \
            "Private key must be in the valid range [2, p-2]"

    def test_ELG_01b_invalid_prime_raises(self):
        """ELG-01 (negative) — Non-prime p must raise ValueError."""
        with pytest.raises(ValueError, match="p must be prime"):
            elg_generate_keys(p=100, g=2)   # 100 is not prime

    def test_ELG_02_encrypt_produces_ciphertext(self):
        """ELG-02 — Encrypting 'Secret Message' must return a non-trivial ciphertext."""
        public_key, _ = elg_generate_keys(p=ELG_P, g=ELG_G)
        ct = elg_encrypt("Secret Message", ELG_P, ELG_G, public_key)

        assert ct is not None,   "Ciphertext must not be None"
        assert len(ct) > 0,      "Ciphertext list must not be empty"
        assert ct != "Secret Message", "Ciphertext must differ from plaintext"
        # Each element must be a (c1, c2) integer pair
        for c1, c2 in ct:
            assert isinstance(c1, int) and isinstance(c2, int), \
                "Each ciphertext element must be a pair of integers"

    def test_ELG_03_decrypt_restores_plaintext(self):
        """ELG-03 — Decrypting a valid ciphertext must restore the original message."""
        public_key, private_key = elg_generate_keys(p=ELG_P, g=ELG_G)
        plaintext = "Secret Message"
        ct = elg_encrypt(plaintext, ELG_P, ELG_G, public_key)
        result = elg_decrypt(ct, private_key, ELG_P)
        assert result == plaintext, f"Expected '{plaintext}', got '{result}'"

    @pytest.mark.skip(reason="ELG-04: sign() not implemented in elgamal.py")
    def test_ELG_04_verify_signature(self):
        """ELG-04 — El Gamal signature verification (not yet implemented)."""
        pass

    @pytest.mark.skip(reason="ELG-05: verify() not implemented in elgamal.py")
    def test_ELG_05_modified_message_fails_verification(self):
        """ELG-05 — Signature check on altered message should fail (not yet implemented)."""
        pass


# ══════════════════════════════════════════════════════════════════════════════
# Common Security & Performance Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestCommon:

    def test_PERF_01_1000_concurrent_hash_operations(self):
        """PERF-01 — 1 000 concurrent MD5 operations must all complete stably."""
        def do_hash(i):
            return md5(f"concurrent_input_{i}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(do_hash, range(1000)))

        assert len(results) == 1000, \
            f"Expected 1000 results, got {len(results)}"
        assert all(len(r) == 32 for r in results), \
            "Every concurrent MD5 result must be a valid 32-char hex digest"
        # Each hash is unique (different inputs → different outputs)
        assert len(set(results)) == 1000, \
            "All 1000 results must be distinct (different inputs)"

    def test_NEG_01_null_input_raises_error(self):
        """NEG-01 — Passing None as a password must raise TypeError, not crash silently."""
        with pytest.raises(TypeError):
            hash_password(None)     # bcrypt_module explicitly checks type

    def test_NEG_02_corrupted_ciphertext_raises_error(self):
        """NEG-02 — Passing a corrupted (non-iterable-of-pairs) ciphertext must raise."""
        _, private_key = elg_generate_keys(p=ELG_P, g=ELG_G)
        # A plain string is not a list of (c1, c2) pairs; unpacking must fail
        with pytest.raises((ValueError, TypeError)):
            elg_decrypt("corrupted_ciphertext_data", private_key, ELG_P)

    def test_SEC_01_replay_attack_same_ciphertext(self):
        """SEC-01 — Re-using the same ciphertext (replay) must not forge a new plaintext.

        This implementation is stateless — the same ciphertext always decrypts
        to the same value. True replay protection (nonce/session tracking) would
        need to be added at the application layer.
        """
        public_key, private_key = elg_generate_keys(p=ELG_P, g=ELG_G)
        original_plaintext = "Sensitive"
        ciphertext = elg_encrypt(original_plaintext, ELG_P, ELG_G, public_key)

        # First decryption
        first_result = elg_decrypt(ciphertext, private_key, ELG_P)
        assert first_result == original_plaintext, \
            "First decryption must succeed"

        # Replay: same ciphertext used again
        replay_result = elg_decrypt(ciphertext, private_key, ELG_P)
        assert replay_result == first_result, \
            "Replay must produce the same plaintext (no forged output)"

        # Additionally verify that two independent encryptions of the same
        # message produce DIFFERENT ciphertexts (due to random k), preventing
        # ciphertext-matching attacks
        ciphertext2 = elg_encrypt(original_plaintext, ELG_P, ELG_G, public_key)
        assert ciphertext != ciphertext2, \
            "Two encryptions of the same message must produce different ciphertexts"
