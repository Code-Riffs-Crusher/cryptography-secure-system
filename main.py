from crypto_algorithms.md5 import md5
from crypto_algorithms.sha1 import sha1
from crypto_algorithms.sha256 import sha256
from crypto_algorithms.bcrypt_module import hash_password, verify_password

from crypto_algorithms import elgamal
from crypto_algorithms import ecc


def run_hashing_demo():
    print("\n===== HASHING DEMO =====")

    text = "hello world"

    print("MD5:", md5(text))
    print("SHA1:", sha1(text))
    print("SHA256:", sha256(text))


def run_bcrypt_demo():
    print("\n===== BCRYPT DEMO =====")

    password = "admin123"

    hashed = hash_password(password)
    print("Hashed password:", hashed)

    print("Verification (correct):", verify_password("admin123", hashed))
    print("Verification (wrong):", verify_password("wrongpass", hashed))


def run_elgamal_demo():
    print("\n===== ELGAMAL DEMO =====")

    p, g = 467, 2

    private_key, public_key = elgamal.generate_keys(p, g)

    message = "hi"

    encrypted = elgamal.encrypt(message, public_key, p, g)
    decrypted = elgamal.decrypt(encrypted, private_key, p)

    print("Original:", message)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)


def run_ecc_demo():
    print("\n===== ECC DEMO =====")

    p, a, b = ecc.init_curve()

    # IMPORTANT: automatically get valid base point
    G = ecc.find_valid_point(p, a, b)

    private_key, public_key = ecc.generate_keys(G, p, a, b)

    message = "hello ecc"

    encrypted = ecc.encrypt(message, G, public_key, p, a)
    decrypted = ecc.decrypt(encrypted, private_key, p, a)

    print("Original:", message)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)


if __name__ == "__main__":

    print("\n==============================")
    print("CRYPTOGRAPHY SYSTEM DEMO")
    print("==============================")

    run_hashing_demo()
    run_bcrypt_demo()
    run_elgamal_demo()
    run_ecc_demo()

    print("\n===== END OF DEMO =====")