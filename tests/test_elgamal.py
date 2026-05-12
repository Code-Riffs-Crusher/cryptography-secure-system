from crypto_algorithms import elgamal


# =========================
# Global test parameters
# =========================
p = 467
g = 2


def test_prime_check():

    assert elgamal.is_prime(467) is True

    assert elgamal.is_prime(100) is False


def test_primitive_root():

    assert elgamal.is_primitive_root(2, 467) is True


def test_modular_inverse():

    assert elgamal.modular_inverse(3, 11) == 4


def test_encrypt_decrypt_single_character():

    public_key, private_key = elgamal.generate_keys(p, g)

    message = "A"

    encrypted = elgamal.encrypt(message, p, g, public_key)

    decrypted = elgamal.decrypt(encrypted, private_key, p)

    assert decrypted == message


def test_encrypt_decrypt_word():

    public_key, private_key = elgamal.generate_keys(p, g)

    message = "hello"

    encrypted = elgamal.encrypt(message, p, g, public_key)

    decrypted = elgamal.decrypt(encrypted, private_key, p)

    assert decrypted == message


def test_encrypt_decrypt_sentence():

    public_key, private_key = elgamal.generate_keys(p, g)

    message = "cryptography project"

    encrypted = elgamal.encrypt(message, p, g, public_key)

    decrypted = elgamal.decrypt(encrypted, private_key, p)

    assert decrypted == message


def test_same_message_decrypts_correctly_each_time():

    public_key, private_key = elgamal.generate_keys(p, g)

    message = "secure"

    encrypted1 = elgamal.encrypt(message, p, g, public_key)

    encrypted2 = elgamal.encrypt(message, p, g, public_key)

    decrypted1 = elgamal.decrypt(encrypted1, private_key, p)

    decrypted2 = elgamal.decrypt(encrypted2, private_key, p)

    assert decrypted1 == message

    assert decrypted2 == message


def test_same_message_produces_different_ciphertexts():

    public_key, private_key = elgamal.generate_keys(p, g)

    message = "hello"

    encrypted1 = elgamal.encrypt(message, p, g, public_key)

    encrypted2 = elgamal.encrypt(message, p, g, public_key)

    assert encrypted1 != encrypted2