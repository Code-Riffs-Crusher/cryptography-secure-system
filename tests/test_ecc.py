from crypto_algorithms import ecc


# Shared curve + base point
p, a, b = ecc.init_curve()
G = ecc.find_valid_point(p, a, b)


def test_curve_initialization():
    p_test, a_test, b_test = ecc.init_curve()

    assert p_test == 233
    assert a_test == 1
    assert b_test == 1


def test_base_point_on_curve():
    assert ecc.is_on_curve(G, p, a, b) is True


def test_identity_element():

    P = (10, 20)

    assert ecc.point_add(P, ecc.O, p, a) == P
    assert ecc.point_add(ecc.O, P, p, a) == P


def test_encrypt_decrypt_word():

    private_key, public_key = ecc.generate_keys(G, p, a, b)

    message = "hello"

    encrypted = ecc.encrypt(message, G, public_key, p, a)
    decrypted = ecc.decrypt(encrypted, private_key, p, a)

    assert decrypted == message


def test_encrypt_decrypt_sentence():

    private_key, public_key = ecc.generate_keys(G, p, a, b)

    message = "ecc works correctly"

    encrypted = ecc.encrypt(message, G, public_key, p, a)
    decrypted = ecc.decrypt(encrypted, private_key, p, a)

    assert decrypted == message


def test_same_key_consistency():

    private_key, public_key = ecc.generate_keys(G, p, a, b)

    msg = "test consistency"

    enc1 = ecc.encrypt(msg, G, public_key, p, a)
    dec1 = ecc.decrypt(enc1, private_key, p, a)

    enc2 = ecc.encrypt(msg, G, public_key, p, a)
    dec2 = ecc.decrypt(enc2, private_key, p, a)

    assert dec1 == msg
    assert dec2 == msg


def test_different_messages_produce_different_ciphertexts():

    private_key, public_key = ecc.generate_keys(G, p, a, b)

    msg1 = "hello"
    msg2 = "world"

    enc1 = ecc.encrypt(msg1, G, public_key, p, a)
    enc2 = ecc.encrypt(msg2, G, public_key, p, a)

    assert enc1 != enc2