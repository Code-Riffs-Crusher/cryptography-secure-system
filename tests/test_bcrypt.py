from crypto_algorithms.bcrypt_module import hash_password, verify_password


def test_bcrypt_hash_is_string():
    password = "maria mark"
    hashed = hash_password(password)

    assert isinstance(hashed, str)


def test_bcrypt_hash_is_not_same_as_password():
    password = "habiba fahd"
    hashed = hash_password(password)

    assert hashed != password


def test_bcrypt_correct_password_verifies_true():
    password = "hello world"
    hashed = hash_password(password)

    assert verify_password(password, hashed) is True


def test_bcrypt_wrong_password_verifies_false():
    password = "hello world"
    wrong_password = "Hello World"

    hashed = hash_password(password)

    assert verify_password(wrong_password, hashed) is False


def test_bcrypt_same_password_creates_different_hashes():
    password = "123456789"

    hashed1 = hash_password(password)
    hashed2 = hash_password(password)

    assert hashed1 != hashed2


def test_bcrypt_different_hashes_still_verify_same_password():
    password = "cryptography project"

    hashed1 = hash_password(password)
    hashed2 = hash_password(password)

    assert verify_password(password, hashed1) is True
    assert verify_password(password, hashed2) is True


def test_bcrypt_empty_password():
    password = ""

    hashed = hash_password(password)

    assert verify_password(password, hashed) is True


def test_bcrypt_rejects_non_string_password():
    try:
        hash_password(12345)
        assert False
    except TypeError:
        assert True


def test_bcrypt_rejects_invalid_hash_format():
    try:
        verify_password("hello", "not_bytes_hash")
        assert False
    except ValueError:
        assert True