from crypto_algorithms.sha256 import sha256


def test_sha256_empty_string():
    assert sha256("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_abc():
    assert sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_hello_world():
    assert sha256("hello world") == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"


def test_sha256_numbers():
    assert sha256("123456789") == "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225"


def test_sha256_same_input_same_hash():
    text = "cryptography project"
    assert sha256(text) == sha256(text)


def test_sha256_different_inputs_different_hashes():
    assert sha256("hello") != sha256("Hello")