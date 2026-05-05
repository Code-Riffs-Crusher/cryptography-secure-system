from crypto_algorithms.sha1 import sha1


def test_sha1_empty_string():
    assert sha1("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def test_sha1_abc():
    assert sha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d"


def test_sha1_hello_world():
    assert sha1("hello world") == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"


def test_sha1_maria_mark():
    assert sha1("maria mark") == "38e664e1834a4c739fd0542646cc93700c0e6f53"


def test_sha1_habiba_fahd():
    assert sha1("habiba fahd") == "15f74021e0741c85b5310d44466b962c6b05266b"


def test_sha1_numbers():
    assert sha1("123456789") == "f7c3bc1d808e04732adf679965ccc34ca7ae3441"


def test_sha1_same_input_same_hash():
    text = "cryptography project"
    assert sha1(text) == sha1(text)


def test_sha1_different_inputs_different_hashes():
    assert sha1("hello") != sha1("Hello")


def test_sha1_output_length():
    assert len(sha1("abc")) == 40