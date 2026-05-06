from crypto_algorithms.md5 import md5


def test_md5_empty_string():
    assert md5("") == "d41d8cd98f00b204e9800998ecf8427e"


def test_md5_maria_mark():
    assert md5("maria mark") == "9f7f94daf55ff6f296b472c4b51a7802"


def test_md5_habiba_fahd():
    assert md5("habiba fahd") == "24da1a28524aa4f72945ff3771e64141"


def test_md5_hello_world():
    assert md5("hello world") == "5eb63bbbe01eeed093cb22bb8f5acdc3"


def test_md5_numbers():
    assert md5("123456789") == "25f9e794323b453885f5181f1b624d0b"


def test_md5_same_input_same_hash():
    text = "cryptography project"
    assert md5(text) == md5(text)


def test_md5_different_inputs_different_hashes():
    assert md5("hello") != md5("Hello")