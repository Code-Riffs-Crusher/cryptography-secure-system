# crypto_algorithms/bcrypt_module.py

from crypto_algorithms.sha256 import sha256
import os



def generate_salt(length=16):

    random_bytes = os.urandom(length)
    return random_bytes.hex()


def constant_time_compare(value1, value2):

    if len(value1) != len(value2):
        return False

    result = 0

    for char1, char2 in zip(value1, value2):
        result |= ord(char1) ^ ord(char2)

    return result == 0


def bcrypt_like_hash(password, cost=12, salt=None):


    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if cost < 1:
        raise ValueError("Cost must be at least 1.")

    if salt is None:
        salt = generate_salt()

    password_bytes = password.encode("utf-8")
    salt_bytes = salt.encode("utf-8")

    data = password_bytes + salt_bytes

    rounds = 2 ** cost

    hashed_value = sha256(data)

    for _ in range(rounds - 1):
        data = hashed_value.encode("utf-8") + password_bytes + salt_bytes
        hashed_value = sha256(data)

    return f"$custombcrypt$v1${cost}${salt}${hashed_value}"


def bcrypt_like_verify(password, stored_hash):

    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    parts = stored_hash.split("$")

    if len(parts) != 6:
        return False

    algorithm_name = parts[1]
    version = parts[2]
    cost = parts[3]
    salt = parts[4]
    original_hash = parts[5]

    if algorithm_name != "custombcrypt":
        return False

    if version != "v1":
        return False

    try:
        cost = int(cost)
    except ValueError:
        return False

    new_hash = bcrypt_like_hash(password, cost, salt)
    new_hash_value = new_hash.split("$")[5]

    return constant_time_compare(original_hash, new_hash_value)


bcrypt_hash = bcrypt_like_hash
bcrypt_verify = bcrypt_like_verify


if __name__ == "__main__":
    password = input("Enter password: ")

    hashed_password = bcrypt_like_hash(password, cost=12)

    print("\nStored Hash:")
    print(hashed_password)

    password_check = input("\nRe-enter password to verify: ")

    if bcrypt_like_verify(password_check, hashed_password):
        print("Password is correct.")
    else:
        print("Password is incorrect.")