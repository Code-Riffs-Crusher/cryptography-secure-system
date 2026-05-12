# crypto_algorithms/bcrypt_module.py

from crypto_algorithms.sha256 import sha256
import os


def generate_salt(length=16):
    """
    Generates a random salt.

    os.urandom is used only to create random bytes.
    It is not a hashing library and it is not bcrypt.
    """
    random_bytes = os.urandom(length)
    return random_bytes.hex()


def constant_time_compare(value1, value2):
    """
    Compares two strings safely.

    This avoids returning immediately when one character is different.
    That is better for password verification.
    """
    if len(value1) != len(value2):
        return False

    result = 0

    for char1, char2 in zip(value1, value2):
        result |= ord(char1) ^ ord(char2)

    return result == 0


def bcrypt_like_hash(password, cost=12, salt=None):
    """
    Educational bcrypt-like password hashing function.

    This is NOT real bcrypt.
    It demonstrates bcrypt concepts:
    - UTF-8 password encoding
    - random salt
    - cost factor
    - repeated hashing
    - stored hash format
    """

    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if cost < 1:
        raise ValueError("Cost must be at least 1.")

    if salt is None:
        salt = generate_salt()

    # Convert password and salt to bytes.
    # Your sha256 function supports bytes because of text_to_bytes().
    password_bytes = password.encode("utf-8")
    salt_bytes = salt.encode("utf-8")

    # First mix: password + salt
    data = password_bytes + salt_bytes

    # The cost controls how many times hashing happens.
    # Example: cost = 12 means 2^12 = 4096 rounds.
    rounds = 2 ** cost

    hashed_value = sha256(data)

    for _ in range(rounds - 1):
        # sha256 returns a hex string, so we encode it again before hashing.
        data = hashed_value.encode("utf-8") + password_bytes + salt_bytes
        hashed_value = sha256(data)

    # Store all needed information in one string.
    # This allows verification later.
    return f"$custombcrypt$v1${cost}${salt}${hashed_value}"


def bcrypt_like_verify(password, stored_hash):
    """
    Verifies a password against a stored bcrypt-like hash.
    """

    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    parts = stored_hash.split("$")

    # Expected format:
    # $custombcrypt$v1$cost$salt$hash
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


# Optional aliases with shorter names
bcrypt_hash = bcrypt_like_hash
bcrypt_verify = bcrypt_like_verify


# Optional testing from terminal
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