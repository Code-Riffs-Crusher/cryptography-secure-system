import bcrypt

def hash_password(password):

    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    password_bytes = password.encode("utf-8")

    salt = bcrypt.gensalt(rounds=12)

    hashed_password = bcrypt.hashpw(password_bytes, salt)

    return hashed_password.decode("utf-8")


def verify_password(password, hashed_password):

    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not isinstance(hashed_password, str):
        raise TypeError("Hashed password must be a string.")

    password_bytes = password.encode("utf-8")
    hashed_password_bytes = hashed_password.encode("utf-8")

    return bcrypt.checkpw(password_bytes, hashed_password_bytes)

if __name__ == "__main__":
    password = input("Enter a password: ")

    hashed = hash_password(password)

    print("Original password:", password)
    print("Hashed password:", hashed)

    check_password = input("Enter password again to verify: ")

    if verify_password(check_password, hashed):
        print("Password is correct.")
    else:
        print("Password is incorrect.")