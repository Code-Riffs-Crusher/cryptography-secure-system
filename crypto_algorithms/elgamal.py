import random

def gcd(a, b):

    while b != 0:
        a, b = b, a % b

    return a

def extended_gcd(a, b):

    if b == 0:
        return a, 1, 0

    gcd_value, x1, y1 = extended_gcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return gcd_value, x, y

def modular_inverse(a, p):

    gcd_value, x, y = extended_gcd(a, p)

    if gcd_value != 1:
        raise ValueError("Modular inverse does not exist.")

    return x % p

def is_prime(number):

    if number < 2:
        return False

    for i in range(2, int(number ** 0.5) + 1):

        if number % i == 0:
            return False

    return True

def is_primitive_root(g, p):

    values = set()

    for power in range(1, p):

        value = pow(g, power, p)

        values.add(value)

    return len(values) == (p - 1)

def generate_keys(p=467, g=2):

    if not is_prime(p):
        raise ValueError("p must be prime.")

    if not is_primitive_root(g, p):
        raise ValueError("g must be a primitive root modulo p.")

    private_key = random.randint(2, p - 2)

    public_key = pow(g, private_key, p)

    return public_key, private_key

def encrypt(message, p, g, public_key):

    encrypted_message = []

    for character in message:

        message_value = ord(character) % p

        k = random.randint(2, p - 2)

        c1 = pow(g, k, p)

        shared_secret = pow(public_key, k, p)

        c2 = (message_value * shared_secret) % 128

        encrypted_message.append((c1, c2))

    return encrypted_message

def decrypt(encrypted_message, private_key, p):

    decrypted_message = ""

    for c1, c2 in encrypted_message:

        shared_secret = pow(c1, private_key, p)

        inverse_secret = modular_inverse(shared_secret, p)

        message_value = (c2 * inverse_secret) % p

        decrypted_message += chr(message_value % 128)

    return decrypted_message

if __name__ == "__main__":

    message = input("Enter message to encrypt with El Gamal: ")

    public_key, private_key = generate_keys()

    encrypted_message = encrypt(message, p, g, public_key)

    decrypted_message = decrypt(
        encrypted_message,
        private_key,
        p
    )

    print("\nEncrypted message:")
    print(encrypted_message)

    print("\nDecrypted message:")
    print(decrypted_message)
