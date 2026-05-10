import random
from crypto_algorithms.elgamal import modular_inverse

def validate_curve(p, a, b):
    return (4 * a**3 + 27 * b**2) % p != 0

def init_curve(p=233, a=1, b=1):

    if not validate_curve(p, a, b):
        raise ValueError("Invalid ECC curve parameters")

    return p, a, b

O = "O"

def is_on_curve(P, p, a, b):

    if P == O:
        return True

    x, y = P
    return (y*y - (x**3 + a*x + b)) % p == 0

def point_add(P, Q, p, a):

    if P == O:
        return Q
    if Q == O:
        return P

    x1, y1 = P
    x2, y2 = Q

    # Case: P + (-P) = O
    if x1 == x2 and (y1 + y2) % p == 0:
        return O

    # Case: Point doubling
    if P == Q:

        if y1 == 0:
            return O

        m = ((3 * x1 * x1 + a) * modular_inverse(2 * y1, p)) % p

    else:

        if x1 == x2:
            return O  # vertical line

        m = ((y2 - y1) * modular_inverse(x2 - x1, p)) % p

    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)

def scalar_mult(k, P, p, a):

    result = O
    addend = P

    while k > 0:

        if k % 2 == 1:
            result = point_add(result, addend, p, a)

        addend = point_add(addend, addend, p, a)

        k //= 2

    return result

def find_valid_point(p, a, b):

    for x in range(p):
        for y in range(p):

            if (y*y - (x**3 + a*x + b)) % p == 0:
                return (x, y)

    raise ValueError("No valid point found")


def generate_keys(G, p, a, b):

    if not is_on_curve(G, p, a, b):
        raise ValueError("Base point G is not on the curve")

    private_key = random.randint(2, p - 1)
    public_key = scalar_mult(private_key, G, p, a)

    return private_key, public_key

def encode_message(message):
    return [ord(c) for c in message]

def decode_message(numbers):
    return "".join(chr(n % 128) for n in numbers)

def encrypt(message, G, public_key, p, a):

    encoded = encode_message(message)
    ciphertext = []

    for m in encoded:

        k = random.randint(2, p - 1)

        C1 = scalar_mult(k, G, p, a)
        
        shared = scalar_mult(k, public_key, p, a)

        if shared == O:
            sx = 0
        else:
            sx = shared[0]

        C2 = (m + sx) % p

        ciphertext.append((C1, C2))

    return ciphertext

def decrypt(ciphertext, private_key, p, a):

    message_numbers = []

    for C1, C2 in ciphertext:

        shared = scalar_mult(private_key, C1, p, a)

        if shared == O:
            sx = 0
        else:
            sx = shared[0]

        m = (C2 - sx) % p

        message_numbers.append(m)

    return decode_message(message_numbers)


if __name__ == "__main__":

    p, a, b = init_curve()

    G = find_valid_point(p, a, b)

    if not is_on_curve(G, p, a, b):
        raise ValueError("G is not on curve")

    private_key, public_key = generate_keys(G, p, a, b)

    message = input("Enter message to encrypt with ECC: ")

    encrypted = encrypt(message, G, public_key, p, a)
    decrypted = decrypt(encrypted, private_key, p, a)

    print("\nEncrypted message:")
    print(encrypted)

    print("\nDecrypted message:")
    print(decrypted)

