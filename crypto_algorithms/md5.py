def left_rotate(value, shift):
    value = value & 0xFFFFFFFF
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def to_bytes(message):

    if isinstance(message, bytes):
        return message
    return str(message).encode("utf-8")


def pad_message(message_bytes):
    original_length_bits = len(message_bytes) * 8

    padded = bytearray(message_bytes)

    padded.append(0x80)

    while (len(padded) % 64) != 56:
        padded.append(0)

    for i in range(8):
        padded.append((original_length_bits >> (8 * i)) & 0xFF)

    return padded


def bytes_to_32bit_words(block):
    words = []

    for i in range(0, 64, 4):
        word = (
            block[i]
            | (block[i + 1] << 8)
            | (block[i + 2] << 16)
            | (block[i + 3] << 24)
        )
        words.append(word)

    return words


def int_to_little_endian_hex(value):
    result = ""

    for i in range(4):
        byte = (value >> (8 * i)) & 0xFF
        result += format(byte, "02x")

    return result


def md5(message):
    shifts = [
        7, 12, 17, 22,
        7, 12, 17, 22,
        7, 12, 17, 22,
        7, 12, 17, 22,

        5, 9, 14, 20,
        5, 9, 14, 20,
        5, 9, 14, 20,
        5, 9, 14, 20,

        4, 11, 16, 23,
        4, 11, 16, 23,
        4, 11, 16, 23,
        4, 11, 16, 23,

        6, 10, 15, 21,
        6, 10, 15, 21,
        6, 10, 15, 21,
        6, 10, 15, 21,
    ]

    constants = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ]

    a0 = 0x67452301
    b0 = 0xefcdab89
    c0 = 0x98badcfe
    d0 = 0x10325476

    message_bytes = to_bytes(message)
    padded_message = pad_message(message_bytes)

    for block_start in range(0, len(padded_message), 64):
        block = padded_message[block_start:block_start + 64]
        words = bytes_to_32bit_words(block)

        A = a0
        B = b0
        C = c0
        D = d0

        for i in range(64):
            if 0 <= i <= 15:
                F = (B & C) | ((~B) & D)
                g = i
            elif 16 <= i <= 31:
                F = (D & B) | ((~D) & C)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                F = C ^ (B | (~D))
                g = (7 * i) % 16

            F = F & 0xFFFFFFFF

            temp = D
            D = C
            C = B

            rotated = left_rotate(
                (A + F + constants[i] + words[g]) & 0xFFFFFFFF,
                shifts[i]
            )

            B = (B + rotated) & 0xFFFFFFFF
            A = temp

        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF

    digest = (
        int_to_little_endian_hex(a0)
        + int_to_little_endian_hex(b0)
        + int_to_little_endian_hex(c0)
        + int_to_little_endian_hex(d0)
    )

    return digest


if __name__ == "__main__":
    user_text = input("Enter text to hash with MD5: ")
    hashed_text = md5(user_text)

    print("MD5 hash:")
    print(hashed_text)