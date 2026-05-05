def left_rotate(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def sha1(message):
    if isinstance(message, str):
        message = message.encode("utf-8")

    message = bytearray(message)

    original_bit_length = len(message) * 8

    message.append(0x80)

    while (len(message) % 64) != 56:
        message.append(0)

    for shift in range(56, -1, -8):
        message.append((original_bit_length >> shift) & 0xFF)

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    for block_start in range(0, len(message), 64):
        block = message[block_start:block_start + 64]

        words = []

        for i in range(16):
            j = i * 4
            word = (
                (block[j] << 24)
                | (block[j + 1] << 16)
                | (block[j + 2] << 8)
                | block[j + 3]
            )
            words.append(word)

        for i in range(16, 80):
            word = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]
            words.append(left_rotate(word, 1))

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + words[i]) & 0xFFFFFFFF

            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    return (
        format(h0, "08x")
        + format(h1, "08x")
        + format(h2, "08x")
        + format(h3, "08x")
        + format(h4, "08x")
    )


if __name__ == "__main__":
    user_input = input("Enter text to hash with SHA-1: ")
    hashed_value = sha1(user_input)

    print("SHA-1 Hash:")
    print(hashed_value)