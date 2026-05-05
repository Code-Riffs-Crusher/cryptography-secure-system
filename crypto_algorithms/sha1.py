def left_rotate(value, shift):
    """
    Rotate a 32-bit integer value to the left by shift bits.
    SHA-1 requires 32-bit circular left rotation.
    """
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def sha1(message):
    """
    Pure Python SHA-1 hashing function written from scratch.

    No hashlib or external libraries are used.

    Input:
        message: string or bytes

    Output:
        40-character hexadecimal SHA-1 hash
    """

    # Convert string input into bytes manually using UTF-8 encoding.
    # This is not a hashing library; it only converts text to bytes.
    if isinstance(message, str):
        message = message.encode("utf-8")

    # Make a copy so the original message is not changed.
    message = bytearray(message)

    # Step 1: Save original message length in bits.
    original_bit_length = len(message) * 8

    # Step 2: Add the bit '1' to the message.
    # In byte form, 10000000 is 0x80.
    message.append(0x80)

    # Step 3: Add zero bytes until message length is 56 mod 64.
    # SHA-1 works on 512-bit blocks, which are 64 bytes.
    # The last 8 bytes are saved for the original length.
    while (len(message) % 64) != 56:
        message.append(0)

    # Step 4: Append the original length as a 64-bit big-endian integer.
    for shift in range(56, -1, -8):
        message.append((original_bit_length >> shift) & 0xFF)

    # Step 5: Initialize SHA-1 hash values.
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Step 6: Process the message in 512-bit blocks.
    for block_start in range(0, len(message), 64):
        block = message[block_start:block_start + 64]

        # Break block into sixteen 32-bit big-endian words.
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

        # Extend the sixteen words into eighty 32-bit words.
        for i in range(16, 80):
            word = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]
            words.append(left_rotate(word, 1))

        # Initialize working variables for this block.
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Step 7: Main SHA-1 compression loop.
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

        # Step 8: Add this block's result to the current hash value.
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    # Step 9: Return final hash as 40-character hexadecimal string.
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