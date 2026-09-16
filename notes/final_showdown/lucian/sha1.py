import struct


MASK32 = 0xffffffff

INITIAL_STATE = (
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
    0xc3d2e1f0,
)


def left_rotate(value, bits):
    return ((value << bits) | (value >> (32 - bits))) & MASK32


def pad(message):
    """
    Apply standard SHA-1 padding to a complete message.
    """

    message_length = len(message)

    padded = message + b"\x80"

    while (len(padded) + 8) % 64 != 0:
        padded += b"\x00"

    padded += struct.pack(">Q", message_length * 8)

    return padded


def sha1_padding(message_length):
    """
    Return only the SHA-1 padding for a message of
    message_length bytes.
    """

    padding = b"\x80"

    while (message_length + len(padding) + 8) % 64 != 0:
        padding += b"\x00"

    padding += struct.pack(">Q", message_length * 8)

    return padding


def f(t, b, c, d):
    if t < 20:
        return (b & c) | ((~b) & d)

    if t < 40:
        return b ^ c ^ d

    if t < 60:
        return (b & c) | (b & d) | (c & d)

    return b ^ c ^ d


def k(t):
    if t < 20:
        return 0x5A827999

    if t < 40:
        return 0x6ED9EBA1

    if t < 60:
        return 0x8F1BBCDC

    return 0xCA62C1D6


def process_block(block, state):
    """
    Process one 64-byte SHA-1 block.

    state is a tuple containing the five 32-bit SHA-1 state words.
    """

    assert len(block) == 64

    h0, h1, h2, h3, h4 = state

    # Convert 64 bytes into 16 big-endian 32-bit words.
    w = list(struct.unpack(">16I", block))

    # Expand 16 words into 80 words.
    for i in range(16, 80):
        value = (
            w[i - 3]
            ^ w[i - 8]
            ^ w[i - 14]
            ^ w[i - 16]
        )

        w.append(left_rotate(value, 1))

    # Initialize working variables.
    a, b, c, d, e = h0, h1, h2, h3, h4

    # SHA-1's 80 compression rounds.
    for t in range(80):
        temp = (
            left_rotate(a, 5)
            + f(t, b, c, d)
            + e
            + k(t)
            + w[t]
        ) & MASK32

        e = d
        d = c
        c = left_rotate(b, 30)
        b = a
        a = temp

    # Feed the working variables back into the state.
    h0 = (h0 + a) & MASK32
    h1 = (h1 + b) & MASK32
    h2 = (h2 + c) & MASK32
    h3 = (h3 + d) & MASK32
    h4 = (h4 + e) & MASK32

    return h0, h1, h2, h3, h4


def sha1(message):
    """
    Calculate SHA-1 from the standard initial state.
    """

    message = pad(message)

    state = INITIAL_STATE

    for offset in range(0, len(message), 64):
        block = message[offset:offset + 64]

        state = process_block(block, state)

    return struct.pack(">5I", *state).hex()


def sha1_continue(data, state, bytes_already_processed):
    """
    Continue SHA-1 from an existing internal state.

    `state` is the five 32-bit words recovered from a previous
    SHA-1 digest.

    `bytes_already_processed` is the number of bytes that SHA-1
    has already processed before `data`.
    """

    total_length = bytes_already_processed + len(data)

    # Generate the final SHA-1 padding based on the complete
    # message length, including everything processed previously.
    padding = sha1_padding(total_length)

    padded = data + padding

    for offset in range(0, len(padded), 64):
        block = padded[offset:offset + 64]

        state = process_block(block, state)

    return struct.pack(">5I", *state).hex()


if __name__ == "__main__":
    # Standard SHA-1 test vectors.
    tests = {
        b"": "da39a3ee5e6b4b0d3255bfef95601890afd80709",

        b"abc":
            "a9993e364706816aba3e25717850c26c9cd0d89d",

        b"hello world":
            "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
    }

    for message, expected in tests.items():
        actual = sha1(message)

        print(f"{message!r}")
        print(f"actual:   {actual}")
        print(f"expected: {expected}")
        print(f"match:    {actual == expected}")
        print()

    # Lucian's example from the README.
    key = b"changing_secret_key!"
    message = b"super secret message"

    mac = sha1(key + message)

    print("Lucian test:")
    print(mac)

    # Show the five internal SHA-1 state words represented
    # by Lucian's digest.
    state = struct.unpack(
        ">5I",
        bytes.fromhex(mac)
    )

    print(state)

    for value in state:
        print(f"{value:08x}")