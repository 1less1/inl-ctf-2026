import re
import socket
import struct

from sha1 import sha1_continue
from sha1 import sha1_padding


HOST = "192.168.100.5"
PORT = 9003

PASSWORD = b"crypto_psychic\n"

KEY_LENGTH = 20
ORIGINAL_MESSAGE = b"mr.mime;espeon;bronzong;alakazam;"
EXTENSION = b";gallade;"


def recv_until(sock, marker):
    """Receive data until marker appears."""
    data = b""

    while marker not in data:
        chunk = sock.recv(4096)

        if not chunk:
            break

        data += chunk

    return data


def parse_hmac(data):
    """Extract Lucian's 40-character SHA-1 HMAC from server output."""
    match = re.search(
        rb"Lucian's HMAC:\s*([0-9a-fA-F]{40})",
        data,
    )

    if not match:
        raise ValueError(
            "Could not find Lucian's HMAC in server response."
        )

    return match.group(1).decode().lower()


def build_forgery(original_mac):
    """
    Perform the SHA-1 length-extension attack.

    Original secret-prefix input:

        key || original_message

    We know:
        len(key) = 20
        len(original_message) = 33

    Therefore:
        len(key || original_message) = 53

    SHA-1 pads that to exactly one 64-byte block.

    The forged message becomes:

        original_message
        || original SHA-1 padding
        || extension
    """

    original_length = KEY_LENGTH + len(ORIGINAL_MESSAGE)

    # Padding that SHA-1 would have appended to:
    #
    #     key || ORIGINAL_MESSAGE
    #
    original_padding = sha1_padding(original_length)

    # The observed SHA-1 digest is the internal SHA-1 state
    # after processing key || ORIGINAL_MESSAGE || padding.
    state = struct.unpack(
        ">5I",
        bytes.fromhex(original_mac),
    )

    bytes_already_processed = (
        original_length
        + len(original_padding)
    )

    # Continue SHA-1 from the recovered internal state.
    #
    # sha1_continue() adds the final padding for:
    #
    #     key || ORIGINAL_MESSAGE || original_padding || EXTENSION
    #
    forged_mac = sha1_continue(
        EXTENSION,
        state,
        bytes_already_processed,
    )

    # What we submit as the forged message does NOT include
    # the unknown key, but DOES include the padding that would
    # have appeared after the original message.
    forged_message = (
        ORIGINAL_MESSAGE
        + original_padding
        + EXTENSION
    )

    return forged_message, forged_mac


def main():
    print(f"[*] Connecting to {HOST}:{PORT}...")

    with socket.create_connection((HOST, PORT)) as sock:

        # ---------------------------------------------------------
        # 1. Receive password prompt
        # ---------------------------------------------------------

        response = recv_until(
            sock,
            b"password",
        )

        print("\n[SERVER]")
        print(response.decode(errors="replace"))

        # ---------------------------------------------------------
        # 2. Send password
        # ---------------------------------------------------------

        print("[*] Sending password...")

        sock.sendall(PASSWORD)

        # ---------------------------------------------------------
        # 3. Receive Lucian's message + HMAC
        # ---------------------------------------------------------

        response = recv_until(
            sock,
            b"Forged Message:",
        )

        print("\n[SERVER]")
        print(response.decode(errors="replace"))

        # ---------------------------------------------------------
        # 4. Extract HMAC
        # ---------------------------------------------------------

        original_mac = parse_hmac(response)

        print(f"[*] Original HMAC: {original_mac}")

        # ---------------------------------------------------------
        # 5. Build length-extension forgery
        # ---------------------------------------------------------

        forged_message, forged_mac = build_forgery(
            original_mac
        )

        print("\n[*] Forgery details")
        print(f"    Key length:       {KEY_LENGTH}")
        print(f"    Original length:  {len(ORIGINAL_MESSAGE)}")
        print(f"    Extension length: {len(EXTENSION)}")
        print(
            f"    Original padding: "
            f"{len(forged_message) - len(ORIGINAL_MESSAGE) - len(EXTENSION)} bytes"
        )
        print(f"    Forged message:   {forged_message!r}")
        print(f"    Forged hex:       {forged_message.hex()}")
        print(f"    Forged length:    {len(forged_message)} bytes")
        print(f"    Forged HMAC:      {forged_mac}")

        # ---------------------------------------------------------
        # 6. Send forged message
        # ---------------------------------------------------------
        #
        # IMPORTANT:
        #
        # forged_message contains binary SHA-1 padding:
        #
        #     80 00 00 ... 01 a8
        #
        # Therefore we must send it as raw bytes.
        #
        # Do NOT:
        #
        #     forged_message.decode(...)
        #
        # and do NOT hex-encode it.
        #
        # The newline after the message is the protocol delimiter.
        # ---------------------------------------------------------

        print("\n[*] Sending forged message...")

        sock.sendall(forged_message)
        sock.sendall(b"\n")

        # ---------------------------------------------------------
        # 7. Send forged MAC
        # ---------------------------------------------------------

        print("[*] Sending forged HMAC...")

        sock.sendall(forged_mac.encode("ascii"))
        sock.sendall(b"\n")

        # ---------------------------------------------------------
        # 8. Read server result
        # ---------------------------------------------------------

        print("\n[*] Waiting for server response...")

        response = b""

        while True:
            chunk = sock.recv(4096)

            if not chunk:
                break

            response += chunk

            print("\n[SERVER CHUNK]")
            print(repr(chunk))
            print(chunk.decode(errors="replace"))

            if b"Goodbye" in response or b"Congratulations" in response:
                break


if __name__ == "__main__":
    main()