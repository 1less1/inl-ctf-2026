import struct

from sha1 import sha1
from sha1 import sha1_continue
from sha1 import sha1_padding


# ---------------------------------------------------------
# Known Lucian example
# ---------------------------------------------------------

key = b"changing_secret_key!"
original = b"super secret message"
extension = b";gallade;"

original_mac = "013fa8d0c73faacb43f09d6e1a29ec6f93d1159d"


# ---------------------------------------------------------
# What the attacker knows
# ---------------------------------------------------------

# In the real challenge, we don't know the key.
# We only know that it is 20 bytes long.
key_length = 20


# The original SHA-1 input was:
#
#     key || original
#
# 20 + 20 = 40 bytes.
original_length = key_length + len(original)

print("Original length:")
print(original_length)


# ---------------------------------------------------------
# Reconstruct the padding SHA-1 used
# ---------------------------------------------------------

padding = sha1_padding(original_length)

print()
print("SHA-1 padding:")
print(padding.hex())

print()
print("Padding length:")
print(len(padding))


# ---------------------------------------------------------
# Recover SHA-1's internal state from the known digest
# ---------------------------------------------------------

state = struct.unpack(
    ">5I",
    bytes.fromhex(original_mac)
)

print()
print("Recovered state:")

for value in state:
    print(f"{value:08x}")


# ---------------------------------------------------------
# Continue SHA-1 from that state
# ---------------------------------------------------------

# The original message plus its padding was processed
# before SHA-1 produced original_mac.
bytes_already_processed = original_length + len(padding)

forged_mac = sha1_continue(
    extension,
    state,
    bytes_already_processed,
)


# ---------------------------------------------------------
# Construct the forged message
# ---------------------------------------------------------

# An attacker can construct this because they know:
#
#   original message
#   key length
#   SHA-1 padding rules
#   desired extension
#
# They do NOT need to know the key.
forged_message = original + padding + extension

print()
print("Forged message:")
print(forged_message)

print()
print("Forged message hex:")
print(forged_message.hex())

print()
print("Forged MAC:")
print(forged_mac)


# ---------------------------------------------------------
# Verify the attack
#
# The attacker does NOT have the key.
#
# We are using it here ONLY to prove that our
# length-extension implementation is correct.
# ---------------------------------------------------------

direct_mac = sha1(
    key + forged_message
)

print()
print("Direct MAC:")
print(direct_mac)

print()
print("MATCH:")
print(forged_mac == direct_mac)