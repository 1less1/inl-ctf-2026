### Basic Concepts

**Hash function**: SHA-1 takes any data and produces a fixed 160-bit (20-byte) fingerprint called a digest.

**Block processing**: SHA-1 processes data in 64-byte chunks, carrying an internal 160-bit state from one chunk to the next.

**Secret-prefix MAC**: Lucian authenticates with SHA1(key || message). Because the secret is placed before the message, this construction is vulnerable to length-extension attacks.

**Length extension**: The SHA-1 digest reveals the final internal state, allowing us to continue hashing new data without knowing the original key.

**Padding + known key length**: SHA-1 adds padding based on the total message length. Since we know Lucian's key is exactly 20 bytes, we can calculate the padding he used and correctly continue the hash.

**Cryptopals Set 4 Challenge 29 teaches essentially this exact attack**: take SHA1(secret || message), use the known digest and key length, append new data, and create a valid forged MAC without knowing the secret.




Solved the Lucian challenge with these steps:

### Contextual Information
Read text within challenge ``README``:
```
PS C:\Users\coreadmin\Downloads\LUCIANBOSS\lucian_veilstone_challenge> get-content .\lucian_veilstone_readme.txt
```

Content:
```
Lucian Veilstone wants to test our your psychic cryptography capabilities before providing you his flag.

Lucian is using a SHA-1 secret-prefix HMAC for authentication SHA-1(key + message).

For instance, if his key was "\x63\x68\x61\x6e\x67\x69\x6e\x67\x5f\x73\x65\x63\x72\x65\x74\x5f\x6b\x65\x79\x21" (changing_secret_key!) and message was "super secret message", the SHA-1 HMAC would be:
SHA-1("changing_secret_key!super secret message") = 013fa8d0c73faacb43f09d6e1a29ec6f93d1159d

Lucian is constantly changing his key, but luckily all of his keys are always 20 characters/bytes long.

Lucian's messages are always "mr.mime;espeon;bronzong;alakazam;", but he would like you to break his SHA-1 HMAC by sending him a new/forged message and HMAC without knowing the key.

Lucian requires the forged message you send him to contain both the original message "mr.mime;espeon;bronzong;alakazam;" and a new string ";gallade;".

If you reach out to Lucian at "challenges.icsjwgctf.com:9003" and provide him the password "crypto_psychic", he will give you his message and resulting HMAC and then ask you for your new/forged message. If your message contains the correct strings and the HMAC is verified against his key, he will provide you his secret key.

Good luck!
```

Made an inital connection to the server over port ``9003``:
```
PS C:\Users\coreadmin\Downloads\LUCIANBOSS\lucian_veilstone_challenge> python -c "import socket; s=socket.create_connection(('192.168.100.5',9003)); print(s.recv(1024)); s.sendall(b'crypto_psychic\n'); print(s.recv(4096))"
```

Output:
```
b"\nPlease enter Lucian Veilstone's password to access this challenge: "
b"Lucian's Message:  mr.mime;espeon;bronzong;alakazam;\nLucian's HMAC:     a1f2168969d9db59d80cd65974d0bfc31ebada5a\nForged Message:   "
```

---

### 1. Identify the MAC construction
The challenge told us Lucian was using:
```text
SHA-1(key || message)
```
with a **20-byte secret key**.

That's vulnerable to a **SHA-1 length-extension attack**.

```MAC``` = Message Authentication Code.

Basically, it's a value generated from a ```secret key + message``` that lets someone verify:  

    "This message was created by someone who knows the secret key, and it hasn't been modified."

For this challenge, the server uses: 
```text
MAC = SHA-1(secret_key || message)
```

NOTE: **The problem is that this is a secret-prefix MAC, rather than a proper HMAC construction, which makes it vulnerable to the length-extension attack.**

---

### 2. Recognize the intended attack
The challenge hint pointed to Cryptopals Set 4, Challenge 29 - via CTF admins!!!

The key idea was:
> Given `SHA1(key || message)`, you can calculate a valid MAC for `key || message || padding || extension` without knowing `key`.

We therefore wanted to append:
```text
;gallade;
```
to Lucian's message.

---

### 3. Build and verify own SHA-1 implementation

Rather than treating SHA-1 as a black box, implement it locally.

Verified it against standard SHA-1 test vectors and the challenge's known example.

This was important because the length-extension attack requires access to SHA-1's **internal state**, which is represented by the ``five 32-bit words`` contained in the final digest.

SHA-1 begins with **five fixed initial state constants**:
```
h0 = 67452301
h1 = EFCDAB89
h2 = 98BADCFE
h3 = 10325476
h4 = C3D2E1F0
```

As SHA-1 processes the message, these five values are repeatedly updated. The final values are concatenated to form the ``160-bit SHA-1 digest``.

This is important for the length-extension attack because the server's ``SHA-1 MAC`` gives us those final state values, allowing us to use them as the starting state for continuing the SHA-1 computation.

---

### 4. Calculate the original message length

The challenge gave:

```text
Key length     = 20 bytes
Message length = 33 bytes
```

Therefore:
```text
20 + 33 = 53 bytes
```
of secret-prefix input had been processed.

Calculated the ``SHA-1 padding ``for those **53 bytes**:
```text
80 00 00 00 00 00 00 00 00 01 a8
```

That's **11 bytes**, bringing the total to exactly:
```text
53 + 11 = 64 bytes
```
or **one complete SHA-1 block**.

---

### 5. Recover the SHA-1 internal state

The server gave a MAC such as:
```text
ca32c3d5761738ab7b7ba227ec0ca9330b906f64
```

A SHA-1 digest is 160 bits, or 40 hexadecimal characters. Split the digest into ``five 32-bit words``:
```
h0 = CA32C3D5
h1 = 761738AB
h2 = 7B7BA227
h3 = EC0CA933
h4 = 0B906F64
```

Those became the starting state for our SHA-1 continuation.

---

### 6. Continue SHA-1 with our extension

Then continued SHA-1 from that recovered state with:
```text
;gallade;
```

This produced a new ``MAC``:
```text
7d84088f6d2038291f454e054e9a0366d05ab062
```

Never knew the secret key!!!

---

### 7. Construct the forged message

The message we submitted wasn't simply:
```text
original + ";gallade;"
```

It was:
```text
original
+ SHA-1 padding for key || original
+ ";gallade;"
```

Conceptually:
```text
mr.mime;espeon;bronzong;alakazam;
        ↓
SHA-1 padding
        ↓
;gallade;
```

The padding had to be sent as **actual binary bytes**, not as the text `"800000..."`.

---

### 8. Send the forgery to the server

Local script:
1. Connected to `192.168.100.5:9003`
2. Supplied `crypto_psychic`
3. Retrieved the fresh message and HMAC
4. Calculated the forged MAC
5. Sent the binary forged message
6. Sent the forged HMAC

The server verified:
```text
SHA1(secret_key || forged_message)
    ==
our forged HMAC
```
and accepted it.

---

### 9. Receive the secret key

The server responded:
```text
Congratulations! You have completed Lucian Veilstone's challenge.

Lucian's Secret Key is:
af62d91e0556d06805b255a9a005d668d0a655a6
```

### The entire attack in one picture

```text
SERVER GIVES US
      │
      ├── original message
      │      "mr.mime;espeon;bronzong;alakazam;"
      │
      └── SHA1(key || message)
               │
               ▼
       Recover SHA-1 state
               │
               ▼
      Calculate SHA-1 padding
               │
               ▼
       Continue SHA-1 with
          ";gallade;"
               │
               ▼
        FORGED MAC
               │
               ▼
   Submit:
   original || padding || ";gallade;"
   +
   forged MAC
               │
               ▼
          SERVER ACCEPTS
               │
               ▼
          SECRET KEY
```

### Core Lesson
The core lesson is that **a secret-prefix SHA-1 MAC leaks enough information through its digest to let an attacker continue hashing after the original message**. That's precisely why real HMAC construction exists instead of simply doing `SHA1(key || message)`.
