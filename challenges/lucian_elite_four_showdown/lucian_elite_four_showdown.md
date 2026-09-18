[Home](../../README.md) | [Challenges](../../challenges/challenges.md) | [Tools](../../tools/tools.md) 
# Elite Four Showdown: Lucian Veilstone

## Scenario
The CTF presented an overarching boss challenge called **Elite Four Showdown**. The goal is to unlock a listening TCP service at `192.168.100.5:9004` which requires four specific submission strings from different CEOs. The required format is `$CEO_NAME's Secret Key is: $SECRET_KEY`. Using the starter archive password `dce1a3126f787599bf7decdbfc1e61bcdd6c3a71` harvested from the Veilstone track, retrieve Lucian Veilstone's secret key.

## Timeline and Incident Response
Triage began by reading the challenge text within `lucian_veilstone_readme.txt`:
```shell
PS C:\Users\coreadmin\Downloads\LUCIANBOSS\lucian_veilstone_challenge> get-content .\lucian_veilstone_readme.txt
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

---

### Finding
Initial server password = `crypto_psychic`

---

An initial connection to the server over `port 9003` was established using the password: `crypto_psychic`.
```shell
PS C:\Users\coreadmin\Downloads\LUCIANBOSS\lucian_veilstone_challenge> python -c "import socket; s=socket.create_connection(('192.168.100.5',9003)); print(s.recv(1024)); s.sendall(b'crypto_psychic\n'); print(s.recv(4096))"
b"\nPlease enter Lucian Veilstone's password to access this challenge: "
b"Lucian's Message:  mr.mime;espeon;bronzong;alakazam;\nLucian's HMAC:     a1f2168969d9db59d80cd65974d0bfc31ebada5a\nForged Message:   "
```

---

### Finding
The challenge instructions indicated Lucian was using a secret prefix `MAC` construction formatted as SHA-1(`key || message`) with a known 20 byte secret key. Because the secret is placed before the message, this construction is vulnerable to a `length extension attack`.

`MAC` = Message Authentication Code
`HMAC` = Keyed-Hash Message Authentication Code

The final SHA-1 digest reveals the algorithm's internal state (``five 32 bit words``), allowing an attacker to continue hashing new data and forge a valid MAC without knowing the original key.   

---

To manipulate the internal state, a custom SHA-1 implementation was created in [`sha1.py`](./sha1.py) to allow resuming the hash computation from an existing state. A local proof of concept, [`length_extension_test.py`](./length_extension_test.py), was then developed to verify the math against the challenge's example data before attacking the live server.   
```shell
PS C:\Users\coreadmin\Downloads\LUCIANBOSS\lucian_veilstone_challenge> python .\length_extension_test.py
Original length:
40

SHA-1 padding:
800000000000000000000000000000000000000000000140

Padding length:
24

Recovered state:
013fa8d0
c73faacb
43f09d6e
1a29ec6f
93d1159d

Forged message:
b'super secret message\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01@;gallade;'

Forged message hex:
737570657220736563726574206d6573736167658000000000000000000000000000000000000000000001403b67616c6c6164653b

Forged MAC:
047dfef3bb04ee0d1d8b77ec6864d12df60df556

Direct MAC:
047dfef3bb04ee0d1d8b77ec6864d12df60df556

MATCH:
True
```

---

### Finding
The local test proved the `length extension attack` works. By extracting the internal state from a legitimate `MAC` and calculating the hidden padding, `;gallade;` was successfully appended to forge a new ``MAC`` that perfectly matched the real one.  

To attack the live server, the exact SHA-1 padding required was calculated first. The 20 byte secret key plus the 33 byte original message totaled 53 bytes. Adding 11 bytes of padding rounded this up perfectly to a complete 64 byte SHA-1 block.

1. `20 byte key + 33 byte message` = `53 bytes`
2. `SHA1` = `64 bytes`
3. `20 byte key + 33 byte message + 11 byte padding` = `64 bytes` (complete SHA-1 block)

---

Next, the server's MAC was split into five parts to recover its internal state. Using this as a starting point, the hash was resumed and the 9 byte extension (`;gallade;`) was injected. Because the original 64 byte block was already accounted for, the algorithm simply processed the extension, added the final padding, and output the forged `MAC`.

A local script, [`attack.py`](./attack.py), was created to automate the `length extension attack` against the server. The script connected to `192.168.100.5:9003`, authenticated with `crypto_psychic`, and retrieved a fresh message and `HMAC`. It then calculated the forged `MAC` and submitted the malicious payload.   

The required payload structure sent over the socket was the original message, followed by the binary SHA-1 padding (sent as raw bytes, not hex-encoded), followed by the `;gallade;` extension.
```shell
PS C:\Users\coreadmin\Downloads\LUCIANBOSS\lucian_veilstone_challenge> python .\attack.py
[*] Connecting to 192.168.100.5:9003...

[SERVER]

Please enter Lucian Veilstone's password to access this challenge: 
[*] Sending password...

[SERVER]
Lucian's Message:  mr.mime;espeon;bronzong;alakazam;
Lucian's HMAC:     ca32c3d5761738ab7b7ba227ec0ca9330b906f64
Forged Message:   
[*] Original HMAC: ca32c3d5761738ab7b7ba227ec0ca9330b906f64

[*] Forgery details
    Key length:       20
    Original length:  33
    Extension length: 9
    Original padding: 11 bytes
    Forged message:   b'mr.mime;espeon;bronzong;alakazam;\x80\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa8;gallade;'
    Forged hex:       6d722e6d696d653b657370656f6e3b62726f6e7a6f6e673b616c616b617a616d3b80000000000000000001a83b67616c6c6164653b
    Forged length:    53 bytes
    Forged HMAC:      7d84088f6d2038291f454e054e9a0366d05ab062

[*] Sending forged message...
[*] Sending forged HMAC...

[*] Waiting for server response...

[SERVER CHUNK]
b'Forged HMAC:      '
Forged HMAC:      

[SERVER CHUNK]
b"Congratulations! You have completed Lucian Veilstone's challenge.\n\nLucian's Secret Key is: af62d91e0556d06805b255a9a005d668d0a655a6\n\n\n"
Congratulations! You have completed Lucian Veilstone's challenge.

Lucian's Secret Key is: af62d91e0556d06805b255a9a005d668d0a655a6
```

---

### Finding
The server verified the forged MAC (`7d84088f6d2038291f454e054e9a0366d05ab062`) against the malicious payload and successfully returned the flag. By exploiting the secret prefix construction SHA1(`key || message`), a valid authentication tag was generated for the extended message without ever recovering or knowing the `20 byte secret key`.

---

## Solution/Summary
```
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

## SHA-1
`SHA-1 (Secure Hash Algorithm 1) `is a cryptographic tool that takes a message of any size and crushes it down into a fixed 40-character fingerprint, called a hash.

It works through a continuous process of `padding`, `chopping`, and `blending`:
1. **Padding:** SHA-1 adds extra filler data (a 1 and some 0s) to the end of your message, along with the original message length. This pads the data so it can be perfectly divided into 64 byte chunks.
2. **Initialization:** The algorithm sets up a starting "internal state" made of five fixed numbers.
3. **Chunking:** The padded message is sliced into those 64 byte blocks.
4. **Blending (Compression):** The first 64 byte block goes into a mathematical blender. It gets completely scrambled together with the five internal state numbers to create a brand new internal state.
5. **Chaining:** The algorithm grabs the next 64 byte block and scrambles it into this new internal state. This chain reaction repeats until every block is processed.
6. **Output:** Once the final block is done, the leftover five numbers are glued together to form the final hash.

**The Vulnerability:** Because the final hash is literally just the leftover internal state from the final block, an attacker can take a legitimate hash, add new data to it, and continue the math as if the original message never ended. This is how a `length extension attack` works.