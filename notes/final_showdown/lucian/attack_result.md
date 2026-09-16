Used the ``attack.py`` file:
```
PS C:\Users\coreadmin\Downloads\LUCIANBOSS\lucian_veilstone_challenge> python .\attack.py
```

Output:
```
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



🎉 **You got it!**

The length-extension attack worked against the live challenge server.

Your successful run was:

```text
Original HMAC:
ca32c3d5761738ab7b7ba227ec0ca9330b906f64

Forged HMAC:
7d84088f6d2038291f454e054e9a0366d05ab062
```

The server accepted:

```text
mr.mime;espeon;bronzong;alakazam;
\x80\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa8
;gallade;
```

and returned:

```text
Congratulations! You have completed Lucian Veilstone's challenge.

Lucian's Secret Key is:
af62d91e0556d06805b255a9a005d668d0a655a6
```

### What we demonstrated

You successfully exploited the fact that the challenge uses:

```text
SHA1(key || message)
```

instead of a proper HMAC construction.

You **didn't need to know the 20-byte secret key**. From the original MAC, you treated the five 32-bit SHA-1 digest words as the internal SHA-1 state and continued hashing:

```text
key
  ||
mr.mime;espeon;bronzong;alakazam;
  ||
SHA-1 padding
  ||
;gallade;
```

The crucial part was realizing that the original:

```text
20-byte key + 33-byte message = 53 bytes
```

gets padded to exactly **64 bytes**, allowing us to resume SHA-1 from the leaked digest.

So the final attack was:

```text
Original:
K || "mr.mime;espeon;bronzong;alakazam;"

Forged:
"mr.mime;espeon;bronzong;alakazam;"
|| SHA1_padding(53)
|| ";gallade;"
```

with the forged MAC calculated without ever knowing `K`.

**Challenge solved.** 🏆
