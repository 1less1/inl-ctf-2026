Tested the ``length_extension_test.py`` script: 
```
python .\length_extension_test.py
```

Output:
```
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

### Local Length-Extension Test

**Original length:**
```text
40 bytes
```

This was:
```text
20-byte key + 20-byte message = 40 bytes
```

**SHA-1 padding:**
```text
800000000000000000000000000000000000000000000140
```

The padding was **24 bytes**, bringing the input to exactly one 64-byte SHA-1 block.
**Recovered state:**
```text
h0 = 013fa8d0
h1 = c73faacb
h2 = 43f09d6e
h3 = 1a29ec6f
h4 = 93d1159d
```

These five values came from the original SHA-1 digest and were used as the starting state for continuing SHA-1.
**Forged message:**
```text
original message
+ SHA-1 padding
+ ";gallade;"
```

We then calculated a **Forged MAC** using the recovered state:
```text
047dfef3bb04ee0d1d8b77ec6864d12df60df556
```

Finally, we calculated the MAC normally using the **actual secret key** as a verification step:
```text
Direct MAC:
047dfef3bb04ee0d1d8b77ec6864d12df60df556
```

Since:
```text
Forged MAC == Direct MAC
```
the result was:
```text
MATCH: True
```

**This proved that our length-extension attack worked correctly.**
Then we measured Lucian's actual message:
```text
len("mr.mime;espeon;bronzong;alakazam;") = 33 bytes
```

which we combined with the known 20-byte key length:
```text
20 + 33 = 53 bytes
```

That gave us the values needed for the real server attack.

