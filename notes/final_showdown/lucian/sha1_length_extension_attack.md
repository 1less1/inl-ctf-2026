What we just demonstrated

The legitimate MAC is:
```
SHA1(
    changing_secret_key!
    ||
    super secret message
)
= 013fa8d0c73faacb43f09d6e1a29ec6f93d1159d
```

We then took only:
```
original message
original MAC
key length = 20
```

and produced:
```
super secret message
+
SHA-1 padding
+
;gallade;
```

with:
```
047dfef3bb04ee0d1d8b77ec6864d12df60df556
```

And independently calculated:

```
SHA1(
    actual secret key
    ||
    forged message
)
```

which produced the same MAC.

So:
```
length-extension MAC == direct MAC
```

is True.

That is the vulnerability.