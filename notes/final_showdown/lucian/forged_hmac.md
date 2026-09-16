Now apply it to Lucian

We know from the challenge:
```
key length = 20
```
and the original message is:
```
mr.mime;espeon;bronzong;alakazam;
```
Let's verify the length ourselves:
```
python -c "print(len(b'mr.mime;espeon;bronzong;alakazam;'))"
```
We expect:
```
33
```
Therefore:
```
20 + 33 = 53
```
And we've already established the original padding:
```
80000000000000000001a8
```
which is **11** bytes.

So Lucian's SHA-1 state was produced after exactly:
```
53 + 11 = 64 bytes
```
That's especially convenient:
```
┌────────────────────────────────────────────────────────┐
│ key (20) │ original message (33) │ padding (11)       │
└────────────────────────────────────────────────────────┘
                         64 bytes
                         1 block
```
The server gives us the resulting digest.

We turn that digest into:
```
H0
H1
H2
H3
H4
```
and start our SHA-1 implementation from that state.

Then we feed it:
```
;gallade;
```
Our continuation function automatically adds the final padding based on the total length:
```
64 bytes already processed
+
9 byte extension
=
73 bytes
```
So the continuation processes one final 64-byte block:
```
9 bytes ;gallade;
+
55 bytes final padding
=
64 bytes
```
**The resulting digest is the forged MAC.**