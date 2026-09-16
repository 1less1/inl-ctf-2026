The password was ground.

Here is what was happening behind the scenes and why standard tools failed while the Python script succeeded:

1. Bypassing the Damaged ZIP Structure

Standard extraction tools (like 7-Zip or Windows Explorer) rely on the Central Directory at the end of the ZIP file to index files and verify their integrity.

The challenge author intentionally stripped or corrupted that footer (causing the Unexpected end of archive error), which made standard unpackers fail or write empty 0-byte dummy files.

The script bypassed the missing footer entirely by parsing the local file header at offset 0 (PK\x03\x04), grabbing the compressed payload directly from offset 30 + filename_length + extra_length.

2. Emulating the PKZIP Stream Cipher

Legacy ZIP encryption (ZipCrypto) is an internal stream cipher that maintains three 32-bit internal state keys: key0, key1, and key2.

For each password candidate, the script initialized the internal state (0x12345678, 0x23456789, 0x34567890) and updated it byte-by-byte using the password characters and CRC32 table transformations.

3. The 1-Byte Fast Filter (The Check Byte)

PKZIP prepends a 12-byte pseudo-random encryption header to the compressed stream.

Crucially, the 12th byte is always set by the archiver to the high byte of the file's CRC32 (or the high byte of the file's last modified timestamp when bit 3 is set).

Instead of decompressing the entire 24 KB payload for every bad password, the script only decrypted the first 12 bytes. If byte 12 didn't match the check byte, the password was discarded in microseconds.

4. Raw Deflate Inflation

When ground passed the 12-byte check, the script decrypted the remaining stream and called zlib.decompress(dec_stream, -15).

Passing -15 to zlib.decompress instructs Python to inflate raw RFC 1951 Deflate data without expecting zlib or gzip header wrappers. It inflated into the genuine 24,455-byte JPEG image.



Crazy stuff above - need to condense and write in my own words to make sense