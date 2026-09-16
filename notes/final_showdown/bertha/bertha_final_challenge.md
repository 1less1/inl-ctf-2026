**Phase 1:** Analyzing the Master Challenge \& Scoreboard Context



The Prompt Architecture: The CTF presented an overarching boss challenge called Elite Four Showdown worth 850 points.



The Goal: Unlocking a listening TCP service at <CTFd\_IP>:9004 which requires four specific submission strings in the format $CEO\_NAME's Secret Key is: $SECRET\_KEY.



The Breadcrumb Trail: The challenge description established that each CEO represented an organization from earlier tracks:

* Aaron Celestic (provided starter password)
* Bertha Jubilife
* Flint Snowpoint
* Lucian Veilstone



Harvesting the Bertha Password: Completing the concluding challenge in the Jubilife track yielded Bertha's archive password: **30272a6cf9420ad29110a84c700f5c7db2fde08d**



**Phase 2:** Archive Extraction \& Initial Triage



Unpacking Layer 1: Using 7-Zip with the retrieved SHA1 password against bertha\_jubilife\_challenge.zip unpacked two files:

* bertha\_jubilife\_readme.txt
* jubilife\_challenge.zip



Inspecting the Readme: Reading b**ertha\_jubilife\_readme.txt** supplied the operational constraints:



The target file was **jubilife\_challenge.zip**.



The author explicitly hinted: **"Bertha has a favorite password TYPE, and luckily she only uses lowercase dictionary words for all her passwords."**



The Failure Mode: When listing jubilife\_challenge.zip via 7z l, 7-Zip identified an inner file named jubilife\_challenge.jpg (\~24 KB), but immediately threw:



Plaintext

ERRORS: Unexpected end of archive

Attempting standard extraction prompted for a password, but entering passwords either failed or yielded an empty placeholder file.



**Phase 3:** Deep File Forensics \& Diagnosing the Corruption



Verifying the Magic Bytes: Running a Python byte inspection over the file header printed:



Plaintext: **50 4b 03 04 14 00 09 00 08 00 ...**



This confirmed it was a **genuine ZIP local file header** (PK\\x03\\x04), using **standard Deflate compression** (method 08) with encryption bit flags set (0x09).



Why Traditional Extractors Failed:

* A valid ZIP file has three parts: Local File Headers + Compressed Payloads, a Central Directory, and an End of Central Directory (EOCD) record.
* The challenge author intentionally chopped off the entire central directory footer.
* Standard archive tools (7-Zip, WinRAR, Windows Explorer) read ZIPs from the back to the front (seeking the EOCD first). Without the footer, standard tools crash or assume the stream is truncated, failing to authenticate or decompress the payload properly.



Confirming Empty Extractions: Inspecting the file that 7-Zip previously spat out with **exiftool** returned:

Plaintext

Error: Entire file is binary zeros

This proved that earlier CLI attempts hadn't actually cracked anything; 7-Zip had simply allocated zeroed dummy blocks due to the missing footer.



**Phase 4:** Algorithmic Recovery \& In-Memory Cracking



The Pokémon Lore Connection: Bertha is the Ground-type Elite Four master from the Sinnoh Pokémon region. The hint's emphasis on "favorite password TYPE" meant the password was the word ground or a Ground-type move/species in all lowercase.



Bypassing the Footer: Instead of attempting to manually repair the Central Directory hex headers, a custom Python script was constructed to handle raw PKZIP stream decryption directly in RAM:



Offset Calculation: It located the start of the payload at offset **30 + filename\_length + extra\_length.**



ZipCrypto Stream Emulation: PKZIP uses three 32-bit state keys (k0, k1, k2) shifted through a CRC32 table for every character in the password.



The 12th Byte Check: The first 12 bytes of any PKZIP encrypted stream are pseudo-random garbage used to verify passwords. In archives with bit 3 set, the 12th decrypted byte must match the high byte of the file's modification time.



The Break: The script tested dictionary candidates against this single check byte. When testing the literal word **ground**, **byte 12 matched**.



Inflation: The script ran the decrypted stream through zlib.decompress(payload, -15) (raw RFC 1951 Deflate decompression), successfully reconstructing the intact 24,455-byte recovered\_jubilife.jpg.



**Phase 5:** Steganographic Carving



Desktop Reconnaissance: A folder named **steghide** existed on the system desktop (C:\\Users\\Public\\Desktop\\steghide), indicating that image **steganography** was the intended next layer.



Payload Extraction: Since CTF challenge designers frequently reuse passwords across nested layers, ground was supplied as the passphrase to **steghide.exe**:



PowerShell

**\& "C:\\Users\\Public\\Desktop\\steghide\\steghide.exe" extract -sf .\\recovered\_jubilife.jpg -p "ground"**

Result: Steghide extracted jubilife\_secret.txt, containing:

**Congratulations! You have completed Bertha Jubilfie's challenge.**



**Bertha's Secret Key is: ce1e5df1d63331a93fd9f99b2a3a62d795364ad7**

