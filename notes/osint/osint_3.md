**Scenario:** Alyssa Martinez was trying to transfer the extracted company data to a threat actor via USB drive. Forensics could not figure out what was on the drive. I did!



**Phase 1:** Analyzing the Artifact \& Clue



The Clue: The challenge prompt stated that a USB drive was recovered behind the Thatcher Fountain statue and contained an NTFS volume with nothing of apparent interest, but explicitly mentioned investigating Alternate Data Streams (ADS).



The File: FLASHDRIVE.dd.tar.gz contained a raw disk image (FLASHDRIVE.dd), which Windows Disk Management could not natively attach as a VHD because .dd is a flat sector dump lacking a VHD container header/footer.



**Phase 2:** Inspecting the Raw NTFS Image



Listing with 7-Zip: Rather than mounting, 7-Zip was used to inspect the NTFS file system directly:



PowerShell

\& "C:\\Program Files\\7-Zip\\7z.exe" l .\\FLASHDRIVE.dd

The Finding: 7-Zip identified a suspicious user-created image, YouBeenFished.png (507,026 bytes), and noted 5 alternate streams present in the volume.



**Phase 3:** Preserving and Extracting NTFS Streams



Extracting with -ssp: The critical switch -ssp (Set Security / Streams Preservation) instructed 7-Zip to extract both primary files and their NTFS Alternate Data Streams to disk:



PowerShell

\& "C:\\Program Files\\7-Zip\\7z.exe" x -ssp .\\FLASHDRIVE.dd -oextracted\_drive -y

**Phase 4:** Enumerating Streams with PowerShell



Discovering the Hidden Stream: Querying the filesystem using PowerShell's native -Stream parameter revealed an alternate stream attached to the image:



PowerShell

Get-ChildItem -Path .\\extracted\_drive -Recurse | Get-Item -Stream \*

The Target:



File: YouBeenFished.png



Stream Name: AdobePackages



Length: 180 bytes



**Phase 5:** Reading and Decoding the Payload



Reading the Stream:



PowerShell

Get-Content .\\extracted\_drive\\YouBeenFished.png -Stream AdobePackages

This returned a Base64 string:



Plaintext

U2VuZCB1cyB0aGVzZSBkb2N1bWVudHMgbmV4dDogTm9kZSBOZXR3b3JrIERlc2lnbiBEb2N1bWVudCwgTmV0d29yayBTZWN1cml0eSBQb2xpY3ksIERpc2FzdGVyIFJlY292ZXJ5IFBsYW4sIEZsYWc6IEFsdGVybmF0ZURhdGFTdHJlYW1z

Decoded Message:



"Send us these documents next: Node Network Design Document, Network Security Policy, Disaster Recovery Plan, Flag: AlternateDataStreams"



**Flag: AlternateDataStreams**

