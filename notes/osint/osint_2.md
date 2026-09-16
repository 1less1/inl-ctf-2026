**Scenario:** Insider suspect Alyssa Martinez (alyssaDesigns) exfiltrated confidential company data through her GitHub repositories, which were initially uncovered via a browser history snapshot (BrowserHistory.png) pointing to alyssaDesigns/Malcolm and alyssaDesigns/icsnpp-opcua-binary. Working through the provided repository archives (malcolm-repo.tar.gz and icsnpp-opcua-binary-repos.tar.gz), an investigator discovers that Alyssa staged a disguised file named test.pcap in a hidden commit (2b7aba9) on the Malcolm repo before immediately reverting it to conceal the activity. By analyzing a modified source file (opcua\_binary-activate-browse\_analyzer.pac) in the secondary OPC UA repository, the exfiltration scheme is reverse-engineered as a Base64-encoded, byte-level Vigenère cipher utilizing the key "supersecretkey". Reversing this cipher on the disguised PCAP yields an encrypted ZIP archive containing employee records (CelesticEmployeesInformation.csv) and a proprietary 6G research PDF (Defining the Tenets of 6G Wireless System\_ A Forward-Looking Vision.pdf), where extracting the research paper and reviewing the end of its text reveals the challenge's final flag (w1r3l355f0r4ll).



**Phase 1: Establishing the Threat Actor \& Target Repositories**



**Finding:** Reviewing the suspect’s browser history (BrowserHistory.png) revealed Alyssa Martinez (alyssaDesigns) actively visiting two GitHub repositories: alyssaDesigns/Malcolm (at 3:16 PM) and alyssaDesigns/icsnpp-opcua-binary (at 3:01 PM).



**Initial Archive Extraction:**



PowerShell

tar -xzf .\\malcolm-repo.tar.gz

tar -xzf .\\icsnpp-opcua-binary-repos.tar.gz

Extraction of malcolm-repo.tar.gz on Windows threw symlink creation errors (Can't create ... Invalid argument), but the underlying .git repository folder remained intact.



**Phase 2:** Uncovering the Hidden Git Exfiltration Artifact



**Finding:** Inspecting recent commits in alyssaDesigns-malcolm revealed Alyssa had added a PCAP file and immediately reverted the commit to erase it from the working tree.



PowerShell

git log -n 10 --oneline

\# Output:

\# 9e22d26 (HEAD -> main) Revert "adding test.pcap"

\# 2b7aba9 adding test.pcap

Checking Out the Deleted Evidence:



PowerShell

git checkout 2b7aba9

This restored test.pcap inside alyssaDesigns-malcolm\\pcap\\upload\\test.pcap.



**Phase 3:** Inspecting test.pcap \& File Fingerprinting



Finding: Wireshark failed to open test.pcap because it was not a raw capture file. Opening it in VS Code revealed a single continuous string of Base64 characters starting with w8BzaYZzZWNy....



Decoding the Base64 Layer:



PowerShell

$base64 = (Get-Content .\\test.pcap -Raw).Trim()

$bytes = \[System.Convert]::FromBase64String($base64)

\[System.IO.File]::WriteAllBytes("$PWD\\decoded.bin", $bytes)

Analyzing decoded.bin:

Checking the printable ASCII bytes revealed repeating plaintext key remnants (supersecretk... / secre), pointing to XOR or polyalphabetic encryption applied over standard binary structures.



**Phase 4:** Hunting the Decryption Routine Across Repositories



**Finding:** While alyssaDesigns-icsnpp-opcua-binary showed a decoy commit message (939d96e No Commit History Here), checking directory differences against the clean upstream repo revealed a modified source file:



PowerShell

Compare-Object -ReferenceObject (Get-ChildItem -Recurse -File .\\upstream-icsnpp-opcua-binary) -DifferenceObject (Get-ChildItem -Recurse -File .\\alyssaDesigns-icsnpp-opcua-binary) -Property Name, Length

This flagged opcua\_binary-activate-browse\_analyzer.pac.



Extracting the Algorithm \& Key:



PowerShell

Get-Content .\\alyssaDesigns-icsnpp-opcua-binary\\src\\opcua\_binary-activate-browse\_analyzer.pac

The file contained embedded Python logic specifying the cipher and key:



Algorithm: Base64 decode, followed by byte-by-byte subtraction modulo 256:



plaintext\[i] = (ciphertext\[i] - ord(key\[i % len(key)])) % 256



Key: "supersecretkey"



**Phase 5:** Decrypting the Exfiltrated Payload



Executing the Reconstructed Decryption:

Running the decryption script against the Base64 data inside test.pcap:



PowerShell

python -c "import base64; ct = base64.b64decode(open(r'C:\\Users\\coreadmin\\Downloads\\OSINT2\\alyssaDesigns-malcolm\\pcap\\upload\\test.pcap', 'rb').read().strip()); key = b'supersecretkey'; pt = bytes(\[(ct\[i] - key\[i % len(key)]) % 256 for i in range(len(ct))]); open('exfiltrated\_data.bin', 'wb').write(pt); print(pt\[-1000:].decode('latin1', errors='ignore'))"

Payload Identification:

The output displayed the signature PK header and listed the bundled files:



download /CelesticEmployeesInformation.csv



download /Defining the Tenets of 6G Wireless System\_ A Forward-Looking Vision.pdf



**Phase 6:** Archive Extraction \& Flag Retrieval



Fixing Trailing Path Spaces on Windows:

Standard extraction failed because the archive folder name had a trailing space (download /). A targeted script stripped the trailing space to extract the PDF cleanly:



PowerShell

python -c "import zipfile, os; z = zipfile.ZipFile('exfiltrated\_data.bin'); \[os.makedirs(os.path.dirname(os.path.join('extracted\_exfil', \*\[p.strip() for p in info.filename.split('/') if p.strip()])), exist\_ok=True) or open(os.path.join('extracted\_exfil', \*\[p.strip() for p in info.filename.split('/') if p.strip()]), 'wb').write(z.read(info.filename)) for info in z.infolist() if not info.is\_dir() and \[p.strip() for p in info.filename.split('/') if p.strip()]]"

Flag Extraction:

Inspecting the final section of Defining the Tenets of 6G Wireless System\_ A Forward-Looking Vision.pdf revealed the exfiltrated flag string:



**Flag: w1r3l355f0r4ll**

