**Scenario:** An attacker altered a fire suppression BACnet device's temperature setpoint, causing a heat detector to trigger an alarm prematurely during normal operating temperatures. The malicious change was deployed via an encrypted ZIP archive protected with the password jubilife\_BMS\_configuration!. Extract the configuration file from the BACnet network traffic and retrieve the password assigned to the misconfigured binary sensor to submit as the flag.



**1. Log Triage in Malcolm (OpenSearch)**

* You queried the indexed Zeek logs with **destination.ip: "10.120.50.12" OR source.ip: "10.120.50.12" combined with zeek.bacnet.pdu\_service: "atomic\_write\_file"**.
* This identified **6 distinct log events** on standard BACnet UDP port **47808**.
* The log metadata revealed the exact timestamp (2023-05-04 16:51:18 UTC) and the sender IP (10.120.50.198) uploading the configuration file to the fire suppression controller (10.120.50.12).



**2. Packet Capture Extraction in Arkime**

* You switched to Arkime and filtered for the exact conversation: **ip == 10.120.50.198 \&\& ip == 10.120.50.12 \&\& port == 47808 across the May 4th time window**.
* You isolated the raw communication stream and **downloaded the 6 packets as sessions.pcap**.



**3. Protocol Analysis in Wireshark**

* You opened **sessions.pcap** in Wireshark and inspected the BACnet APDU structure.
* You distinguished between the two packet types in the request-response transaction:

  * Packets 2, 4, and 6 were empty server acknowledgments (Complex-ACK).
  * **Packets 1, 3, and 5 were the actual data-bearing requests** (Confirmed-REQ atomicWriteFile).
* Drilling into stream access → File Data:, you observed the standard ZIP file magic signature (50 4B 03 04 / PK..) starting in packet 1.



**4. Payload Carving**

* Because BACnet does not reassemble file transfers like HTTP or TCP streams, you copied the payload (**File Data:**) from each of the three data packets using **Copy → ...as a Hex Stream**:

  * Packet 1: 350 bytes (offset 0)
  * Packet 3: 350 bytes (offset 350)
  * Packet 5: 98 bytes (offset 700)
* You placed the hex sequences sequentially into **filedata.hex**.



**5. Binary Reassembly and Offset Alignment**

* You identified that the raw concatenation previously had framing discrepancies throwing BadZipFile: Bad magic number for central directory.
* Using **Python, you converted the 3 raw hex chunks into binary and merged them end-to-end**:

  * **350 bytes+350 bytes+98 bytes=798 bytes**
* This brought the Central Directory (PK\\x01\\x02) to byte offset 679 and the End of Central Directory (PK\\x05\\x06) to byte 776, perfectly restoring valid ZIP structural integrity as **fixed.zip**.



**6. Decryption and Flag Extraction**

* Extracted the password-protected archive using the key from the challenge prompt: **jubilife\_BMS\_configuration!**
* This unpacked **fire\_suppression\_config.txt**.
* Inside, you inspected the sensor entries and found that while all other heat detectors had a setpoint of **135.0, BINARY 4 (HD-LB) had been maliciously dropped to 72.4**:

  * **BINARY 4**( "HD-LB", 72.4, "Heat Detector - Lab B", "Lab B", "927ab89245")
* You extracted the password string assigned to HD-LB (**927ab89245**) to complete the challenge.

