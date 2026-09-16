**File System Timeline \& Incident Response**

**Initial Execution \& C2 Communication**

Identified malicious executable **B@CkD00R.exe (PID 5524)**. Initial execution began at 3:38:59.366 PM.



**Immediately upon execution, it established an outbound reverse TCP connection to 172.16.240.2:4444**, indicating a Metasploit/Meterpreter payload: **"3:38:59.6122301 PM","B@CkD00R.exe","5524","TCP TCPCopy","ENGINEERINGWKS.jubilife.com:64974 -> 172.16.240.2:4444","SUCCESS","Length: 1460, seqnum: 0, connid: 0"**



**Thread Injection \& Migration to winlogon.exe**

Observed three bursts of Thread Create events in B@CkD00R.exe:

* 3:38:59 PM: Initial execution (4 threads created)
* 3:39:09 PM – 3:39:13 PM: First burst (11 threads created)
* 3:39:24 PM: Second burst (5 threads created)



**During the second burst, a remote thread was injected into winlogon.exe (PID 796). Immediately following the injection:**

* 3:39:26 PM: winlogon.exe queried WinSock2\\Parameters\\NameSpace\_Catalog5 and dynamically loaded networking libraries (wshtcpip.dll, mswsock.dll, and wshqos.dll).



**Note:** A legitimate winlogon.exe process does not initialize WinSock2 and TCP networking components under normal operation, confirming it became the host for the migrated reverse shell.



**File System Timeline \& Incident Response Boundary**

The adversary's active staging window occurred strictly between process migration (03:39:24 PM) and the launch of the automated host logging script (03:42:38 PM):

* 03:38:59 PM – B@CkD00R.exe (Initial malware execution \& reverse TCP connection)
* 03:39:24 PM – winlogon.exe (Remote thread injected; process migrated to SYSTEM)
* 03:40:23 PM – C:\\Windows\\passwords.pcap (First file added by adversary)
* 03:41:46 PM – C:\\Users\\ABIGAIL\_FORBES\\Documents\\capcom.doc (Last file added by adversary / LPE driver exploit tool)
* 03:42:38 PM – ENGINEERINGWKS-2023-05-15-03-42 (IR Snapshot Cutoff: Custom logging script execution began)
* 03:42:58 PM+ – AmazonList2.\*, newProject.pdf, VMS.pdf (Post-trigger noise / collection artifacts; discarded)



