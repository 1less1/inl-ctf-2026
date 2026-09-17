[Home](../../README.md) | [Challenges](../../challenges/challenges.md) | [Tools](../../tools/tools.md) 
# Tools
## Malcolm
![Malcolm Logo](./images/tools/malcolm_logo.png)  
**Malcolm** is an open source network traffic analysis tool (**NTA**) and network security monitoring (**NSM**) suite developed by **CISA** (Cybersecurity and Infrastructure Security Agency) in partnership with Idaho National Laboratory (**INL**). It packages server industry standard tools into a unified **Docker/Kubernetes** container stack, designed to ingest, enrich, and visualize full packet captures (PCAP), **Zeek** logs, and **Suricata** alerts.

### Zeek
Passive network security monitor that parses raw packet streams into detailed, structured, protocol-specific transaction logs for deep forensic visibility and behavioral analysis.

### Suricata
Rule based intrusion detection and prevention system (**IDS/IPS**) that actively scans network traffic and payloads against known threat signatures to generate real-time security alerts.

### Home Screen
![Malcolm home screen](./images/tools/malcolm_home.png)  

## Core Components  
### Dashboards
![Malcolm dashboard](./images/tools/malcolm_dashboard.png)  
Visualize parsed network data through pre built dashboards with filtering and data manipulation.

### Arkime
![Arkime dashboard](./images/tools/arkime_dashboard.png)  
Network session analysis tool that provides deep insights into network traffic and helps identify security threats.

### NetBox
![Netbox dashboard](./images/tools/netbox_dashboard.png)  
IP address management (IPAM) and network documentation tool that helps manage and document network assets.

### CyberChef
![CyberChef dashboard](./images/tools/cyberchef_dashboard.png)  
"Swiss Army knife" web utility for deobfuscating, decoding, hashing, and manipulating extracted data payloads on the fly.

### Artifact Upload
![Artifact Upload dashboard](./images/tools/artifact_upload_dashboard.png)  
Browser based ingestion portal to drag and drop standalone PCAP files or Zeek/Suricata logs for immediate indexing and processing.

### Keycloak
![Keycloak dashboard](./images/tools/keycloak_dashboard.png)  
Centralized authentication, RBAC, and identity management across Malcolm's microservices.

### Extracted Files
![Extracted Files dashboard](./images/tools/extracted_files_dashboard.png)  
Automatically captures files transmitted across the wire via Zeek, scanning them for malware, signatures, and entropy.

## Wireshark
![Wireshark logo](./images/tools/wireshark_logo.png)  
Network traffic analyzer providing full packet inspection, protocol dissection, and deep forensics across hundreds of protocols to isolate anomalies, decode payloads, and export session artifacts.

## Nmap
![Nmap logo](./images/tools/nmap_logo.png)  
Network scanning tool that enables host/topology discovery, port and service fingerprinting, and vulnerability assessment (misconfigurations, default credentials, and known CVEs).
