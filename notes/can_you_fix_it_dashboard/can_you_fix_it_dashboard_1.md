**Scenario:** Field technicians at **Snowpoint** are experiencing critical malfunctions with their custom vehicles, specifically involving engine ignition failures and unresponsive climate control systems. Engineers suspect a cyber-physical anomaly within either the E**lectronic Control Units (ECUs)**, **Engine Control Modules (ECMs)**, or the **HVAC systems**. To investigate without grounding the fleet, security teams are auditing a simulator harness that hosts the **ECU dashboard on web port 5001** and a **configuration database on Modbus port 5021**, searching for security flaws—such as an **exposed access PIN**—that could allow an external attacker to manipulate these vehicle modules.



**Step 1:** Analyzed Session Management: We submitted a dummy PIN to the **/update\_permissions** endpoint and checked the response headers. We discovered that the web server dropped a **Base64-encoded cookie** (permission=YmFzaWM=, which decodes to basic).



**Step 2:** Proved Cookie Manipulation: We tested the web application's access controls by encoding diagnostics into Base64 (**ZGlhZ25vc3RpY3M=**) and modifying our browser cookie. This **successfully bypassed the front-end PIN screen** and granted access to the Diagnostic View, confirming flawed client-side session tracking.



**Step 3:** Identified Modbus Restrictions: Our initial attempts to bulk-scan the Modbus server failed or returned empty datasets. This revealed that the simulator harness **rejects multi-register requests** and requires individual polling.



**Step 4:** **Executed Single-Register Enumeration:** We developed a precise Python script using pymodbus to query the server on port 5021 for exactly **one register at a time starting from address 0**.



**Step 5:** Recovered the PIN: The individual scan successfully avoided server errors and dumped the first few Input Registers, **exposing the environment's configuration values—including the baseline port layouts, the 1234 default PIN, and the valid diagnostic PIN: 39578**.





