# SMB Enumeration & Data Exfiltration

## Table of Contents
- [Scenario Overiew](#i-scenario-overview)
- [Attack Phase](#ii-attack-phase)
- [Detection Phase](#iii-detection-phase)
- [Incident Response Phase](#iv-incident-response-phase)
- [Corrective Measures Phase](#v-corrective-measures-phase)

## I. Scenario Overview:

**Objective:** Using valid SMB credentials, enumerate network shares hosted on the Windows Server (172.16.0.2), identify sensitive or accessible data, and exfiltrate selected files to an unauthorized system within the segmented private network.

**MITRE ATT&CK Mapping:**
- Tactics: 
    - Discovery (TA0007)
    - Exfiltration (TA0010)
- Techniques: 
    - Network Share Discovery (T1135)
    - Exfiltration Over Alternative Protocol (T1048)

## II. Attack Phase:

- use smbmap to enumerate network shares
- use smbmap to list finance share contents
- use smbmap to download balance sheet file

### Step 1: 


## III. Detection Phase:

- Windows Security logs: remote logon, Excessive SMB Share Enumeration ALERT
- Suricata: SMB traffic to External Host ALERT
- Wireshark: Confirm that Enumeration + Exfiltration occurred, how much data was transferred?

### NIST CSF Function: Detect (DE)

Category: DE.[] — []
- DE.[]-[]: []
     - Mapping: []

### Step 1:

In Wazuh Dashboard ...
- Filter for `agent.name: WIN-MEUJ3KPDEG5` (Windows Server agent)
- Filter for `data.win.system.channel: Security` (Security Event Logs)
- Select Timeslot: 

![](screenshots/.png)


### Security Event summary:
| rule.description | hit count | rule.id |data.win.eventdata.ipAddress | agent.ip |
| --- | --- | --- | --- | --- |
| Logon Failure - Unknown user or bad password | 13K+ | 60122 | 172.16.0.5 | 172.16.0.2 |
| Multiple Windows Logon Failures | 2K+ |  60204 |172.16.0.5 | 172.16.0.2 |
| Successful Remote Logon Detected - User:\Administrator ... | 1 | 92652 | 172.16.0.5 | 172.16.0.2 |



### Step 2: Analyze Suricata Logs
In Wazuh Dashboard ...
- Filter for ...
- Select Timeslot: 

![](screenshots/.png)

### Network log summary:
| rule.description | hit count | data.src_ip | data.dest_ip | data.dest_port |
| --- | --- | --- | --- | --- |
| Suricata: Alert - GPL ICMP PING *NIX | 4 | 172.16.0.5 | 172.16.0.2 | N/A |
| Suricata: Alert - SURICATA STREAM ... | 128 | 172.16.0.5 | 172.16.0.2 | 445 |



### Step 3: Network Traffic Analysis (Wireshark)


## IV. Incident Response Phase:

Immediate Actions:
- Temporarily Lock Administrator Account
- Reset Administrator Password
- Block attacker source IP using host-based firewall rules on the Domain Controller/file server

Scope & Impact Analysis:
- Investigate File Server Audit logs to see:
    - Which shares were accessed? 
    - Which files were read or copied? 

Notification & Escalation:
- Escalate incident to Finance department

### NIST CSF Function: Response (RS)

Category: RS.MI — Incident Mitigation 
- DE.MI-01: Incidents are contained
    - Mapping: Temporarily lock administrator account
- DE.MI-02: Incidents are eradicated 
    - Mapping: Reset Administrator Account Password

### Remediation Steps:

Step 1: 

Step 2: 

## V. Corrective Measures Phase:

- Enforce stronger authentication policies for privileged accounts.
- Restrict SMB access to authorized domain-joined devices.

### NIST CSF Function: Protect (PR)

Category: PR.AA — Identity Management, Authentication, and Access Control
- PR.AA-03: Users, services, and hardware are authenticated
     - Mapping: Implement Password Complexity Policy

Category: PR.PS — Platform Security
- PR.PS-01: Configuration management practices are established and applied
     - Mapping: Implement Account Lockout Policy

### Preventative Measures:

Step 1:

Step 2: 