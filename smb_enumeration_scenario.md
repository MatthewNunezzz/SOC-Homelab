# SMB Enumeration

## Table of Contents
- [Scenario Overiew](#i-scenario-overview)
- [Attack Phase](#ii-attack-phase)
- [Detection Phase](#iii-detection-phase)
- [Incident Response Phase](#iv-incident-response-phase)
- [Corrective Measures Phase](#v-corrective-measures-phase)

## I. Scenario Overview:

**Objective:** 

**MITRE ATT&CK Mapping:**
- Tactic: 
- Technique: 
    - Sub-technique: 

## II. Attack Phase:

### Step 1: 


## III. Detection Phase:

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