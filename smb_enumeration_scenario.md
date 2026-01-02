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

### Step 1: Ensure SMB service is open on target (172.16.0.2)
```bash
# Ensure target is reachable
ping -c 4 172.16.0.2

# Check if file-sharing service (445) is open
nmap -p 445 172.16.0.2
```

### Step 2: Enumerate network shares using `smbmap`
```bash
smbmap -H 172.16.0.2 -u Administrator -p 'password1234'  
# - -H: Specify target host IP
# - -u: Specify account username
# - -p: Specify account password 
```
![](screenshots/enum_exfil_01.png)

### Step 3: View contents of Finance share
```bash
smbmap -H 172.16.0.2 -u Administrator -p 'password1234' -r 'Finance'
# - -r: Specify share to open
```
![](screenshots/enum_exfil_02.png)

### Step 4: Locally download all files stored in Finance share
```bash
smbmap -H 172.16.0.2 -u Administrator -p 'password1234' -r Finance -A '.*'
# - -A: Specify which files to download
```
![](screenshots/enum_exfil_025.png)

## III. Detection Phase:

### NIST CSF Function: Detect (DE)

Category: DE.CM — Continuous Monitoring
- DE.CM-09: Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events
     - Mapping: Monitor file sharing services to detect enumeration and exfiltration.

### Step 1: Analyze Windows Security Events

In Wazuh Dashboard ...
- Filter for `agent.name: WIN-MEUJ3KPDEG5` (Windows Server agent)
- Filter for `data.win.system.channel: Security` (Security Event Logs)
- Select Timeslot: `Jan 2, 2026 @ 01:23:00.000` -> `Jan 2, 2026 @ 01:26:00.000`

![](screenshots/enum_exfil_03.png)


### Security Event summary:
| rule.description | hit count | rule.id |data.win.eventdata.ipAddress | agent.ip |
| --- | --- | --- | --- | --- |
| SMB Share Accessed: ... by Administrator | 79 | 100005 | 172.16.0.5 | 172.16.0.2 |
| Possible SMB Enumeration: ... | 24 |  100006 |172.16.0.5 | 172.16.0.2 |
| Windows audit failure event | 3 | 60104 | 172.16.0.5 | 172.16.0.2 |

We observe that some machine (172.16.0.5) logged in as Administrator accessed a large number of network shares across different departments within the span of 3 minutes triggering multiple "Possible SMB Enumeration" alerts.

### Step 2: Analyze Suricata Logs
In Wazuh Dashboard ...
- Filter for `rule.groups:suricata` (network logs)
- Select Timeslot: `Jan 2, 2026 @ 01:23:00.000` -> `Jan 2, 2026 @ 01:26:00.000`

![](screenshots/enum_exfil_04.png)

### Network log summary:
| rule.description | hit count | data.src_ip | data.dest_ip | data.flow.bytes_toclient |
| --- | --- | --- | --- | --- |
| Suricata: Alert - GPL ICMP PING *NIX | 4 | 172.16.0.5 | 172.16.0.2 | 294 |
| Suricata: Alert - Data Exfiltration - Large Transfer from SMB Port  | 1 | 172.16.0.5 | 172.16.0.2 | 54946 |

We observe that some machine (172.16.0.5) sent a ping request to the primary domain controller before transferring a sizeable amount data via the SMB Port. For the data exfiltration alert to be triggered, the machine's IP must appear as an "external" IP not being registered under the Suricata `HOME_NET`, along with having transferred greater than 50 KB. Combined with the fact that this detection was triggered by the same device/account having triggered an SMB enumeration alert shortly before, a data exfiltration attempt appears likely and warrants further investigation.

### Step 3: Network Traffic Analysis (Wireshark)

- How quickly were file shares enumerated?
- How much data was transferred?

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