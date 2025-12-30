# SOC-Homelab

## Table of Contents
- [Project Overview](#project-overview)
- [Logical Architecture](#logical-architecture)
- [Defensive Stack & Telemetry](#defensive-stack--telemetry)
- [Attack & Detection Scenarios](#attack--detection-scenarios)
- [SIEM Dashboard & Analysis](#siem-dashboard--analysis)
- [Incident Response Reports](#incident-response-reports)
- [Lessons Learned](#lessons-learned)

---

## Project Overview

### Description
This homelab project demonstrates the design and implementation of an SOC environment ...

### Key Objectives
- 

---

## Logical Architecture

### Network Diagram: ![link to lab architecture](lab_setup/images/soc_network_config.png)

**Network Configuration (no gateway):**
- **Subnet:** 172.16.0.0/24
- **Windows Server IP:** 172.16.0.2
- **Wazuh Server IP:** 172.16.0.6
- **Kali Linux IP:** 172.16.0.5
- **Internal Switch IP:** 172.16.0.1
- **Domain Name:** HELPLAB.local

### Hardware & Virtualization Specifications

#### Host Machine
- **RAM:** 16 GB
- **CPU:** 4 cores / 8 threads
- **Storage:** 1 TB SSD
- **Hypervisor:** Microsoft Hyper-V
- **Operating System:** Windows 11 Pro

#### Windows Server VM
- **Hostname:** `WIN-MEUJ3KPDEG5`
- **Operating System:** Windows Server 2022 Standard
- **RAM:** 3.5 GB
- **vCPU:** 4 cores
- **Storage:** 60 GB virtual disk
- **IP Address:** 172.16.0.2/24

#### Kali Linux VM 
- **Hostname:** `kali`
- **Operating System:** Kali Linux
- **RAM:** 2 GB
- **vCPU:** 2 cores
- **Storage:** 40 GB virtual disk
- **IP Address:** 172.16.0.5/24 

#### Wazuh Server VM
- **Hostname:** `wazuh-server`
- **Operating System:** Ubuntu Linux
- **RAM:** 2.5 GB
- **vCPU:** 2 cores
- **Storage:** 40 GB virtual disk
- **IP Address:** 172.16.0.6/24 

[Click here for more details on Homelab Installation and Configuration](lab_setup/lab_setup.md)

---

## Defensive Stack & Telemetry

| Component | Technology | Purpose |
| --- | --- | --- |
| **Endpoint Agent** | Wazuh Agent | Log collection and active response |
| **Endpoint Monitor** | Sysmon | Detailed windows activity logging |
| **Network Monitor** | Suricata | Network activity logging |
| **Central Manager** | Wazuh Manager | Enriches data, matches rules, and triggers alerts |
| **Database** | Wazuh Indexer | Stores and indexes the data |
| **Visualizer** | Wazuh Dashboard | Provides the GUI for analysis and reporting |

### 1. Endpoint Detection & Response (EDR)

- Wazuh Agent: 
- Sysmon:

### 2. SIEM & Log Management

-

### 3. Network Security & Monitoring



### 4. Telemetry Visualization



---

## Attack & Detection Scenarios

---

## SIEM Dashboard & Analysis

---

## Incident Response Reports

---

## Lessons Learned

