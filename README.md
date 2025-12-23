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

### Network Diagram: [link to lab architecture]

**Network Configuration:**
- **Subnet:** 172.16.0.0/24
- **Windows Server IP:** 172.16.0.2 (Static)
- **Ubuntu Server IP:** ... TBD
- **Internal Switch IP:** 172.16.0.1
- **Domain Name:** HELPLAB.local

### Hardware & Virtualization Specifications

#### Host Machine
- **RAM:** 16 GB
- **CPU:** 4 cores / 8 threads
- **Storage:** 1 TB SSD
- **Hypervisor:** Microsoft Hyper-V
- **Operating System:** Windows 11 Pro

#### Domain Controller VM (Windows Server 2022)
- **Hostname:** WIN-MEUJ3KPDEG5
- **Operating System:** Windows Server 2022 Standard
- **RAM:** 3.5 GB
- **vCPU:** 4 cores
- **Storage:** 60 GB virtual disk
- **Network:** Hyper-V Internal Switch
- **IP Address:** 172.16.0.2/24 (Static, no gateway)

#### Kali Linux VM 
- **Hostname:** 
... TBD

#### Ubuntu Linux Server VM
- **Hostname:**
... TBD

### For more details on Homelab Installation and Configuration: [link to lab_setup.md]

---

## Defensive Stack & Telemetry

---

## Attack & Detection Scenarios

---

## SIEM Dashboard & Analysis

---

## Incident Response Reports

---

## Lessons Learned

