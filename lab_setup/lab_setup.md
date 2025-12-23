# Build Ubuntu Server VM:

## Download Ubuntu Server
1. Get Ubuntu Server 24.04 LTS from: https://ubuntu.com/download/server
2. Download the ISO (approximately 2.5 GB)

## Create VM in Hyper-V
Hyper-V Manager Steps:

1. Right-click your Hyper-V host → New → Virtual Machine
2. Name: Ubuntu-Wazuh-Server
3. Generation: Generation 2
4. Memory: 2560 MB (2.5 GB), uncheck "Use Dynamic Memory"
5. Networking: Select your default/external switch (for installing necessary packages from internet)
6. Virtual Hard Disk: Create new, 40 GB (dynamically expanding is fine)
7. Installation Options: Select your Ubuntu ISO
8. Finish the wizard

## Before starting the VM:
1. Right-click VM → Settings
2. Security → Disable "Enable Secure Boot" (or change to Microsoft UEFI)
3. Processor → Set to 2 virtual processors
4. Click OK

## Install Ubuntu Server
Start the VM and follow the installer:

- Language: English
- Keyboard: Your layout (usually English US)
- Installation type: Ubuntu Server (default)
- Network:
    - Should show your network adapter
    - Choose "Edit IPv4" → DHCPv4 (automatic)
    - Save and continue
- Proxy: Leave blank
- Mirror: Use default (or choose closest mirror)
- Storage: Use entire disk (default)
- Profile Setup:
    - Your name: Matt
    - Server name: wazuh-server
    - Username: administrator
    - Password: Strong password (save it!)

- SSH Setup: Check "Install OpenSSH server"
- Featured snaps: Don't select anything, just continue
- Installation will begin - takes 5-10 minutes
- When complete, select "Reboot Now"
- Press Enter when prompted to remove installation medium

## Initial Ubuntu Configuration
```bash
# Login with username and password

#Update package list and upgrade system
sudo apt update && sudo apt upgrade -y

#Install useful security tools and utilities
sudo apt-get install -y \
  suricata suricata-update tcpdump tshark net-tools nmap \
  curl wget jq htop iotop python3-pip && \
  sudo suricata-update && \
  sudo suricata-update update-sources && \
  sudo suricata-update enable-source et/open && \
  sudo suricata-update enable-source oisf/trafficid

```

## Install Wazuh Server
```bash
# Extend the logical volume of Disk space to utilize all of assigned VM disk space
sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv

# Resize the file system to use new available disk space
sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv

# Download the installation script
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh

# Download the configuration file
curl -sO https://packages.wazuh.com/4.9/config.yml

# Run the installation
sudo bash wazuh-install.sh -a

# Verify Installation
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard

# All should show "active (running)"
```

## Access Wazuh Dashboard
1. Navigate to `https://<wazuh-dashboard-ip>:443`
2. You'll get a certificate warning click "Advanced" > "Proceed"
3. Login with:
    - Username: `admin`
    - Password: (installation output)

## Reconfigure Ubuntu server VM to internal network
- Shut down the VM
- Go back to Settings → Network Adapter
- Switch back to your internal network switch
- Start the VM

Once booted, reconfigure the static IP:
- Edit netplan configuration
```bash
sudo nano /etc/netplan/50-cloud-init.yaml
```
- Change it to:
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: false
      addresses:
        - 172.16.0.6/24
      routes:
        - to: default
          via: 172.16.0.2
      nameservers:
        addresses:
          - 172.16.0.2
- Save (Ctrl+X, Y, Enter) and apply:
- Run `sudo netplan try`

Checkpoint-----------------------

## Download Wazuh agent on DC
On your Windows Server 2022 DC:
1. Open browser and go to: https://192.168.10.100
2. Login to Wazuh Dashboard
3. Click hamburger menu (☰) → Server management → Endpoints summary
4. Click Deploy new agent
5. Configure:
    - Operating system: Windows
    - Server address: 192.168.10.100
    - Agent name: DC01 (or your preference)
6. Copy the PowerShell command shown

## Install Wazuh agent on DC
Run powershell as administrator on DC
1. Execute copied powershell command
2. Start the agent `NET START WazuhSvc`

## Verify Agent connection
Back in Wazuh Dashboard
1. Go to Server management > Endpoints summary
2. After 30-60 seconds, you should see agent appear
3. Status should show active
Check logs are flowing:
1. Click on agent name
2. Click Security events tab
3. You should start seeing Windows Event logs appearing