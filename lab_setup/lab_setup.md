# Build Wazuh Server VM:

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
```bash
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
```
- Save (Ctrl+X, Y, Enter) and apply:
- Run `sudo netplan try`

## Download Wazuh agent on DC
On your host machine:
1. Navigate to https://documentation.wazuh.com/4.9/installation-guide/wazuh-agent/wazuh-agent-package-windows.html
2. Download wazuh agent for windows (Ensure agent version is compatible with wazuh manager version)
3. Copy/Paste downloaded file over to DC VM in the desktop folder (must be running enhanced session)

## Install Wazuh agent on DC
Run powershell as administrator on DC
1. Run `msiexec.exe /i C:\Users\Administrator\Desktop\wazuh-agent-4.9.2-1.msi /q WAZUH_MANAGER="172.16.0.6"`
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

---

# Build Kali Linux (Attacker) VM

## Install Pre-built Kali Linux VM

1. Go to: https://www.kali.org/get-kali/#kali-virtual-machines
2. Download Kali Linux Hyper-V 64-bit (approximately 3-4 GB)
3. Extract the ZIP file
4. Install the VM by double-clicking "install-vm.bat" script
5. Configure VM settings: 
  - Set RAM to 2 GB
  - 2 virtual processors
  - Set network adapter to Internal switch
6. Default credentials for pre-built VM: 
  - Username: `kali`
  - Password: `kali`

## Update Kali and Install Tools
```bash
# Update and install tools

# Update system
sudo apt update && sudo apt upgrade -y

# Install additional useful tools
sudo apt install -y \
  crackmapexec \
  evil-winrm \
  impacket-scripts \
  enum4linux \
  smbclient \
  hydra \
  metasploit-framework \
  powershell-empire \
  bloodhound \
  responder \
  mimikatz \
  chisel

# Initialize Metasploit database
sudo msfdb init

```

## Configure Kali Network settings
In Hyper-V Manager
- Configure Kali VM network adpater to Internal Switch
- Start Kali Linux VM

In Kali linux VM
- Open terminal
- Edit network configuration: `sudo nano /etc/network/interfaces`
```bash
# Add to file ...
# Internal switch network interface (eth0)
auto eth0
iface eth0 inet static
        address 172.16.0.5
        netmask 255.255.255.0
        gateway 172.16.0.2
        dns-nameservers 172.16.0.2
```
- Edit default dns resolver file: `sudo nano /etc/resolv.conf`
```bash
# Overwrite existing file ...
search helplab.local
nameserver 172.16.0.2

# Ensure Kali can ping wazuh-server and DC
ping -c 4 172.16.0.6
ping -c 4 172.16.0.2

# May need to edit DNS records on DC
nslookup wazuh-server
nslookup WIN-MEUJ3KPDEG5 # resolve DC hostname
```

---

# Suricata Configuration on Ubuntu

1. Verify Suricata Installation: `suricata -V`
2. Check if rules downloaded: `ls -lh /var/lib/suricata/rules` (Should show 'suricata.rules')
3. Configure Suricata for your Network
```bash
# Backup original config
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup

# Edit main configuration
sudo nano /etc/suricata/suricata.yaml
```
- Modify these main sections:
Define home network:
```yaml
vars:
  address-groups:
    HOME_NET: "[172.16.0.2/32]" # Ensure Kali host is external to more easily trigger alerts
    EXTERNAL_NET: "!$HOME_NET"
```
Configure network interface (using AF_PACKET socket):
```yaml
af-packet:
  - interface: eth0  # Your interface name
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: no # for VM stability
```
Enable EVE JSON logging (consolidates alerts, protocol data, and file info into single JSON file.):
```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
        - http:
            extended: yes
        - dns:
            version: 2
        - tls:
            extended: yes
        - files:
            force-magic: no
        - smtp:
        - ssh
        - flow
```
4. Enable Promiscuous Mode (network interface analyzes all network traffic instead of ignoring traffic not meant for it)
```bash
# Enable promiscuous mode on network interface
sudo ip link set eth0 promisc on

# Make it persistent (survives reboot)
sudo nano /etc/network/interfaces # Add "post-up ip link set eth0 promisc on"

# Create a new systemd service to keep promiscuous mode on
sudo nano /etc/systemd/system/promisc-eth0.service
```
Add this content:
```yaml
[Unit]
Description=Enable promiscuous mode on eth0 for Suricata
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set eth0 promisc on
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```
Enable and restart the service:
```bash
# Reload systemd to recognize new service
sudo systemctl daemon-reload

# Enable service to run at boot
sudo systemctl enable promisc-eth0.service

# Start it now
sudo systemctl start promisc-eth0.service

# Check status
sudo systemctl status promisc-eth0.service

# Verify promiscuous mode is enabled
ip link show eth0
# Should show PROMISC now
```
Ensure Hyper-V port mirroring is Enabled:
```PowerShell
# Check which VMs are set as Source/Destination
Get-VM | Get-VMNetworkAdapter | Select-Object VMName, PortMirroringMode # DC should say src and Wazuh-server dest

# 1. Set the Domain Controller to send traffic
Set-VMNetworkAdapter -VMName "Your_DC_Name" -PortMirroring Source

# 2. Set the Wazuh Server to receive traffic
Set-VMNetworkAdapter -VMName "wazuh-server" -PortMirroring Destination
```
5. Test Suricata Configuration
```bash
# Test configuration syntax
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Should end with:
# "Configuration provided was successfully loaded. Exiting."
```
6. Start Suricata
```bash
# Start Suricata service
sudo systemctl start suricata

# Enable to start on boot
sudo systemctl enable suricata

# Check status
sudo systemctl status suricata

# Should show "active (running)"

# Monitor Suricata in real-time
sudo tail -f /var/log/suricata/suricata.log
```
7. Verify Suricata is capturing traffic
```bash
# Watch for network logs in real-time
sudo tail -f /var/log/suricata/eve.json
# or
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert") | {time: .timestamp, alert: .alert.signature, severity: .alert.severity, src: .src_ip, dest: .dest_ip, dest_port: .dest_port}' # for alerts
# Generate test traffic from Kali to trigger alerts
# Open another terminal on Kali and run:
# nmap 172.16.0.2

# You should see JSON events appearing
```
8. Configure Wazuh to ingest Suricata Alerts
```bash
# Edit Wazuh manager configuration on Ubuntu
sudo nano /var/ossec/etc/ossec.conf
```
Find the `ossec_config` section and add this before the closing tag:
```xml
<!-- Suricata integration -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
```
Save and Exit
```bash
# Restart Wazuh agent to apply changes
sudo systemctl restart wazuh-manager

# Check Wazuh agent status
sudo systemctl status wazuh-manager
```