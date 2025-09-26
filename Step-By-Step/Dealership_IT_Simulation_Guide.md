# Dealership IT Infrastructure Simulation – Step-by-Step Build Guide

**Author:** Christian Leep  

This project simulates a dealership IT environment using **Windows Server 2022**, **Windows 11**, and **VirtualBox**.  
It demonstrates skills in **Active Directory, DNS, DHCP, Group Policy, security hardening, file/print services, and remote administration**.

---

## 📖 Table of Contents
1. [Prerequisites & Lab Topology](#1-prerequisites--lab-topology)  
2. [VirtualBox VM Setup](#2-virtualbox-vm-setup)  
3. [Domain Controller: Networking](#3-domain-controller-networking)  
4. [Domain Controller: Roles](#4-domain-controller-roles)  
5. [DNS Configuration](#5-dns-configuration)  
6. [DHCP Configuration](#6-dhcp-configuration)  
7. [OU Structure, Users & Groups](#7-ou-structure-users--groups)  
8. [Management Server Setup](#8-management-server-setup)  
9. [Department Shares & Permissions](#9-department-shares--permissions)  
10. [Core Group Policies](#10-core-group-policies)  
11. [Validation & Troubleshooting](#11-validation--troubleshooting)  
12. [Future Enhancements](#12-future-enhancements)  

---

## 1) Prerequisites & Lab Topology
- **Host:** PC capable of running multiple VMs in VirtualBox  
- **ISOs:** Windows Server 2022, Windows 11 Pro  
- **VMs:**
  - Dealership-DC (4 GB RAM, 2 CPU, 50 GB disk)
  - MGMT-SRV (4 GB RAM, 2 CPU, 50 GB disk)
  - Sales-PC, Service-PC (4 GB RAM, 2 CPU, 80 GB disk each)  
- **Network:**  
  - Internal network: `192.168.1.0/24`  
  - NAT adapter for Internet access  

---

## 2) VirtualBox VM Setup
- Create **Dealership-DC** with Windows Server 2022 Standard.  
- Power off → Settings → Network:
  - Adapter 1: Internal Network  
  - Adapter 2: NAT  

---

## 3) Domain Controller Networking
Set static IP on Internal NIC:  

- IP: `192.168.1.10`  
- Subnet: `255.255.255.0`  
- Gateway: `192.168.1.1`  
- DNS: `192.168.1.10`  

---

## 4) Domain Controller Roles
```powershell
# Install roles & tools
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-WindowsFeature DNS -IncludeManagementTools
Install-WindowsFeature DHCP -IncludeManagementTools
Install-WindowsFeature GPMC -IncludeManagementTools

# Create new forest/domain
Install-ADDSForest -DomainName "dealership.local" -DomainNetbiosName "DEALERSHIP" -InstallDNS
```

---

## 5) DNS Configuration
```powershell
Import-Module DnsServer

# Secure forward zone
Set-DnsServerPrimaryZone -Name "dealership.local" -DynamicUpdate Secure
Get-DnsServerZone -Name "dealership.local" | Select ZoneName, DynamicUpdate

# Reverse zone
Add-DnsServerPrimaryZone -NetworkId 192.168.1.0/24 -ReplicationScope Domain
Set-DnsServerPrimaryZone -Name "1.168.192.in-addr.arpa" -DynamicUpdate Secure

# Forwarders
Add-DnsServerForwarder -IPAddress 1.1.1.1,8.8.8.8 -PassThru

# Scavenging
Set-DnsServerScavenging -ScavengingState $true -NoRefreshInterval 7.00:00:00 -RefreshInterval 7.00:00:00
Set-DnsServerZoneAging -Name "dealership.local" -Aging $true -NoRefreshInterval 7.00:00:00 -RefreshInterval 7.00:00:00
```

---

## 6) DHCP Configuration
```powershell
Import-Module DhcpServer

# Authorize DHCP
Add-DhcpServerInDC -DnsName "DEALERSHIP-DC.dealership.local" -IpAddress 192.168.1.10

# Scope
Add-DhcpServerv4Scope -Name "DealershipScope" -StartRange 192.168.1.100 -EndRange 192.168.1.200 -SubnetMask 255.255.255.0 -State Active

# Exclusions
Add-DhcpServerv4ExclusionRange -ScopeId 192.168.1.0 -StartRange 192.168.1.1 -EndRange 192.168.1.20

# Options
Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -Router 192.168.1.1
Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -DnsServer 192.168.1.10 -DnsDomain dealership.local

# DNS Updates
Set-DhcpServerv4DnsSetting -DynamicUpdates Always -DeleteDnsRROnLeaseExpiry $true -DisableDnsPtrRRUpdate $false
```

---

## 7) OU Structure, Users & Groups
```powershell
# Create OUs
New-ADOrganizationalUnit -Name "Dealership" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Dealership,DC=dealership,DC=local"
New-ADOrganizationalUnit -Name "Workstations" -Path "OU=Dealership,DC=dealership,DC=local"
New-ADOrganizationalUnit -Name "Users" -Path "OU=Dealership,DC=dealership,DC=local"
New-ADOrganizationalUnit -Name "Groups" -Path "OU=Dealership,DC=dealership,DC=local"

# Redirect defaults
redircmp "OU=Workstations,OU=Dealership,DC=dealership,DC=local"
redirusr "OU=Users,OU=Dealership,DC=dealership,DC=local"

# Groups
New-ADGroup -Name "SalesDept" -SamAccountName SalesDept -GroupScope Global -GroupCategory Security -Path "OU=Groups,OU=Dealership,DC=dealership,DC=local"
New-ADGroup -Name "ServiceDept" -SamAccountName ServiceDept -GroupScope Global -GroupCategory Security -Path "OU=Groups,OU=Dealership,DC=dealership,DC=local"

# Users
New-ADUser -Name "Sales Rep 01" -SamAccountName SalesRep01 -AccountPassword (ConvertTo-SecureString "SalesP@ss1" -AsPlainText -Force) -Enabled $true -Path "OU=Users,OU=Dealership,DC=dealership,DC=local"
New-ADUser -Name "Service Rep 01" -SamAccountName ServiceRep01 -AccountPassword (ConvertTo-SecureString "ServiceP@ss1" -AsPlainText -Force) -Enabled $true -Path "OU=Users,OU=Dealership,DC=dealership,DC=local"

# Add users to groups
Add-ADGroupMember -Identity "SalesDept" -Members SalesRep01
Add-ADGroupMember -Identity "ServiceDept" -Members ServiceRep01
```

---

## 8) Management Server Setup
- Create **MGMT-SRV** with Windows Server 2022 Desktop Experience.  
- Internal NIC → Preferred DNS: `192.168.1.10`  
- Join domain: `dealership.local`  
- Install RSAT + GPMC:
```powershell
Install-WindowsFeature RSAT-ADDS, GPMC -IncludeManagementTools
```

---

## 9) Department Shares & Permissions (on MGMT-SRV)
```powershell
# Create folders
New-Item -Path "C:\Shares\Sales" -ItemType Directory -Force
New-Item -Path "C:\Shares\Service" -ItemType Directory -Force

# Share
New-SmbShare -Name "Sales" -Path "C:\Shares\Sales" -FullAccess "DEALERSHIP\SalesDept"
New-SmbShare -Name "Service" -Path "C:\Shares\Service" -FullAccess "DEALERSHIP\ServiceDept"

# NTFS Permissions
icacls "C:\Shares\Sales" /inheritance:r
icacls "C:\Shares\Service" /inheritance:r
icacls "C:\Shares\Sales" /grant "DEALERSHIP\SalesDept:(OI)(CI)F"
icacls "C:\Shares\Service" /grant "DEALERSHIP\ServiceDept:(OI)(CI)F"
```

---

## 10) Core Group Policies
- **Drive Mapping GPO**  
  - Map S: → `\\MGMT-SRV\Sales` for SalesDept  
  - Map T: → `\\MGMT-SRV\Service` for ServiceDept  

- **Password Policy (Default Domain Policy)**  
  - Min length 10, history 5, max age 30, complexity enabled  

- **Account Lockout Policy**  
  - Threshold 5, duration 15 min, reset after 15 min  

- **Advanced Auditing (Default Domain Controllers Policy)**  
  - Logon success/failure, Account Lockout, Credential Validation, Kerberos events  

- **RDP Hardening**  
  - NLA enabled, encryption = High  
  - Firewall inbound rule: Remote Desktop (TCP-In, Domain profile) = Allow  
  - Restricted Groups → only ITAdmins allowed RDP  

---

## 11) Validation & Troubleshooting
```powershell
# On DC
Get-DnsServerZone | Select ZoneName, DynamicUpdate
Get-DhcpServerv4Scope
Get-DhcpServerv4OptionValue -ScopeId 192.168.1.0
Get-DhcpServerv4DnsSetting | fl *

# On clients
ipconfig /all
nslookup dealership.local
gpupdate /force
gpresult /r
```

- Event Viewer custom logs: 4624 (logon success), 4625 (logon failure), 4740 (account lockout).  
- RDP test: From MGMT-SRV, run `mstsc` and connect to Sales-PC with ITAdmin01.  

---

## 12) Future Enhancements
- WSUS for patch management  
- Ticketing workflow (lightweight helpdesk)  
- hMailServer SMTP for email troubleshooting  
- VPN simulation  
- RMM-style monitoring  

---

_© Christian Leep – Part of the Dealership IT Infrastructure Simulation Project_
