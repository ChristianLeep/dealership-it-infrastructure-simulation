# Dealership IT Infrastructure Simulation Project
**Author:** Christian Leep  

This project simulates the IT infrastructure of a car dealership using **VirtualBox**, **Windows Server 2022**, and **Windows 11** clients.  
It demonstrates **Active Directory, DNS, DHCP, Group Policy, security hardening, file/print services, and remote management** — showing how an IT Administrator would design and manage a small business network.

---

## 1. Environment Setup
### Tools Used
- VirtualBox  
- Windows Server 2022 ISO  
- Windows 11 ISO  

### Virtual Machines
- **Dealership-DC** (Domain Controller)  
- **MGMT-SRV** (Management Server)  
- **Sales-PC** (Client)  
- **Service-PC** (Client)  

---

## 2. Domain Controller (Dealership-DC)
### VM Configuration
- Name: `Dealership-DC`  
- RAM: 4 GB | CPU: 2 | Disk: 50 GB  
- Network: Adapter 1 = Internal Network | Adapter 2 = NAT  

### IP Settings
```
IP: 192.168.1.10
Subnet: 255.255.255.0
Gateway: 192.168.1.1
DNS: 192.168.1.10
```

### Install Roles and Features
```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-WindowsFeature DHCP -IncludeManagementTools
Install-WindowsFeature DNS -IncludeManagementTools
Install-WindowsFeature GPMC -IncludeManagementTools
Install-ADDSForest -DomainName "dealership.local" -DomainNetbiosName "DEALERSHIP" -InstallDNS
```

After reboot, log in with:  
`DEALERSHIP\Administrator`

---

## 3. DNS Configuration
- Secure dynamic updates only.  
- Forward and reverse lookup zones.  
- DNS forwarders for internet resolution.  
- Scavenging enabled to remove stale entries.

```powershell
Import-Module DnsServer
Set-DnsServerPrimaryZone -Name "dealership.local" -DynamicUpdate Secure
Add-DnsServerPrimaryZone -NetworkId 192.168.1.0/24 -ReplicationScope Domain
Set-DnsServerPrimaryZone -Name "1.168.192.in-addr.arpa" -DynamicUpdate Secure
Add-DnsServerForwarder -IPAddress 1.1.1.1,8.8.8.8 -PassThru
Set-DnsServerScavenging -ScavengingState $true -NoRefreshInterval 7.00:00:00 -RefreshInterval 7.00:00:00
```

---

## 4. DHCP Configuration
```powershell
Import-Module DhcpServer
Add-DhcpServerSecurityGroup
Add-DhcpServerInDC -DnsName "DEALERSHIP-DC.dealership.local" -IpAddress 192.168.1.10

Add-DhcpServerv4Scope -Name "DealershipScope" -StartRange 192.168.1.100 -EndRange 192.168.1.200 -SubnetMask 255.255.255.0 -State Active
Add-DhcpServerv4ExclusionRange -ScopeId 192.168.1.0 -StartRange 192.168.1.1 -EndRange 192.168.1.20

Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -Router 192.168.1.1
Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -DnsServer 192.168.1.10 -DnsDomain dealership.local

Set-DhcpServerv4DnsSetting -DynamicUpdates Always -DeleteDnsRROnLeaseExpiry $true -DisableDnsPtrRRUpdate $false
```

---

## 5. Organizational Units (OUs)
```powershell
New-ADOrganizationalUnit -Name 'Dealership' -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name 'Servers' -Path 'OU=Dealership,DC=dealership,DC=local'
New-ADOrganizationalUnit -Name 'Workstations' -Path 'OU=Dealership,DC=dealership,DC=local'
New-ADOrganizationalUnit -Name 'Users' -Path 'OU=Dealership,DC=dealership,DC=local'
New-ADOrganizationalUnit -Name 'Groups' -Path 'OU=Dealership,DC=dealership,DC=local'
```

Redirect new objects:
```powershell
redircmp "OU=Workstations,OU=Dealership,DC=dealership,DC=local"
redirusr "OU=Users,OU=Dealership,DC=dealership,DC=local"
```

---

## 6. Groups and Users
### Create Groups
```powershell
New-ADGroup -Name "SalesDept" -SamAccountName SalesDept -GroupScope Global -GroupCategory Security -Path 'OU=Groups,OU=Dealership,DC=dealership,DC=local'
New-ADGroup -Name "ServiceDept" -SamAccountName ServiceDept -GroupScope Global -GroupCategory Security -Path 'OU=Groups,OU=Dealership,DC=dealership,DC=local'

# 🔑 IT Admins group for restricted admin access
New-ADGroup -Name "ITAdmins" -SamAccountName ITAdmins -GroupScope Global -GroupCategory Security -Path 'OU=Groups,OU=Dealership,DC=dealership,DC=local'
```

### Create Users
```powershell
New-ADUser -Name "Sales Rep 01" -SamAccountName SalesRep01 -AccountPassword (ConvertTo-SecureString "SalesP@ss1" -AsPlainText -Force) -Enabled $true -Path 'OU=Users,OU=Dealership,DC=dealership,DC=local'
New-ADUser -Name "Service Rep 01" -SamAccountName ServiceRep01 -AccountPassword (ConvertTo-SecureString "ServiceP@ss1" -AsPlainText -Force) -Enabled $true -Path 'OU=Users,OU=Dealership,DC=dealership,DC=local'

# 🔑 IT Admin account
New-ADUser -Name "ITAdmin 01" -SamAccountName ITAdmin01 -AccountPassword (ConvertTo-SecureString "ITAdminP@ss1" -AsPlainText -Force) -Enabled $true -Path 'OU=Users,OU=Dealership,DC=dealership,DC=local'
```

### Add Users to Groups
```powershell
Add-ADGroupMember -Identity "SalesDept" -Members "SalesRep01"
Add-ADGroupMember -Identity "ServiceDept" -Members "ServiceRep01"

# 🔑 Add ITAdmin01 into ITAdmins group
Add-ADGroupMember -Identity "ITAdmins" -Members "ITAdmin01"
```

---

## 7. Management Server (MGMT-SRV)
- Desktop Experience installation  
- Joined to domain under `OU=Servers`  
- Configured DNS to point to Domain Controller  

### Enable Remote Desktop + Firewall Rules
```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# 🔑 Allow only ITAdmins group to RDP
net localgroup "Remote Desktop Users" "DEALERSHIP\ITAdmins" /add
```

---

## 8. Group Policy Objects (GPOs)
### Drive Mapping
- SalesDept → `S:` mapped to `\\MGMT-SRV\Sales`  
- ServiceDept → `T:` mapped to `\\MGMT-SRV\Service`  

### Security Hardening
- Password Policy (min length 10, complexity required)  
- Account Lockout Policy (5 attempts → 15 min lockout)  
- Audit Policies for logon/logoff and credential validation  

### 🔑 RDP GPOs
- **Workstations - RDP (Admins Only)** → Linked to `OU=Workstations`  
- **MGMT-SRV - RDP (Admins Only)** → Linked to `OU=Servers`  

Configured to:  
- Require **NLA** (Network Level Authentication)  
- Enable Remote Desktop inbound rules (TCP/UDP) for **Domain profile only**  
- Restricted Groups: only `ITAdmins` allowed RDP access  

---

## 9. Shared Folders
```powershell
New-Item -Path "C:\Shares\Sales" -ItemType Directory -Force
New-Item -Path "C:\Shares\Service" -ItemType Directory -Force

New-SmbShare -Name "Sales" -Path "C:\Shares\Sales" -FullAccess "DEALERSHIP\SalesDept"
New-SmbShare -Name "Service" -Path "C:\Shares\Service" -FullAccess "DEALERSHIP\ServiceDept"

icacls "C:\Shares\Sales" /inheritance:r
icacls "C:\Shares\Sales" /grant "DEALERSHIP\SalesDept:(OI)(CI)F"

icacls "C:\Shares\Service" /inheritance:r
icacls "C:\Shares\Service" /grant "DEALERSHIP\ServiceDept:(OI)(CI)F"
```

---

## 10. Verification
- `gpresult /r` → confirm applied GPOs  
- `Get-SmbShare` → confirm shared folders  
- Test logging in with **SalesRep01** and **ServiceRep01**  
- Test **RDP with ITAdmin01** (restricted to ITAdmins group only)  

---

## 11. Conclusion
This lab demonstrates:  
- Deploying and configuring AD DS, DNS, DHCP, and GPOs.  
- Creating and organizing OUs, groups, and users.  
- Implementing security policies (password, lockout, auditing).  
- **Restricting RDP to ITAdmins only** for secure remote access.  
- Mapping departmental drives and securing access.  

This simulation mirrors a **real-world dealership IT environment**, showcasing practical sysadmin skills.

---
