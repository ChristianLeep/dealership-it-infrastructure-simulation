# Dealership IT Infrastructure Simulation Project
A custom simulated dealership IT infrastructure built in VirtualBox using Windows Server 2022 and Windows 11. Includes AD, DNS, DHCP, GPO, secure RDP, file/print sharing, and audit logging. Designed to demonstrate system administration, network troubleshooting, and security hardening skills.

**Author:** Christian Leep


## What I built (at a glance)
- **Active Directory Domain:** `dealership.local` with structured OUs (Servers, Workstations, Users, Groups)
- **DNS:** Forward + reverse zones, secure dynamic updates, forwarders, scavenging
- **DHCP:** Authorized server, scope (192.168.1.100–200), options (gateway/DNS/domain), DNS update integration
- **GPOs:** Password/lockout policies, advanced auditing, RDP hardening (NLA), drive mappings (S:, T:), printers
- **Access Control:** Departmental shares with NTFS + SMB permissions using security groups
- **Remote Admin:** Management server (GPMC/RSAT), restricted RDP for IT admins only
- **Validation:** `gpresult /r`, Event Viewer custom views, RDP tests, mapped drives, DNS/DHCP checks

## Why it matters
- Mirrors the work of an **IT Field Technician / SysAdmin**
- Shows I can **design, deploy, secure, and support** a Windows domain from scratch
- Demonstrates **troubleshooting discipline** and **policy-driven management**

## Key files
- **Project Report (Word):** 
- **PowerShell Scripts:**  
- **Screenshots:** 

## Tech stack
Windows Server 2022, Windows 11, Active Directory, DNS, DHCP, GPO, SMB/NTFS, RDP (NLA), PowerShell, VirtualBox

## License
MIT
